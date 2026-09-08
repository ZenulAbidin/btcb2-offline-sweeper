"""Public-data network operations, isolated from the offline executable.

GET requests may be retried. A transaction POST is attempted at most once per
receipt; an ambiguous result must be checked before the user considers resending.
"""
from __future__ import annotations

import datetime
import importlib
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .service import (ServiceError, _fields, _hex, _number, _unique, atomic_directory,
                      inspect_signed_bundle, read_json, signer_for, validate_inventory,
                      validate_manifest, write_json)
from .receipt_lock import ReceiptLock
from .http_deadline import DeadlineHTTPSHandler

CHECKPOINT_HEIGHT = 961640
CHECKPOINT = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb"
DEFAULT_ENDPOINT = "https://mempool.guide/api"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class NetworkError(ServiceError):
    """A network failure with no remote body or sensitive local detail exposed."""


class NotFound(NetworkError):
    pass


def validate_endpoint(endpoint: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        if (not isinstance(endpoint, str) or len(endpoint) > 2048 or any(c.isspace() for c in endpoint)
                or parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.port == 0 or "\\" in endpoint):
            raise ValueError()
        return endpoint.rstrip("/")
    except Exception:
        raise NetworkError("Use an HTTPS explorer API URL without credentials, query parameters, or a fragment.") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NetworkError("The explorer redirected the request. Enter its final HTTPS API address explicitly.")


class ExplorerClient:
    def __init__(self, endpoint=DEFAULT_ENDPOINT, *, timeout=30, retries=3):
        self.endpoint = validate_endpoint(endpoint)
        self.timeout = timeout
        self.retries = retries
        self.opener = urllib.request.build_opener(_NoRedirect(), DeadlineHTTPSHandler())

    def _request(self, path, data=None):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c.isspace() for c in path):
            raise NetworkError("An explorer request path is invalid.")
        headers = {"User-Agent": "BTCB2-Sweep-Assistant/1.0", "Cache-Control": "no-cache"}
        if data is not None:
            headers["Content-Type"] = "text/plain"
        request = urllib.request.Request(self.endpoint + path, data=data, headers=headers,
                                         method="POST" if data is not None else "GET")
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise NetworkError("The explorer response exceeded the safety size limit.")
        try:
            text = raw.decode("utf-8").strip()
            return json.loads(text, object_pairs_hook=_unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except json.JSONDecodeError:
            return text
        except (UnicodeError, ValueError):
            raise NetworkError("The explorer returned malformed data.") from None

    def get(self, path):
        for attempt in range(self.retries):
            try:
                return self._request(path)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise NotFound("The explorer does not know this transaction yet.") from None
                retry = exc.code == 429 or 500 <= exc.code <= 599
                if not retry or attempt + 1 == self.retries:
                    raise NetworkError("The explorer rejected a public-data request. Check the API address and try again.") from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt + 1 == self.retries:
                    raise NetworkError("Could not reach the explorer. Check the connection and API address.") from None
            time.sleep(min(2 ** attempt, 4))
        raise NetworkError("Could not complete the explorer request.")

    def post_transaction(self, raw_hex):
        # Never retry POST, including a timeout after a potentially accepted send.
        try:
            return self._request("/tx", data=raw_hex.encode("ascii"))
        except Exception:
            raise NetworkError("Broadcast result is uncertain. Check the saved receipt before attempting another send.") from None


def _progress(callback, message):
    if callback is not None:
        callback(message)


def verify_checkpoint(get):
    if get(f"/block-height/{CHECKPOINT_HEIGHT}") != CHECKPOINT:
        raise NetworkError("This explorer does not report the required BTCB2 fork checkpoint. Nothing was broadcast.")


def collect_inventory(kind, inventory, endpoint, out, workers=4, progress=None, *, client=None) -> dict:
    """Scan the public inventory and save manifest.json + verification.json."""
    endpoint = validate_endpoint(endpoint)
    _number(workers, 1, 16)
    data = validate_inventory(read_json(inventory) if not isinstance(inventory, dict) else inventory, kind)
    client = client or ExplorerClient(endpoint)
    builder = importlib.import_module(f"{kind}.build_manifest")
    count, lock = 0, threading.Lock()

    def get(path):
        nonlocal count
        result = client.get(path)
        with lock:
            count += 1
            if path.startswith("/address/"):
                _progress(progress, f"Checking public addresses ({count} explorer requests completed)…")
            elif path.endswith("/hex"):
                _progress(progress, "Verifying raw parent transactions…")
        return result

    _progress(progress, "Checking the BTCB2 fork and scanning public addresses…")
    try:
        # The existing builder verifies checkpoint, amounts, scripts, outspends,
        # coinbase maturity, and that its snapshot did not reorganize.
        manifest, evidence = builder.collect(data, get, workers, progress=lambda message: _progress(progress, message))
        validate_manifest(manifest, kind)
        evidence["source"] = endpoint
        with atomic_directory(out) as staging:
            write_json(staging / "manifest.json", manifest)
            signer_for(kind).load_manifest(staging / "manifest.json")
            write_json(staging / "verification.json", evidence)
    except ServiceError:
        raise
    except Exception:
        raise NetworkError("The public scan could not be verified. Check the inventory, API, and address range, then scan again.") from None
    _progress(progress, f"Saved {len(manifest['utxos'])} verified candidate outputs.")
    return {"manifest": manifest, "evidence": evidence, "output": str(Path(out).absolute())}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _save_receipt(path, receipt):
    """Durably replace the single receipt after every state transition."""
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=".btcb2-receipt-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _validate_receipt(receipt):
    _fields(receipt, ("format", "plan_sha256", "endpoint", "destination", "created_utc", "updated_utc", "transactions"))
    if receipt["format"] != "btcb2-broadcast-receipts/v1":
        raise ServiceError("Choose a broadcast receipt created by this assistant.")
    _hex(receipt["plan_sha256"], 32)
    validate_endpoint(receipt["endpoint"])
    if not isinstance(receipt["destination"], str) or not 26 <= len(receipt["destination"]) <= 90:
        raise ServiceError("The broadcast receipt destination is invalid.")
    for field in ("created_utc", "updated_utc"):
        if not isinstance(receipt[field], str) or len(receipt[field]) > 50:
            raise ServiceError("The broadcast receipt timestamp is invalid.")
    rows = receipt["transactions"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 200_000:
        raise ServiceError("The broadcast receipt transaction list is invalid.")
    seen = set()
    for row in rows:
        _fields(row, ("txid", "state"), ("updated_utc", "confirmed", "block_height"))
        _hex(row["txid"], 32)
        if row["txid"] in seen or row["state"] not in {"pending", "sending", "accepted", "already_known", "uncertain"}:
            raise ServiceError("The broadcast receipt has duplicate transactions or an invalid state.")
        if "updated_utc" in row and (not isinstance(row["updated_utc"], str) or len(row["updated_utc"]) > 50):
            raise ServiceError("The broadcast receipt timestamp is invalid.")
        if "confirmed" in row and type(row["confirmed"]) is not bool:
            raise ServiceError("The broadcast receipt confirmation state is invalid.")
        if "block_height" in row:
            _number(row["block_height"], 0, 0x7fffffff)
        seen.add(row["txid"])
    return receipt


def _status(client, txid):
    try:
        result = client.get(f"/tx/{txid}/status")
    except NotFound:
        return None
    if not isinstance(result, dict) or type(result.get("confirmed")) is not bool:
        raise NetworkError("The explorer returned an invalid transaction status.")
    status = {"confirmed": result["confirmed"]}
    if result["confirmed"]:
        status["block_height"] = _number(result.get("block_height"), CHECKPOINT_HEIGHT, 0x7fffffff)
    return status


def broadcast_bundle(source, endpoint, receipts_dir, progress=None, *, expected_plan_sha256, client=None) -> dict:
    """Explicit irreversible action. Call only after the user confirms the preview.

    The complete bundle is revalidated before any request. A durable 'sending'
    receipt is written before POST. Reopening an uncertain receipt only checks
    status; it will never automatically send that transaction a second time.
    """
    endpoint = validate_endpoint(endpoint)
    report = inspect_signed_bundle(source)
    if report["plan_sha256"] != expected_plan_sha256:
        raise ServiceError("The signed bundle changed after approval. Review it again before broadcasting.")
    folder = Path(source).parent if Path(source).name == "report.json" else Path(source)
    # Freeze the exact validated bytes before network calls or USB removal.
    payloads = {}
    with tempfile.TemporaryDirectory(prefix="btcb2-broadcast-check-") as name:
        temporary = Path(name)
        write_json(temporary / "report.json", report)
        for record in report["transactions"]:
            with (folder / record["file"]).open("rb") as handle:
                raw = handle.read(800_002)
            if len(raw) > 800_001:
                raise ServiceError("A signed transaction exceeds the size limit.")
            (temporary / record["file"]).write_bytes(raw)
            payloads[record["txid"]] = raw.decode("ascii").strip()
        inspect_signed_bundle(temporary)
    receipts_dir = Path(receipts_dir).absolute()
    receipt_path = receipts_dir / "receipts.json"
    if receipts_dir.is_symlink():
        raise ServiceError("Choose a regular receipt folder, not a link.")
    if receipts_dir.exists():
        receipt = _validate_receipt(read_json(receipt_path))
        if (receipt["plan_sha256"] != report["plan_sha256"] or receipt["endpoint"] != endpoint
                or receipt["destination"] != report["destination"]
                or [row["txid"] for row in receipt["transactions"]] != [row["txid"] for row in report["transactions"]]):
            raise ServiceError("This receipt folder belongs to a different bundle or explorer.")
    else:
        now = _now()
        receipt = dict(format="btcb2-broadcast-receipts/v1", plan_sha256=report["plan_sha256"], endpoint=endpoint,
                       destination=report["destination"], created_utc=now, updated_utc=now,
                       transactions=[dict(txid=row["txid"], state="pending") for row in report["transactions"]])
        with atomic_directory(receipts_dir) as staging:
            write_json(staging / "receipts.json", receipt)
    # Ownership belongs to the process, not the existence of a file. A crash
    # releases it automatically, so the next run can inspect its durable receipt.
    lock = ReceiptLock(receipts_dir)
    if not lock.acquire():
        raise ServiceError("Another operation is using this receipt folder. Let it finish, then reopen the saved receipt.")
    try:
        # Another run may have finished between the initial read and this lock.
        # Reload after acquiring ownership so an uncertain send is never reset.
        receipt = _validate_receipt(read_json(receipt_path))
        if (receipt["plan_sha256"] != report["plan_sha256"] or receipt["endpoint"] != endpoint
                or receipt["destination"] != report["destination"]
                or [row["txid"] for row in receipt["transactions"]] != [row["txid"] for row in report["transactions"]]):
            raise ServiceError("The receipt changed before broadcast. Review its contents again.")
        client = client or ExplorerClient(endpoint)
        _progress(progress, "Verifying the BTCB2 fork checkpoint before broadcast…")
        verify_checkpoint(client.get)
        for index, row in enumerate(receipt["transactions"], 1):
            _progress(progress, f"Checking transaction {index} of {len(receipt['transactions'])}…")
            status = _status(client, row["txid"])
            if status is not None:
                row.pop("block_height", None)
                row.update(state="already_known", updated_utc=_now(), **status)
                receipt["updated_utc"] = _now()
                _save_receipt(receipt_path, receipt)
                continue
            if row["state"] != "pending":
                row.update(state="uncertain", updated_utc=_now())
                row.pop("confirmed", None)
                row.pop("block_height", None)
                receipt["updated_utc"] = _now()
                _save_receipt(receipt_path, receipt)
                break
            row.update(state="sending", updated_utc=_now())
            receipt["updated_utc"] = _now()
            _save_receipt(receipt_path, receipt)
            _progress(progress, f"Submitting transaction {index} of {len(receipt['transactions'])} once…")
            try:
                returned = client.post_transaction(payloads[row["txid"]])
                if not isinstance(returned, str) or returned.strip() != row["txid"]:
                    raise NetworkError("The explorer did not return the expected transaction ID.")
                row.update(state="accepted", updated_utc=_now(), confirmed=False)
            except Exception:
                row.update(state="uncertain", updated_utc=_now())
                receipt["updated_utc"] = _now()
                _save_receipt(receipt_path, receipt)
                break
            receipt["updated_utc"] = _now()
            _save_receipt(receipt_path, receipt)
    finally:
        lock.release()
    _progress(progress, "Broadcast receipts saved. Check any uncertain transaction before another send.")
    return receipt


def check_status(receipts, endpoint=None, progress=None, *, client=None) -> dict:
    """Read-only network checks; update an existing receipt file when supplied."""
    path, owned_lock = None, None
    try:
        if isinstance(receipts, dict):
            receipt = _validate_receipt(json.loads(json.dumps(receipts)))
        else:
            path = Path(receipts)
            if path.is_dir():
                path = path / "receipts.json"
            lock = ReceiptLock(path.parent)
            if lock.acquire():
                owned_lock = lock
            else:
                # Status remains available during an active send,
                # but never overwrites another operation's durable sending state.
                pass
            receipt = _validate_receipt(read_json(path))
        endpoint = validate_endpoint(endpoint or receipt["endpoint"])
        client = client or ExplorerClient(endpoint)
        verify_checkpoint(client.get)
        for row in receipt["transactions"]:
            _progress(progress, "Checking the explorer for saved transaction IDs…")
            status = _status(client, row["txid"])
            if status is not None:
                row.pop("block_height", None)
                row.update(state="already_known", updated_utc=_now(), **status)
            elif row["state"] != "pending":
                row.update(state="uncertain", updated_utc=_now())
                row.pop("confirmed", None)
                row.pop("block_height", None)
        receipt["updated_utc"] = _now()
        if path is not None and owned_lock is not None:
            _save_receipt(path, receipt)
        return receipt
    finally:
        if owned_lock is not None:
            owned_lock.release()
