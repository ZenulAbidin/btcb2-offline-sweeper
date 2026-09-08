"""Local workflow services. This module deliberately has no network imports.

All public transfers use an allowlisted schema; output directories appear only
after a successful operation. Signer arithmetic and crypto stay in the original
legacy/segwit modules. Keys are never passed as command-line arguments.
"""
from __future__ import annotations

import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
from typing import Any

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_ADDRESSES = 200_000
_CLI_LOCK = threading.Lock()
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_FORMATS = {"segwit": "offline-p2wpkh-sweep-report/v2", "legacy": "offline-p2pkh-sweep-report/v1"}
_MANIFESTS = {"segwit": "offline-p2wpkh-sweep/v2", "legacy": "offline-p2pkh-sweep/v1"}


class ServiceError(ValueError):
    """An intentionally non-secret error suitable for displaying in the TUI."""


def signer_for(kind: str):
    if kind not in _FORMATS:
        raise ServiceError("Choose a native SegWit or legacy wallet.")
    return importlib.import_module(f"{kind}.offline_sweep")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ServiceError("Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def read_json(path, limit=MAX_JSON_BYTES) -> dict:
    try:
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ServiceError("Choose an ordinary JSON file, not a link or folder.")
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise ServiceError("The selected JSON file exceeds the 64 MiB safety limit.")
        result = json.loads(raw, object_pairs_hook=_unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(result, dict):
            raise ServiceError("The selected JSON file must contain an object.")
        return result
    except ServiceError:
        raise
    except Exception:
        raise ServiceError("Cannot read this JSON file. Check its format and location.") from None


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise ServiceError("The public file contains missing or unsupported fields. Use a fresh export.")


def _number(value, low=0, high=21_000_000 * 100_000_000):
    if type(value) is not int or not low <= value <= high:
        raise ServiceError("The public file contains an invalid numeric value.")
    return value


def _hex(value, size=None):
    if not isinstance(value, str) or len(value) % 2 or not re.fullmatch(r"[0-9a-f]+", value):
        raise ServiceError("The public file contains invalid hexadecimal data.")
    if size is not None and len(value) != size * 2:
        raise ServiceError("The public file contains a hexadecimal value of the wrong length.")
    return bytes.fromhex(value)


def _snapshot(value):
    _fields(value, ("height", "block_hash"))
    _number(value["height"], 0, 0x7fffffff)
    _hex(value["block_hash"], 32)


def validate_inventory(data: dict, kind: str | None = None) -> dict:
    """Validate exactly the public inventory format produced by Electrum helpers."""
    _fields(data, ("format", "zpub", "per_branch", "addresses"))
    if data["format"] != "electrum-public-inventory/v1":
        raise ServiceError("Choose an exported public address inventory.")
    per_branch = _number(data["per_branch"], 1, MAX_ADDRESSES // 2)
    extended = data["zpub"]
    imported = isinstance(extended, str) and re.fullmatch(r"imported:[0-9a-f]{64}", extended) is not None
    if not imported and (not isinstance(extended, str) or len(extended) != 111 or not extended.startswith(("xpub", "zpub"))):
        raise ServiceError("Inventory must contain a public xpub or zpub, never a private key.")
    rows = data["addresses"]
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise ServiceError("The public inventory has no address list.")
    inferred = ("segwit" if len(str(rows[0].get("script_pubkey", ""))) == 44 else "legacy") if imported else ("segwit" if extended.startswith("zpub") else "legacy")
    if kind is not None and kind != inferred:
        raise ServiceError("The public inventory does not match the selected wallet type.")
    signer = signer_for(inferred)
    try:
        n = 0
        for char in extended if not imported else "":
            n = n * 58 + signer.B58.index(char)
        encoded = n.to_bytes(82, "big")
        expected_version = bytes.fromhex("04b24746" if inferred == "segwit" else "0488b21e")
        if not imported and (encoded[:4] != expected_version or encoded[45] not in (2, 3) or signer.sha256d(encoded[:-4])[:4] != encoded[-4:]):
            raise ValueError()
    except Exception:
        raise ServiceError("The inventory extended public key is invalid.") from None
    if len(rows) != per_branch * (1 if imported else 2):
        raise ServiceError("The inventory must include the stated receive and change address ranges.")
    addresses, suffixes = set(), set()
    for row in rows:
        _fields(row, ("branch", "index", "address", "script_pubkey"))
        suffix = (_number(row["branch"], 0, 0 if imported else 1), _number(row["index"], 0, per_branch - 1))
        address = row["address"]
        if not isinstance(address, str) or not 26 <= len(address) <= 90:
            raise ServiceError("The inventory contains an invalid address.")
        try:
            script = signer.destination_script(address, "bc")
        except Exception:
            raise ServiceError("The inventory contains an invalid address.") from None
        expected_size = 22 if inferred == "segwit" else 25
        if len(script) != expected_size or script.hex() != row["script_pubkey"]:
            raise ServiceError("A public address does not match its script or wallet type.")
        if address in addresses or suffix in suffixes:
            raise ServiceError("The inventory contains duplicate addresses or derivation paths.")
        addresses.add(address)
        suffixes.add(suffix)
    return copy.deepcopy(data)


def validate_manifest(data, kind):
    _fields(data, ("format", "signing_profile", "snapshot", "transactions", "utxos"))
    signer = signer_for(kind)
    if data["format"] != _MANIFESTS[kind] or data["signing_profile"] != signer.PROFILE:
        raise ServiceError("This manifest does not match the selected wallet type and signing profile.")
    _snapshot(data["snapshot"])
    if not isinstance(data["transactions"], dict) or not isinstance(data["utxos"], list) or not 1 <= len(data["utxos"]) <= MAX_ADDRESSES:
        raise ServiceError("The manifest has an invalid transaction or output list.")
    for txid, raw in data["transactions"].items():
        _hex(txid, 32)
        if not isinstance(raw, str) or len(raw) > signer.MAX_PARENT_BYTES * 2:
            raise ServiceError("The manifest contains an oversized parent transaction.")
        _hex(raw)
    for row in data["utxos"]:
        _fields(row, ("txid", "vout"), ("value_sats", "script_pubkey", "confirmations", "role"))
        _hex(row["txid"], 32)
        _number(row["vout"], 0, 0xffffffff)
        if "value_sats" in row:
            _number(row["value_sats"])
        if "script_pubkey" in row:
            _hex(row["script_pubkey"], 22 if kind == "segwit" else 25)
        if "confirmations" in row:
            _number(row["confirmations"], 101, 0x7fffffff)
        if "role" in row and row["role"] != "sweep":
            raise ServiceError("The manifest contains unsupported output roles.")
    return data


def _write(path: Path, content: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path, data):
    _write(Path(path), json.dumps(data, indent=2, allow_nan=False) + "\n")


@contextlib.contextmanager
def atomic_directory(target):
    """Stage beside target so the final rename also works for removable drives."""
    target = Path(target).absolute()
    if target.exists() or target.is_symlink():
        raise ServiceError("That output folder already exists. Choose a new folder name.")
    if not target.parent.is_dir():
        raise ServiceError("Choose an existing parent folder for the output.")
    temporary = Path(tempfile.mkdtemp(prefix=".btcb2-pending-", dir=target.parent))
    try:
        yield temporary
        if target.exists() or target.is_symlink():
            raise ServiceError("The output folder now exists. Choose a new folder name.")
        os.rename(temporary, target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def export_public_inventory(data, target) -> Path:
    safe = validate_inventory(data)
    target = Path(target).absolute()
    if target.exists() or target.is_symlink():
        raise ServiceError("That output file already exists. Choose a new filename.")
    if not target.parent.is_dir():
        raise ServiceError("Choose an existing folder for the public inventory.")
    fd, temporary_name = tempfile.mkstemp(prefix=".btcb2-public-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(safe, handle, indent=2, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "nt":
            os.rename(temporary, target)  # Windows rename never replaces an existing file.
        else:
            os.link(temporary, target)  # Atomic creation, with no overwrite race.
            temporary.unlink()
    except FileExistsError:
        raise ServiceError("That output file already exists. Choose a new filename.") from None
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def _cli(signer, arguments, *, key_provider=None):
    capture = io.StringIO()
    with _CLI_LOCK, contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
        result = signer.main(arguments, key_provider=key_provider)
    if result != 0:
        # Only the original CLI's deliberately sanitized messages can cross this boundary.
        errors = [line.removeprefix("ERROR: ") for line in capture.getvalue().splitlines() if line.startswith("ERROR: ")]
        raise ServiceError(errors[0] if errors else "The local operation could not finish. No completed output was saved.")


def plan(kind, manifest, destination, fee_rate, max_tx_fee, max_total_fee, out, options=None) -> dict:
    """Create a reviewed-plan candidate without loading keys or using a network."""
    signer = signer_for(kind)
    options = dict(options or {})
    if set(options) - {"max_inputs", "max_vbytes", "min_output_sats"}:
        raise ServiceError("Unsupported planning option.")
    data = validate_manifest(read_json(manifest), kind)
    _number(max_tx_fee, 1)
    _number(max_total_fee, 1)
    settings = dict(max_inputs=1322, max_vbytes=90000, min_output_sats=1000)
    settings.update(options)
    for value in settings.values():
        _number(value, 1)
    if not isinstance(destination, str) or len(destination) > 90 or not isinstance(fee_rate, (str, int)):
        raise ServiceError("Enter a destination address and a decimal fee rate.")
    try:
        signer.destination_script(destination, "bc")
        signer.parse_rate(str(fee_rate))
    except Exception:
        raise ServiceError("Enter a valid mainnet destination and a positive decimal fee rate.") from None
    arguments = ["--destination", destination, "--fee-rate", str(fee_rate),
                 "--max-tx-fee-sats", str(max_tx_fee), "--max-total-fee-sats", str(max_total_fee)]
    for key, value in settings.items():
        arguments.extend(["--" + key.replace("_", "-"), str(value)])
    with atomic_directory(out) as staging:
        source = staging / "manifest.input.json"
        write_json(source, data)
        result_path = staging / "result"
        _cli(signer, arguments + ["--manifest", str(source), "--out", str(result_path), "--plan-only"])
        source.unlink()
        report = read_json(result_path / "report.json")
        validate_report(report)
        os.rename(result_path / "report.json", staging / "report.json")
        result_path.rmdir()
    return report


def sign(kind, manifest, keys: list[str], reviewed_plan_path, out, *, expected_plan_sha256=None) -> dict:
    """Sign the exact reviewed settings, keeping all private keys in memory."""
    signer = signer_for(kind)
    approved = read_json(reviewed_plan_path)
    validate_report(approved)
    if expected_plan_sha256 is not None and approved["plan_sha256"] != expected_plan_sha256:
        raise ServiceError("The review report changed after approval. Review the plan again before signing.")
    if approved["format"] != _FORMATS[kind] or approved["signed"] is not False:
        raise ServiceError("Choose the unsigned review report for this wallet type.")
    data = validate_manifest(read_json(manifest), kind)
    if not isinstance(keys, list) or not keys or len(keys) > MAX_ADDRESSES:
        raise ServiceError("No suitable wallet keys were supplied.")
    if any(not isinstance(key, str) or len(key) != 52 or any(c not in signer.B58 for c in key) for key in keys):
        raise ServiceError("Only compressed mainnet WIF keys can be used; key content suppressed.")
    reviewed = approved["review_plan"]
    arguments = ["--destination", reviewed["destination"], "--fee-rate", approved["fee_rate_requested_sat_per_vb"],
                 "--max-inputs", str(reviewed["effective_max_inputs"]), "--max-vbytes", str(reviewed["max_vbytes"]),
                 "--min-output-sats", str(reviewed["min_output_sats"]),
                 "--max-tx-fee-sats", str(reviewed["max_tx_fee_sats"]), "--max-total-fee-sats", str(reviewed["max_total_fee_sats"])]
    # This temporary folder holds only PUBLIC manifests and reports. Private keys
    # go directly to the signer after its reviewed-plan check, never to a file.
    with tempfile.TemporaryDirectory(prefix="btcb2-local-sign-") as local_name:
        local = Path(local_name)
        source, review_path = local / "manifest.json", local / "review.json"
        write_json(source, data)
        write_json(review_path, approved)
        signer.disable_core_dumps()
        with atomic_directory(out) as staging:
            result_path = staging / "result"
            _cli(signer, arguments + ["--manifest", str(source), "--reviewed-plan", str(review_path),
                                     "--out", str(result_path)], key_provider=lambda: signer.parse_key_lines(keys, 128))
            report = inspect_signed_bundle(result_path)
            for path in result_path.iterdir():
                os.rename(path, staging / path.name)
            result_path.rmdir()
    return report


_REVIEW_FIELDS = ("signing_profile", "source_commit", "source_release", "sighash_byte", "mode", "destination",
                  "destination_script_pubkey", "snapshot", "fee_rate_sat_per_vb", "effective_max_inputs", "max_vbytes",
                  "min_output_sats", "max_tx_fee_sats", "max_total_fee_sats", "transactions")
_PLAN_TX_FIELDS = ("txid", "unsigned_tx_hex", "inputs", "output_value_sats", "fee_sats", "estimated_upper_weight", "estimated_upper_vbytes")
_RECORD_FIELDS = ("batch", "txid", "depends_on", "input_count", "inputs", "input_total_sats", "output_index",
                  "output_value_sats", "fee_sats", "estimated_upper_vbytes")
_SIGNED_FIELDS = ("file", "wtxid", "weight", "actual_vbytes", "actual_fee_rate_sat_per_vb")
_REPORT_FIELDS = ("format", "signed", "mode", "destination", "profile", "source_commit", "sighash_byte", "review_plan",
                  "plan_sha256", "fee_rate_requested_sat_per_vb", "effective_max_inputs", "original_input_count", "batch_count",
                  "total_input_sats", "total_fee_sats", "final_unspent_output_count", "final_total_output_sats",
                  "provenance_unverified_by_this_program", "transactions")


def _coins(signer, rows):
    result = []
    if not isinstance(rows, list) or not rows:
        raise ServiceError("A transaction has no input list.")
    for row in rows:
        _fields(row, ("outpoint", "value_sats", "script_pubkey"))
        label = row["outpoint"]
        if not isinstance(label, str) or not re.fullmatch(r"[0-9a-f]{64}:(0|[1-9][0-9]{0,9})", label):
            raise ServiceError("A transaction contains an invalid input reference.")
        txid, index = label.split(":")
        index = _number(int(index), 0, 0xffffffff)
        value = _number(row["value_sats"])
        script = _hex(row["script_pubkey"])
        if signer.PROFILE.startswith("knots-unified-p2wpkh"):
            valid = len(script) == 22 and script[:2] == b"\x00\x14"
        else:
            valid = len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac"
        if not valid:
            raise ServiceError("A transaction input does not match the signing profile.")
        result.append(signer.Coin(txid, index, value, script))
    return result


def validate_report(report: dict) -> str:
    """Verify every human-facing summary against the embedded deterministic plan."""
    try:
        _fields(report, _REPORT_FIELDS)
        for field in ("effective_max_inputs", "original_input_count", "batch_count", "total_input_sats", "total_fee_sats",
                      "final_unspent_output_count", "final_total_output_sats"):
            _number(report[field])
        kind = next((key for key, value in _FORMATS.items() if value == report["format"]), None)
        if kind is None or type(report["signed"]) is not bool:
            raise ServiceError("Choose a supported sweep review or signed report.")
        signer = signer_for(kind)
        review = report["review_plan"]
        _fields(review, _REVIEW_FIELDS)
        _snapshot(review["snapshot"])
        if report["signed"] and review["snapshot"]["height"] < signer.ACTIVATION_HEIGHT:
            raise ServiceError("A signed bundle requires a snapshot at or after BTCB2 unified activation.")
        if (review["signing_profile"] != signer.PROFILE or review["source_commit"] != signer.SOURCE_COMMIT
                or review["source_release"] != signer.SOURCE_RELEASE or review["sighash_byte"] != "21"
                or review["mode"] != "independent"):
            raise ServiceError("The report selects an unsupported signing profile.")
        destination = signer.destination_script(review["destination"], "bc")
        if destination.hex() != review["destination_script_pubkey"]:
            raise ServiceError("The destination address and output script disagree.")
        for field in ("effective_max_inputs", "max_vbytes", "min_output_sats", "max_tx_fee_sats", "max_total_fee_sats"):
            _number(review[field], 1)
        rate = signer.parse_rate(report["fee_rate_requested_sat_per_vb"])
        if str(rate) != review["fee_rate_sat_per_vb"]:
            raise ServiceError("The report fee rate differs from its plan.")
        cap = signer.input_capacity(review["max_vbytes"], review["effective_max_inputs"], len(destination))
        if cap != review["effective_max_inputs"]:
            raise ServiceError("The report input capacity differs from its plan.")
        batches, records = review["transactions"], report["transactions"]
        if not isinstance(batches, list) or not 1 <= len(batches) <= MAX_ADDRESSES or not isinstance(records, list) or len(records) != len(batches):
            raise ServiceError("The report transaction list is invalid.")
        coins = []
        for batch in batches:
            _fields(batch, _PLAN_TX_FIELDS)
            for field in ("output_value_sats", "fee_sats", "estimated_upper_weight", "estimated_upper_vbytes"):
                _number(batch[field])
            coins.extend(_coins(signer, batch["inputs"]))
        expected = signer.make_plan(coins, destination, cap, rate, review["min_output_sats"], review["max_tx_fee_sats"], review["max_total_fee_sats"])
        if len(expected) != len(batches):
            raise ServiceError("The report batch count differs from its inputs.")
        for index, (batch, actual, planned) in enumerate(zip(expected, records, batches), 1):
            canonical = dict(txid=batch.txid, unsigned_tx_hex=signer.serialize_base(batch.inputs, batch.output_value, destination).hex(),
                             inputs=[dict(outpoint=c.label, value_sats=c.value, script_pubkey=c.script.hex()) for c in batch.inputs],
                             output_value_sats=batch.output_value, fee_sats=batch.fee,
                             estimated_upper_weight=signer.estimated_weight(len(batch.inputs), len(destination)), estimated_upper_vbytes=batch.estimated_vbytes)
            if planned != canonical:
                raise ServiceError("The transaction plan is internally inconsistent.")
            _fields(actual, _RECORD_FIELDS + (_SIGNED_FIELDS if report["signed"] else ()))
            for field in ("batch", "input_count", "input_total_sats", "output_index", "output_value_sats", "fee_sats", "estimated_upper_vbytes"):
                _number(actual[field])
            canonical_record = dict(batch=index, txid=batch.txid, depends_on=None, input_count=len(batch.inputs),
                                    inputs=[c.label for c in batch.inputs], input_total_sats=sum(c.value for c in batch.inputs),
                                    output_index=0, output_value_sats=batch.output_value, fee_sats=batch.fee,
                                    estimated_upper_vbytes=batch.estimated_vbytes)
            for field, value in canonical_record.items():
                if field == "txid" and report["signed"] and kind == "legacy":
                    _hex(actual[field], 32)
                elif actual[field] != value:
                    raise ServiceError("A transaction summary differs from its plan.")
            if report["signed"]:
                if actual["file"] != f"tx_{index:04d}.hex":
                    raise ServiceError("The report contains an unsafe or unexpected transaction filename.")
                _hex(actual["wtxid"], 32)
                _number(actual["weight"], 1, 400000)
                _number(actual["actual_vbytes"], 1, 100000)
                if not isinstance(actual["actual_fee_rate_sat_per_vb"], str) or not re.fullmatch(r"[0-9]+\.[0-9]{8}", actual["actual_fee_rate_sat_per_vb"]):
                    raise ServiceError("The report contains an invalid actual fee rate.")
        canonical_summary = dict(mode="independent", destination=review["destination"], profile=signer.PROFILE,
                                 source_commit=signer.SOURCE_COMMIT, sighash_byte="21", plan_sha256=signer.plan_hash(review),
                                 effective_max_inputs=cap, original_input_count=len(coins), batch_count=len(batches),
                                 total_input_sats=sum(c.value for c in coins), total_fee_sats=sum(b.fee for b in expected),
                                 final_unspent_output_count=len(batches), final_total_output_sats=sum(b.output_value for b in expected),
                                 provenance_unverified_by_this_program={"snapshot": review["snapshot"]})
        if any(report[key] != value for key, value in canonical_summary.items()):
            raise ServiceError("The report summary or review checksum is inconsistent.")
        return kind
    except ServiceError:
        raise
    except Exception:
        raise ServiceError("The sweep report is invalid or inconsistent. Recreate it offline.") from None


def _verify_signatures(kind, signer, raw, parsed, coins, output_value, destination):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    if kind == "segwit":
        if parsed.stripped != signer.serialize_base(coins, output_value, destination):
            raise ServiceError("The signed transaction differs from the reviewed transaction.")
        signature_pairs = parsed.witnesses
    else:
        if any(parsed.witnesses) or raw != parsed.stripped:
            raise ServiceError("A legacy signed transaction contains unexpected witness data.")
        reader = signer.Reader(raw)
        if int.from_bytes(reader.read(4), "little") != signer.VERSION or reader.number() != len(coins):
            raise ServiceError("The signed transaction version or input count is unexpected.")
        signature_pairs = []
        for _ in coins:
            reader.read(36)
            script = reader.vector()
            if reader.read(4) != signer.SEQUENCE.to_bytes(4, "little"):
                raise ServiceError("The signed transaction sequence differs from the plan.")
            pushes = signer.Reader(script)
            signature = pushes.read(pushes.read(1)[0])
            public = pushes.read(pushes.read(1)[0])
            if pushes.pos != len(script):
                raise ServiceError("The signed transaction contains an unexpected unlocking script.")
            signature_pairs.append((signature, public))
        if raw[-4:] != signer.LOCKTIME.to_bytes(4, "little"):
            raise ServiceError("The signed transaction locktime differs from the plan.")
    digests = signer.signature_digests(coins, output_value, destination)
    for coin, digest, pair in zip(coins, digests, signature_pairs):
        if len(pair) != 2:
            raise ServiceError("The transaction signature structure is invalid.")
        signature, public = pair
        if not signature or signature[-1] != signer.SIGHASH or len(public) != 33 or public[0] not in (2, 3):
            raise ServiceError("The transaction has an invalid key or signing flag.")
        expected_script = b"\x00\x14" + signer.hash160(public) if kind == "segwit" else b"\x76\xa9\x14" + signer.hash160(public) + b"\x88\xac"
        if expected_script != coin.script:
            raise ServiceError("A signing key does not match the reviewed input.")
        r, s = utils.decode_dss_signature(signature[:-1])
        if not 1 <= r < signer.CURVE_N or not 1 <= s <= signer.CURVE_N // 2:
            raise ServiceError("The signed transaction contains a noncanonical signature.")
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public)
        public_key.verify(signature[:-1], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def inspect_signed_bundle(source) -> dict:
    """Read and cryptographically verify a USB bundle without any network activity."""
    source = Path(source)
    folder = source.parent if source.name == "report.json" else source
    if folder.is_symlink() or not folder.is_dir():
        raise ServiceError("Choose the folder containing report.json and signed transaction files.")
    report = read_json(folder / "report.json")
    kind = validate_report(report)
    if report["signed"] is not True:
        raise ServiceError("This is an unsigned review plan. Sign it on the offline computer first.")
    signer = signer_for(kind)
    try:
        destination = signer.destination_script(report["destination"], "bc")
        for record, batch in zip(report["transactions"], report["review_plan"]["transactions"]):
            path = folder / record["file"]
            if path.is_symlink() or not path.is_file():
                raise ServiceError("A signed transaction file is missing or is a link.")
            with path.open("rb") as handle:
                content = handle.read(800_002)
            if len(content) > 800_001:
                raise ServiceError("A signed transaction file exceeds the size limit.")
            raw = _hex(content.decode("ascii").strip())
            parsed = signer.parse_transaction(raw)
            coins = _coins(signer, batch["inputs"])
            if (parsed.txid != record["txid"] or signer.sha256d(raw)[::-1].hex() != record["wtxid"]
                    or list(parsed.inputs) != [(coin.txid, coin.vout) for coin in coins]
                    or parsed.outputs != ((batch["output_value_sats"], destination),)):
                raise ServiceError("A signed transaction file differs from its reviewed report. Do not broadcast this bundle.")
            weight = len(parsed.stripped) * 3 + len(raw)
            size = (weight + 3) // 4
            if (weight != record["weight"] or size != record["actual_vbytes"] or weight > batch["estimated_upper_weight"]
                    or weight > report["review_plan"]["max_vbytes"] * 4
                    or record["actual_fee_rate_sat_per_vb"] != f"{record['fee_sats'] / size:.8f}"
                    or record["fee_sats"] < signer.fee_for(size, signer.parse_rate(report["fee_rate_requested_sat_per_vb"]))):
                raise ServiceError("The signed transaction size or fee differs from its report.")
            _verify_signatures(kind, signer, raw, parsed, coins, batch["output_value_sats"], destination)
        return report
    except ServiceError:
        raise
    except Exception:
        raise ServiceError("A signed transaction failed validation. Copy a fresh bundle from the offline computer.") from None


def export_signed_bundle(source, target) -> Path:
    """Copy only a validated report and its named .hex files; never copy a wallet."""
    source = Path(source)
    folder = source.parent if source.name == "report.json" else source
    report = inspect_signed_bundle(folder)
    with atomic_directory(target) as staging:
        write_json(staging / "report.json", report)
        for record in report["transactions"]:
            path = folder / record["file"]
            if path.is_symlink():
                raise ServiceError("Transaction links cannot be exported.")
            with path.open("rb") as handle:
                content = handle.read(800_002)
            if len(content) > 800_001:
                raise ServiceError("A signed transaction exceeds the size limit.")
            _write(staging / record["file"], content.decode("ascii"))
        inspect_signed_bundle(staging)  # Recheck the actual copied bytes before completion.
    return Path(target).absolute()
