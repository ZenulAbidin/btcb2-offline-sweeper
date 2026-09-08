"""Network operations use deterministic fake public explorers; no real sends."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from btcb2_tui import online, service
from test_service import fixture, wif


class FakeExplorer:
    def __init__(self, manifest=None, inventory=None):
        self.manifest, self.inventory = manifest, inventory
        self.gets, self.posts = [], []
        self.known = {}
        self.fail_post = False
        self.wrong_checkpoint = False

    def get(self, path):
        self.gets.append(path)
        if path == "/block-height/961640":
            return "00" * 32 if self.wrong_checkpoint else online.CHECKPOINT
        if path.endswith("/status"):
            txid = path.split("/")[2]
            if txid in self.known:
                return self.known[txid]
            raise online.NotFound("Unknown")
        manifest = self.manifest
        if path == "/blocks/tip/hash":
            return manifest["snapshot"]["block_hash"]
        if path == "/block/" + manifest["snapshot"]["block_hash"]:
            return {"height": manifest["snapshot"]["height"]}
        if path == "/block-height/" + str(manifest["snapshot"]["height"]):
            return manifest["snapshot"]["block_hash"]
        if path.startswith("/address/"):
            address = path.split("/")[2]
            row = next(row for row in self.inventory["addresses"] if row["address"] == address)
            return [dict(txid=coin["txid"], vout=coin["vout"], value=coin["value_sats"],
                         status=dict(confirmed=True, block_height=961640)) for coin in manifest["utxos"] if coin["script_pubkey"] == row["script_pubkey"]]
        if path.endswith("/hex"):
            return manifest["transactions"][path.split("/")[2]]
        if path.endswith("/outspends"):
            return [{"spent": False}, {"spent": False}]
        raise AssertionError(path)

    def post_transaction(self, raw):
        self.posts.append(raw)
        txid = service.signer_for("segwit").parse_transaction(bytes.fromhex(raw)).txid
        if self.fail_post:
            raise online.NetworkError("Simulated timeout")
        self.known[txid] = {"confirmed": False}
        return txid


class OnlineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.endpoint = "https://example.invalid/api"

    def tearDown(self):
        self.temporary.cleanup()

    def signed(self, kind="segwit"):
        signer, manifest, path, destination, inventory = fixture(self.root, kind)
        plan = service.plan(kind, path, destination, "1", 1000, 2000, self.root / "plan", {"max_inputs": 1})
        report = service.sign(kind, path, [wif(1, signer), wif(2, signer)], self.root / "plan/report.json", self.root / "signed")
        return report

    def broadcast(self, client, report):
        return online.broadcast_bundle(self.root / "signed", self.endpoint, self.root / "receipts",
                                       expected_plan_sha256=report["plan_sha256"], client=client)

    def test_scan_both_types_checkpoint_and_manifest_validation(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                _, manifest, _, _, inventory = fixture(root, kind)
                client = FakeExplorer(manifest, inventory)
                messages = []
                result = online.collect_inventory(kind, inventory, self.endpoint, root / "scan", progress=messages.append, client=client)
                self.assertEqual(result["manifest"], manifest)
                self.assertEqual(result["evidence"]["included_sats"], 200000)
                self.assertEqual(client.gets[0], "/block-height/961640")
                self.assertTrue((root / "scan/verification.json").exists())
                self.assertTrue(messages)
                self.assertEqual(client.posts, [])

    def test_wrong_fork_blocks_scan_and_broadcast(self):
        _, manifest, _, _, inventory = fixture(self.root, "segwit")
        client = FakeExplorer(manifest, inventory)
        client.wrong_checkpoint = True
        with self.assertRaises(service.ServiceError):
            online.collect_inventory("segwit", inventory, self.endpoint, self.root / "scan", client=client)
        self.assertFalse((self.root / "scan").exists())
        report = self.signed()
        with self.assertRaises(service.ServiceError):
            self.broadcast(client, report)
        self.assertEqual(client.posts, [])

    def test_preview_never_networks_and_broadcast_receipts_resume_without_post(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                self.root = Path(name)
                report = self.signed(kind)
                client = FakeExplorer()
                service.inspect_signed_bundle(self.root / "signed")
                self.assertEqual(client.gets, [])
                receipt = self.broadcast(client, report)
                self.assertEqual(len(client.posts), 2)
                self.assertTrue(all(row["state"] == "accepted" for row in receipt["transactions"]))
                self.broadcast(client, report)
                self.assertEqual(len(client.posts), 2)
                receipt = online.check_status(self.root / "receipts", client=client)
                self.assertTrue(all(row["state"] == "already_known" for row in receipt["transactions"]))

    def test_uncertain_post_is_durable_and_never_retried(self):
        report = self.signed()
        client = FakeExplorer()
        client.fail_post = True
        receipt = self.broadcast(client, report)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual([row["state"] for row in receipt["transactions"]], ["uncertain", "pending"])
        self.assertEqual(receipt, json.loads((self.root / "receipts/receipts.json").read_text()))
        client.fail_post = False
        self.broadcast(client, report)
        self.assertEqual(len(client.posts), 1)

    def test_pending_receipt_saved_before_network_post(self):
        report = self.signed()
        client = FakeExplorer()
        original = client.post_transaction
        def post(raw):
            receipt = json.loads((self.root / "receipts/receipts.json").read_text())
            self.assertIn("sending", [row["state"] for row in receipt["transactions"]])
            return original(raw)
        client.post_transaction = post
        self.broadcast(client, report)

    def test_resume_clears_confirmation_when_transaction_disappears(self):
        from btcb2_tui.online_app import receipt_text

        report = self.signed()
        client = FakeExplorer()
        self.broadcast(client, report)
        txid = report["transactions"][0]["txid"]
        client.known[txid] = {"confirmed": True, "block_height": 961700}
        self.broadcast(client, report)
        del client.known[txid]

        receipt = self.broadcast(client, report)
        first = receipt["transactions"][0]
        self.assertEqual(first["state"], "uncertain")
        self.assertNotIn("confirmed", first)
        self.assertNotIn("block_height", first)
        self.assertNotIn("Confirmed in block 961700", receipt_text(receipt))
        saved = json.loads((self.root / "receipts/receipts.json").read_text())
        self.assertEqual(saved, receipt)
        self.assertEqual(len(client.posts), 2)  # No retry of either existing transaction.

    def test_confirmed_to_unconfirmed_clears_height_in_both_receipt_update_paths(self):
        from btcb2_tui.online_app import receipt_text

        report = self.signed()
        client = FakeExplorer()
        self.broadcast(client, report)
        txid = report["transactions"][0]["txid"]
        receipt_path = self.root / "receipts/receipts.json"
        for mode in ("broadcast", "check_status"):
            with self.subTest(mode=mode):
                def update():
                    return self.broadcast(client, report) if mode == "broadcast" else online.check_status(receipt_path, client=client)
                client.known[txid] = {"confirmed": True, "block_height": 961700}
                confirmed = update()
                self.assertEqual(confirmed["transactions"][0]["block_height"], 961700)
                client.known[txid] = {"confirmed": False}
                receipt = update()
                first = receipt["transactions"][0]
                self.assertEqual(first["state"], "already_known")
                self.assertIs(first["confirmed"], False)
                self.assertNotIn("block_height", first)
                self.assertNotIn("Confirmed in block", receipt_text(receipt))
                self.assertEqual(json.loads(receipt_path.read_text()), receipt)
                self.assertEqual(len(client.posts), 2)

    def test_changed_approval_and_malicious_transfer_never_network(self):
        report = self.signed()
        client = FakeExplorer()
        with self.assertRaisesRegex(service.ServiceError, "changed after approval"):
            online.broadcast_bundle(self.root / "signed", self.endpoint, self.root / "receipts",
                                    expected_plan_sha256="00" * 32, client=client)
        self.assertEqual(client.gets, [])
        (self.root / "signed/tx_0001.hex").write_text("00")
        with self.assertRaises(service.ServiceError):
            self.broadcast(client, report)
        self.assertEqual(client.gets, [])
        self.assertEqual(client.posts, [])

    def test_endpoint_validation(self):
        for endpoint in ("http://example.org", "https://user:pass@example.org", "https://example.org/?key=secret", "https://example.org/#x", "https://example.org\\@evil.test", "https://example.org/ white"):
            with self.subTest(endpoint=endpoint), self.assertRaises(service.ServiceError):
                online.validate_endpoint(endpoint)
        self.assertEqual(online.validate_endpoint("https://example.org/api/"), "https://example.org/api")

    def test_post_transport_never_retries(self):
        client = online.ExplorerClient(self.endpoint)
        with patch.object(client, "_request", side_effect=TimeoutError()) as request:
            with self.assertRaises(online.NetworkError):
                client.post_transaction("00")
            self.assertEqual(request.call_count, 1)

    def test_status_during_broadcast_never_overwrites_durable_receipt(self):
        report = self.signed()
        client = FakeExplorer()
        original = client.post_transaction
        def post(raw):
            path = self.root / "receipts/receipts.json"
            before = path.read_bytes()
            checked = online.check_status(path, client=client)
            self.assertTrue(any(row["state"] == "uncertain" for row in checked["transactions"]))
            self.assertEqual(path.read_bytes(), before)
            return original(raw)
        client.post_transaction = post
        receipt = self.broadcast(client, report)
        self.assertTrue(all(row["state"] == "accepted" for row in receipt["transactions"]))


if __name__ == "__main__":
    unittest.main()
