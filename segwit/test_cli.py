"""Public synthetic end-to-end checks. Never fund the fixed test keys."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import offline_sweep as s


def forbid_network(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.fork", "os.posix_spawn", "os.exec"}:
        raise AssertionError("Network/process operation attempted during tests")


sys.addaudithook(forbid_network)


def wif(n):
    payload = b"\x80" + n.to_bytes(32, "big") + b"\x01"
    num = int.from_bytes(payload + s.sha256d(payload)[:4], "big")
    result = ""
    while num:
        num, r = divmod(num, 58)
        result = s.B58[r] + result
    return result


def key_script(n):
    pub = ec.derive_private_key(n, ec.SECP256K1()).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return b"\x00\x14" + s.hash160(pub)


def address(script):
    hrp = "bc"
    data = [0] + list(s.convertbits(list(script[2:]), 8, 5, True))
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = s.polymod(expanded + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(s.BECH32[x] for x in data + [(mod >> (5 * (5 - i))) & 31 for i in range(6)])


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # One fictional parent with two outputs controlled by key 1 and one by key 2.
        scripts = [key_script(1), key_script(1), key_script(2)]
        vin = b"\x55" * 32 + struct.pack("<I", 0) + b"\x00" + b"\xff" * 4
        parent = (struct.pack("<I", 2) + b"\x01" + vin + b"\x03"
                  + b"".join(s.serialize_output(100000, script) for script in scripts) + b"\x00" * 4)
        txid = s.sha256d(parent)[::-1].hex()
        self.manifest = {"format": "offline-p2wpkh-sweep/v2", "signing_profile": s.PROFILE,
            "snapshot": {"height": 961640, "block_hash": "66" * 32},
            "transactions": {txid: parent.hex()}, "utxos": [
                {"txid": txid, "vout": i, "value_sats": 100000, "script_pubkey": script.hex()}
                for i, script in enumerate(scripts)]}
        self.manifest_path = self.root / "manifest.json"
        self.save_manifest()
        self.keys_path = self.root / "keys.txt"
        self.keys_path.write_text(wif(1) + "\n" + wif(2) + "\n")
        self.keys_path.chmod(0o600)
        self.base = ["--manifest", str(self.manifest_path), "--destination", address(key_script(3)),
                     "--fee-rate", "1.25", "--max-inputs", "2", "--max-tx-fee-sats", "1000",
                     "--max-total-fee-sats", "2000"]

    def tearDown(self):
        self.tmp.cleanup()

    def save_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def run_cli(self, extra, base=None):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            result = s.main((self.base if base is None else base) + extra)
        self.assertNotIn(wif(1), capture.getvalue())
        self.assertNotIn(wif(2), capture.getvalue())
        return result, capture.getvalue()

    def plan(self):
        code, msg = self.run_cli(["--plan-only", "--out", str(self.root / "plan")])
        self.assertEqual(code, 0, msg)
        return self.root / "plan" / "report.json"

    def sign_args(self, report, name="signed"):
        return ["--keys-file", str(self.keys_path), "--reviewed-plan", str(report), "--out", str(self.root / name)]

    def test_review_then_sign_independent_batches_without_destination_key(self):
        report = self.plan()
        code, msg = self.run_cli(self.sign_args(report))
        self.assertEqual(code, 0, msg)
        signed = json.loads((self.root / "signed/report.json").read_text())
        public = json.loads(report.read_text())
        self.assertEqual(signed["plan_sha256"], public["plan_sha256"])
        self.assertEqual(signed["final_unspent_output_count"], 2)
        self.assertEqual(signed["total_input_sats"], signed["final_total_output_sats"] + signed["total_fee_sats"])
        inputs = []
        txids = {row["txid"] for row in signed["transactions"]}
        for row in signed["transactions"]:
            raw = bytes.fromhex((self.root / "signed" / row["file"]).read_text())
            tx = s.parse_transaction(raw)
            self.assertEqual(len(tx.outputs), 1)
            self.assertEqual(tx.outputs[0][1], key_script(3))
            self.assertTrue(all(wit[0][-1] == 0x21 for wit in tx.witnesses))
            self.assertTrue(all(prev not in txids for prev, _ in tx.inputs))
            self.assertIsNone(row["depends_on"])
            inputs.extend(tx.inputs)
            self.assertLessEqual(row["weight"], s.estimated_weight(row["input_count"]))
            self.assertGreaterEqual(row["fee_sats"], s.fee_for(row["actual_vbytes"], s.parse_rate("1.25")))
        self.assertEqual(len(set(inputs)), 3)
        if os.name == "posix":
            self.assertEqual((self.root / "signed").stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in (self.root / "signed").iterdir()))

    def test_changed_fee_destination_and_snapshot_fail_before_loading_keys(self):
        report = self.plan()
        self.keys_path.unlink()  # Missing file proves rejected plans are checked before key loading.
        for i, (option, value) in enumerate([("--fee-rate", "1.5"), ("--destination", address(key_script(4))),
                                          ("--max-tx-fee-sats", "1001")]):
            base = self.base[:]
            base[base.index(option) + 1] = value
            code, msg = self.run_cli(self.sign_args(report, str(i)), base)
            self.assertEqual(code, 2)
            self.assertIn("differ from the reviewed", msg)
            self.assertFalse((self.root / str(i)).exists())
        self.manifest["snapshot"]["block_hash"] = "77" * 32
        self.save_manifest()
        code, msg = self.run_cli(self.sign_args(report))
        self.assertEqual(code, 2)
        self.assertIn("differ from the reviewed", msg)

    def test_missing_review_and_pre_activation_rejected(self):
        code, msg = self.run_cli(["--keys-file", str(self.keys_path), "--out", str(self.root / "none")])
        self.assertEqual(code, 2)
        self.assertIn("--reviewed-plan", msg)
        self.manifest["snapshot"]["height"] = 961639
        self.save_manifest()
        report = self.plan()
        code, msg = self.run_cli(self.sign_args(report))
        self.assertEqual(code, 2)
        self.assertIn("activation", msg)

    def test_inconsistent_report_summary_is_rejected(self):
        report = self.plan()
        original = json.loads(report.read_text())
        for field, value in [("destination", address(key_script(4))), ("total_fee_sats", 0), ("plan_sha256", "0" * 64)]:
            changed = original.copy()
            changed[field] = value
            report.write_text(json.dumps(changed))
            code, msg = self.run_cli(self.sign_args(report))
            self.assertEqual(code, 2)
            self.assertIn("inconsistent", msg)

    def test_duplicate_mismatch_old_manifest_and_seed_rejected(self):
        original = json.dumps(self.manifest)
        mutations = [lambda d: d["utxos"].append(d["utxos"][0].copy()),
                     lambda d: d["utxos"][0].update(value_sats=99999),
                     lambda d: d.update(format="offline-p2wpkh-sweep/v1"),
                     lambda d: d["utxos"][0].update(role="seed")]
        for mutation in mutations:
            self.manifest = json.loads(original)
            mutation(self.manifest)
            self.save_manifest()
            code, _ = self.run_cli(["--plan-only", "--out", str(self.root / "bad")])
            self.assertEqual(code, 2)
            self.assertFalse((self.root / "bad").exists())

    def test_plan_ignores_keys_existing_output_and_fee_caps(self):
        self.keys_path.unlink()
        report = self.plan()
        code, _ = self.run_cli(["--plan-only", "--out", str(report.parent)])
        self.assertEqual(code, 2)
        for option in ["--max-tx-fee-sats", "--max-total-fee-sats"]:
            base = self.base[:]
            base[base.index(option) + 1] = "1"
            code, msg = self.run_cli(["--plan-only", "--out", str(self.root / "bad")], base)
            self.assertEqual(code, 2)
            self.assertIn("Fee ceiling", msg)

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_key_permissions_and_corrupt_key_errors_suppress_contents(self):
        report = self.plan()
        self.keys_path.chmod(0o644)
        code, msg = self.run_cli(self.sign_args(report))
        self.assertEqual(code, 2)
        self.assertIn("0600", msg)
        self.keys_path.chmod(0o600)
        secret_marker = "PRIVATE_CONTENT_MUST_NOT_APPEAR"
        self.keys_path.write_text(secret_marker + "\n")
        code, msg = self.run_cli(self.sign_args(report))
        self.assertEqual(code, 2)
        self.assertNotIn(secret_marker, msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
