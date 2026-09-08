"""Synthetic, unfunded test keys exercise both complete offline workflows."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from btcb2_tui import service


def b58(payload, signer):
    raw = payload + signer.sha256d(payload)[:4]
    n, text = int.from_bytes(raw, "big"), ""
    while n:
        n, digit = divmod(n, 58)
        text = signer.B58[digit] + text
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + text


def wif(n, signer):
    return b58(b"\x80" + n.to_bytes(32, "big") + b"\x01", signer)


def script(n, kind, signer):
    public = ec.derive_private_key(n, ec.SECP256K1()).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    h = signer.hash160(public)
    return b"\x00\x14" + h if kind == "segwit" else b"\x76\xa9\x14" + h + b"\x88\xac"


def address(raw_script, kind, signer):
    if kind == "legacy":
        return b58(b"\x00" + raw_script[3:23], signer)
    hrp = "bc"
    data = [0] + list(signer.convertbits(list(raw_script[2:]), 8, 5, True))
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = signer.polymod(expanded + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(signer.BECH32[x] for x in data + [(mod >> (5 * (5 - i))) & 31 for i in range(6)])


def fixture(root, kind):
    signer = service.signer_for(kind)
    scripts = [script(1, kind, signer), script(2, kind, signer)]
    vin = b"\x55" * 32 + struct.pack("<I", 0) + b"\x00" + b"\xff" * 4
    parent = struct.pack("<I", 2) + b"\x01" + vin + b"\x02" + b"".join(signer.serialize_output(100000, s) for s in scripts) + b"\x00" * 4
    txid = signer.sha256d(parent)[::-1].hex()
    manifest = dict(format=service._MANIFESTS[kind], signing_profile=signer.PROFILE,
                    snapshot=dict(height=961641, block_hash="66" * 32), transactions={txid: parent.hex()},
                    utxos=[dict(txid=txid, vout=i, value_sats=100000, script_pubkey=s.hex()) for i, s in enumerate(scripts)])
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    dest = address(script(3, kind, signer), kind, signer)
    inventory = dict(format="electrum-public-inventory/v1", zpub="imported:" + "77" * 32, per_branch=2,
                     addresses=[dict(branch=0, index=i, address=address(s, kind, signer), script_pubkey=s.hex()) for i, s in enumerate(scripts)])
    return signer, manifest, path, dest, inventory


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def workflow(self, kind, max_inputs=1):
        signer, manifest, path, destination, inventory = fixture(self.root, kind)
        unsigned = service.plan(kind, path, destination, "1.25", 1000, 2000,
                                self.root / "plan", {"max_inputs": max_inputs})
        signed = service.sign(kind, path, [wif(1, signer), wif(2, signer)],
                              self.root / "plan/report.json", self.root / "signed",
                              expected_plan_sha256=unsigned["plan_sha256"])
        return unsigned, signed, signer

    def test_both_kinds_roundtrip_and_public_only_export(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                self.root = Path(name)
                unsigned, signed, signer = self.workflow(kind)
                self.assertEqual(unsigned["plan_sha256"], signed["plan_sha256"])
                self.assertEqual(signed, service.inspect_signed_bundle(self.root / "signed"))
                self.assertEqual(signed["total_input_sats"], signed["total_fee_sats"] + signed["final_total_output_sats"])
                (self.root / "signed/wallet.dat").write_text("THIS MUST NEVER BE EXPORTED")
                (self.root / "signed/private.keys").write_text(wif(1, signer))
                target = service.export_signed_bundle(self.root / "signed", self.root / "usb")
                self.assertEqual({p.name for p in target.iterdir()}, {"report.json", "tx_0001.hex", "tx_0002.hex"})
                for file in target.iterdir():
                    self.assertNotIn(wif(1, signer), file.read_text())
                with self.assertRaises(service.ServiceError):
                    service.export_signed_bundle(self.root / "signed", target)

    def test_malicious_report_fields_and_path_traversal_rejected(self):
        _, signed, _ = self.workflow("segwit")
        bad = copy.deepcopy(signed)
        bad["private_keys"] = "secret"
        with self.assertRaises(service.ServiceError):
            service.validate_report(bad)
        for value in ("../../wallet.dat", "C:\\wallet.dat", "tx_0002.hex"):
            bad = copy.deepcopy(signed)
            bad["transactions"][0]["file"] = value
            with self.assertRaises(service.ServiceError):
                service.validate_report(bad)

    def test_swapped_transaction_and_corrupt_signature_rejected(self):
        _, signed, signer = self.workflow("segwit")
        first, second = self.root / "signed/tx_0001.hex", self.root / "signed/tx_0002.hex"
        original = first.read_text()
        first.write_text(second.read_text())
        with self.assertRaises(service.ServiceError):
            service.inspect_signed_bundle(self.root / "signed")
        raw = bytearray.fromhex(original)
        raw[-40] ^= 1
        first.write_text(raw.hex())
        # Even an attacker who adjusts wtxid cannot pass signature validation.
        signed["transactions"][0]["wtxid"] = signer.sha256d(bytes(raw))[::-1].hex()
        (self.root / "signed/report.json").write_text(json.dumps(signed))
        with self.assertRaises(service.ServiceError):
            service.inspect_signed_bundle(self.root / "signed")

    def test_changed_amount_summary_and_review_approval_rejected(self):
        _, signed, signer = self.workflow("legacy")
        bad = copy.deepcopy(signed)
        bad["total_fee_sats"] += 1
        with self.assertRaises(service.ServiceError):
            service.validate_report(bad)
        bad = copy.deepcopy(signed)
        bad["review_plan"]["transactions"][0]["inputs"][0]["value_sats"] += 1
        with self.assertRaises(service.ServiceError):
            service.validate_report(bad)
        with self.assertRaisesRegex(service.ServiceError, "changed after approval"):
            service.sign("legacy", self.root / "manifest.json", [wif(1, signer), wif(2, signer)],
                         self.root / "plan/report.json", self.root / "never", expected_plan_sha256="00" * 32)
        self.assertFalse((self.root / "never").exists())

    def test_missing_key_cleans_all_temporary_outputs(self):
        signer, _, path, destination, _ = fixture(self.root, "segwit")
        service.plan("segwit", path, destination, "1", 1000, 1000, self.root / "plan")
        local_temp = self.root / "local-temp"
        local_temp.mkdir()
        real_temp = tempfile.TemporaryDirectory
        with patch("btcb2_tui.service.tempfile.TemporaryDirectory", side_effect=lambda **kw: real_temp(dir=local_temp, **kw)):
            with self.assertRaises(service.ServiceError):
                service.sign("segwit", path, [wif(1, signer)], self.root / "plan/report.json", self.root / "failed")
        self.assertFalse((self.root / "failed").exists())
        self.assertEqual(list(local_temp.iterdir()), [])
        self.assertEqual(list(self.root.glob(".btcb2-pending-*")), [])

    def test_duplicate_json_and_public_secret_fields_rejected(self):
        path = self.root / "bad.json"
        path.write_text('{"format":"x","format":"y"}')
        with self.assertRaises(service.ServiceError):
            service.read_json(path)
        _, _, _, _, inventory = fixture(self.root, "segwit")
        service.export_public_inventory(inventory, self.root / "public.json")
        with self.assertRaises(service.ServiceError):
            service.export_public_inventory(inventory, self.root / "public.json")
        inventory["seed"] = "never-export"
        with self.assertRaises(service.ServiceError):
            service.export_public_inventory(inventory, self.root / "bad-export.json")
        self.assertFalse((self.root / "bad-export.json").exists())

    def test_failed_plan_and_existing_output_never_overwrite(self):
        _, _, path, destination, _ = fixture(self.root, "segwit")
        with self.assertRaises(service.ServiceError):
            service.plan("segwit", path, destination, "100", 1, 1, self.root / "fail")
        self.assertFalse((self.root / "fail").exists())
        target = self.root / "keep"
        target.mkdir()
        (target / "data").write_text("keep")
        with self.assertRaises(service.ServiceError):
            service.plan("segwit", path, destination, "1", 1000, 1000, target)
        self.assertEqual((target / "data").read_text(), "keep")

    def test_legacy_and_segwit_signers_do_not_collide(self):
        segwit, legacy = service.signer_for("segwit"), service.signer_for("legacy")
        self.assertNotEqual(segwit.PROFILE, legacy.PROFILE)
        self.assertIsNot(segwit, legacy)

    def test_keys_never_reach_file_writers_even_when_signing_is_interrupted(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                signer, _, manifest, destination, _ = fixture(root, kind)
                service.plan(kind, manifest, destination, "1", 1000, 1000, root / "plan")
                secrets = [wif(1, signer), wif(2, signer)]
                original_write, original_signer_write = service._write, signer.write_private
                writes = []
                def watched(writer):
                    def write(path, content):
                        writes.append(str(path))
                        for secret in secrets:
                            self.assertNotIn(secret, content)
                        return writer(path, content)
                    return write
                with patch.object(service, "_write", side_effect=watched(original_write)), \
                     patch.object(signer, "write_private", side_effect=watched(original_signer_write)), \
                     patch.object(signer, "load_keys", side_effect=AssertionError("File-based key loading is forbidden")), \
                     patch.object(signer, "sign_transaction", side_effect=KeyboardInterrupt()):
                    with self.assertRaises(service.ServiceError):
                        service.sign(kind, manifest, secrets, root / "plan/report.json", root / "interrupted")
                self.assertTrue(writes)  # Public manifest/report writes were inspected.
                self.assertFalse((root / "interrupted").exists())
                self.assertFalse(any(".keys" in path for path in writes))

    def test_rejected_review_does_not_invoke_in_memory_key_provider(self):
        signer, _, manifest, destination, _ = fixture(self.root, "segwit")
        service.plan("segwit", manifest, destination, "1", 1000, 1000, self.root / "plan")
        # A separately valid manifest whose raw parent value differs from the review.
        data = json.loads(manifest.read_text())
        data["snapshot"]["block_hash"] = "88" * 32
        manifest.write_text(json.dumps(data))
        with patch.object(signer, "parse_key_lines", side_effect=AssertionError("Keys accessed before review binding")) as provider:
            with self.assertRaises(service.ServiceError):
                service.sign("segwit", manifest, [wif(1, signer), wif(2, signer)], self.root / "plan/report.json", self.root / "rejected")
            provider.assert_not_called()


if __name__ == "__main__":
    unittest.main()
