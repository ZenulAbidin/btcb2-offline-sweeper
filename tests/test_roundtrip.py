"""Wallet -> USB files -> fork scan -> reviewed signing -> mocked broadcast.

All keys are published unfunded test vectors. Parent transactions and the fork
explorer are synthetic. A socket guard makes any accidental real network fail.
"""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from btcb2_tui import online, service
from btcb2_tui.wallet import Wallet
from test_online import FakeExplorer
from test_wallet import (FIRST_WIF, SECOND_WIF, WORDS, ZPRV, electrum_json,
                         encrypt_keystore, encrypt_storage)


class WalletRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.endpoint = "https://example.invalid/api"

    def synthetic_fork(self, wallet, inventory):
        signer = service.signer_for(wallet.kind)
        addresses = inventory["addresses"]
        # HD wallets spend from receiving AND change; WIF sets spend two keys.
        selected = [addresses[0], addresses[len(addresses) // 2]]
        scripts = [bytes.fromhex(row["script_pubkey"]) for row in selected]
        fake_input = b"\x55" * 32 + struct.pack("<I", 0) + b"\0" + b"\xff" * 4
        parent = (struct.pack("<I", 2) + b"\x01" + fake_input + b"\x02"
                  + b"".join(signer.serialize_output(100000, script) for script in scripts) + b"\0" * 4)
        txid = signer.sha256d(parent)[::-1].hex()
        return dict(format=service._MANIFESTS[wallet.kind], signing_profile=signer.PROFILE,
                    snapshot=dict(height=961641, block_hash="66" * 32), transactions={txid: parent.hex()},
                    utxos=[dict(txid=txid, vout=i, value_sats=100000, script_pubkey=script.hex())
                           for i, script in enumerate(scripts)])

    def roundtrip(self, wallet):
        self.addCleanup(wallet.close)
        public_usb = self.root / "usb-public"
        public_usb.mkdir()
        inventory_path = public_usb / "public_inventory.json"
        inventory = wallet.inventory(2)
        service.export_public_inventory(inventory, inventory_path)
        self.assertEqual(service.read_json(inventory_path), inventory)
        manifest = self.synthetic_fork(wallet, inventory)
        client = FakeExplorer(manifest, inventory)

        with patch("socket.socket", side_effect=AssertionError("No real network in roundtrip tests")):
            returned_folder = self.root / "usb-returned-manifest"
            collected = online.collect_inventory(wallet.kind, inventory_path, self.endpoint,
                                                 returned_folder, client=client)
            self.assertEqual(collected["manifest"], manifest)
            self.assertEqual(collected["evidence"]["included_outputs"], 2)
            self.assertEqual(collected["evidence"]["included_sats"], 200000)
            self.assertEqual(client.posts, [])
            manifest_path = returned_folder / "manifest.json"

            destination_wallet = Wallet.from_mnemonic(WORDS, "unfunded destination test", wallet.kind)
            self.addCleanup(destination_wallet.close)
            destination = destination_wallet.first_address
            plan_folder = self.root / "offline-plan"
            plan = service.plan(wallet.kind, manifest_path, destination, "1.25", 1000, 2000,
                                plan_folder, {"max_inputs": 1})
            self.assertFalse(plan["signed"])
            self.assertEqual(plan["batch_count"], 2)
            self.assertEqual(client.posts, [])

            # The original matching wallet handles keys, not the online client.
            keys = wallet.keys_for_manifest(manifest_path, inventory_path)
            self.assertEqual(len(keys), 2)
            signed_folder = self.root / "offline-signed"
            try:
                signed = service.sign(wallet.kind, manifest_path, keys, plan_folder / "report.json",
                                      signed_folder, expected_plan_sha256=plan["plan_sha256"])
                self.assertTrue(signed["signed"])
                self.assertEqual(signed["plan_sha256"], plan["plan_sha256"])
                self.assertEqual(signed["destination"], destination)
                self.assertEqual(signed["total_input_sats"], signed["total_fee_sats"] + signed["final_total_output_sats"])
                self.assertEqual(client.posts, [])

                signed_usb = self.root / "usb-signed-transfer"
                service.export_signed_bundle(signed_folder, signed_usb)
                self.assertEqual({p.name for p in signed_usb.iterdir()}, {"report.json", "tx_0001.hex", "tx_0002.hex"})
                # Public transfers cannot contain any of the selected WIFs or seed.
                for directory in (public_usb, returned_folder, signed_usb):
                    for path in directory.iterdir():
                        contents = path.read_text(encoding="utf-8")
                        for secret in [*keys, WORDS, ZPRV]:
                            self.assertNotIn(secret, contents)
                self.assertEqual(online.inspect_signed_bundle(signed_usb), signed)
                self.assertEqual(client.posts, [])
            finally:
                keys.clear()

            receipt_folder = self.root / "online-receipts"
            receipt = online.broadcast_bundle(signed_usb, self.endpoint, receipt_folder,
                                              expected_plan_sha256=signed["plan_sha256"], client=client)
            self.assertEqual(len(client.posts), 2)
            self.assertTrue(all(row["state"] == "accepted" for row in receipt["transactions"]))
            self.assertEqual(receipt, service.read_json(receipt_folder / "receipts.json"))
            for record, raw in zip(signed["transactions"], client.posts):
                self.assertEqual(raw, (signed_usb / record["file"]).read_text().strip())

            # Reopening the same receipt checks known txids and never POSTs again.
            online.broadcast_bundle(signed_usb, self.endpoint, receipt_folder,
                                    expected_plan_sha256=signed["plan_sha256"], client=client)
            self.assertEqual(len(client.posts), 2)
            status = online.check_status(receipt_folder, client=client)
            self.assertTrue(all(row["state"] == "already_known" for row in status["transactions"]))

    def test_bip39_native_segwit_receiving_and_change(self):
        self.roundtrip(Wallet.from_mnemonic(WORDS, "", "segwit"))

    def test_bip39_legacy_receiving_and_change(self):
        self.roundtrip(Wallet.from_mnemonic(WORDS, "", "legacy"))

    def test_bie1_electrum_with_encrypted_keystore(self):
        document = encrypt_keystore(electrum_json(), "synthetic password")
        path = self.root / "offline-encrypted-wallet"
        path.write_bytes(encrypt_storage(json.dumps(document).encode(), "synthetic password"))
        original = path.read_bytes()
        self.roundtrip(Wallet.load(path, "synthetic password"))
        self.assertEqual(path.read_bytes(), original)

    def test_compressed_wif_export(self):
        path = self.root / "offline-wif-export.txt"
        path.write_text(FIRST_WIF + "\n" + SECOND_WIF + "\n", encoding="ascii")
        self.roundtrip(Wallet.from_wif_file(path, "segwit"))


if __name__ == "__main__":
    unittest.main()
