"""Synthetic fixtures only. The BIP32 and BIP84 constants are public vectors."""
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from coincurve import PrivateKey
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from btcb2_tui.wallet import (
    InvalidPassword, PasswordRequired, UnsupportedWallet, Wallet, WalletError,
    _Node, _ORDER, _b58decode, _b58encode,
)


# https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki (CC0).
WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
ZPRV = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
FIRST = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
SECOND = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
CHANGE = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
FIRST_WIF = "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"
SECOND_WIF = "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy"
CHANGE_WIF = "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF"


def encrypt_aes(key, iv, plaintext):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def electrum_json(xpub=ZPUB, xprv=ZPRV):
    return {"wallet_type": "standard", "seed_version": 65,
            "keystore": {"type": "bip32", "xpub": xpub, "xprv": xprv}}


def encrypt_keystore(document, password):
    document = copy.deepcopy(document)
    key = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
    iv = bytes(range(16))
    plaintext = document["keystore"]["xprv"].encode()
    document["keystore"]["xprv"] = base64.b64encode(iv + encrypt_aes(key, iv, plaintext)).decode()
    document["keystore"]["pw_hash_version"] = 1
    document["use_encryption"] = True
    return document


def encrypt_storage(plaintext, password):
    # Independent encryption direction: recipient public * ephemeral private.
    # Electrum storage.py -> crypto.ecies_encrypt_message(BIE1) wire format.
    recipient_scalar = int.from_bytes(hashlib.pbkdf2_hmac("sha512", password.encode(), b"", 1024), "big") % _ORDER
    recipient = PrivateKey(recipient_scalar.to_bytes(32, "big"))
    ephemeral = PrivateKey((17).to_bytes(32, "big"))
    shared = recipient.public_key.multiply(ephemeral.secret).format(compressed=True)
    key = hashlib.sha512(shared).digest()
    encrypted = b"BIE1" + ephemeral.public_key.format(compressed=True)
    encrypted += encrypt_aes(key[16:32], key[:16], zlib.compress(plaintext))
    return base64.b64encode(encrypted + hmac.new(key[32:], encrypted, hashlib.sha256).digest())


class WalletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def write(self, name, value):
        path = self.directory / name
        if isinstance(value, dict):
            value = json.dumps(value).encode()
        if isinstance(value, str):
            value = value.encode()
        path.write_bytes(value)
        return path

    def transfer(self, wallet, *, positions=(0,), count=2):
        inventory = wallet.inventory(count)
        prefix = ("offline-p2wpkh-sweep/v2", "knots-unified-p2wpkh-0x21/v2") if wallet.kind == "segwit" else ("offline-p2pkh-sweep/v1", "knots-unified-p2pkh-compressed-0x21/v1")
        manifest = {"format": prefix[0], "signing_profile": prefix[1],
                    "utxos": [{"script_pubkey": inventory["addresses"][i]["script_pubkey"]} for i in positions]}
        return manifest, inventory, self.write("manifest.json", manifest), self.write("inventory.json", inventory)

    def test_bip84_electrum_inventory_and_selected_keys(self):
        document = electrum_json()
        document["addresses"] = {"receiving": [FIRST, SECOND], "change": [CHANGE]}
        path = self.write("electrum-wallet", document)
        original = path.read_bytes()
        wallet = Wallet.load(path)
        self.assertEqual(wallet.kind, "segwit")
        self.assertEqual(wallet.first_address, FIRST)
        self.assertFalse(wallet.watch_only)
        self.assertEqual(wallet.suggested_per_branch, 200)
        manifest, inventory, mp, ip = self.transfer(wallet, positions=(0, 1, 2, 0))
        self.assertEqual([row["address"] for row in inventory["addresses"][:3]], [FIRST, SECOND, CHANGE])
        self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF, SECOND_WIF, CHANGE_WIF])
        self.assertEqual(path.read_bytes(), original)
        self.assertNotIn(ZPRV, json.dumps(inventory))
        self.assertEqual(set(vars(wallet)), {"kind", "_node", "_imported", "_closed", "suggested_per_branch", "watch_only", "derivation", "source"})

    def test_bip32_independent_public_vector(self):
        # BIP32 vector 1 m/0H -> /1 (BSD-2-Clause public test vector).
        parent = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        child_xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        private = _Node.parse(parent, private=True)
        public = _Node.parse(private.xpub(), private=False)
        self.assertEqual(public.child(1).xpub(), child_xpub)
        self.assertEqual(private.child(1, private=True).xpub(), child_xpub)

    def test_official_electrum_native_seed_address_vectors(self):
        # Public test vectors from Electrum's own native-seed integration tests.
        # Verified using `git show` in the local upstream checkout, pinned source:
        # https://github.com/spesmilo/electrum/blob/de1ffddd56014b95dda57647478ab98ac1fdddf1/tests/test_wallet_vertical.py
        vectors = [
            ("xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U",
             "xprv9s21ZrQH143K32jECVM729vWgGq4mUDJCk1ozqAStTphzQtCTuoFmFafNoG1g55iCnBTXUzz3zWnDb5CVLGiFvmaZjuazHDL8a81cPQ8KL6",
             "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf", "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D", "legacy"),
            ("zpub6nsHdRuY92FsMKdbn9BfjBCG6X8pyhCibNP6uDvpnw2cyrVhecvHRMa3Ne8kdJZxjxgwnpbHLkcR4bfnhHy6auHPJyDTQ3kianeuVLdkCYQ",
             "zprvAZswDvNeJeha8qZ8g7efN3FXYVJLaEUsE9TW6qXDEbVe74AZ75c2sZFZXPNFzxnhChDQ89oC8C5AjWwHmH1HeRKE1c4kKBQAmjUDdKDUZw2",
             "bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af", "bc1qdy94n2q5qcp0kg7v9yzwe6wvfkhnvyzje7nx2p", "segwit"),
        ]
        for xpub, xprv, receiving, change, kind in vectors:
            with self.subTest(kind=kind):
                document = electrum_json(xpub=xpub, xprv=xprv)
                document["addresses"] = {"receiving": [receiving], "change": [change]}
                wallet = Wallet.load(self.write("electrum-official-vector", document))
                self.assertEqual(wallet.kind, kind)
                self.assertEqual(wallet.first_address, receiving)
                self.assertEqual([row["address"] for row in wallet.inventory(1)["addresses"]], [receiving, change])
                _, _, mp, ip = self.transfer(wallet, positions=(0, 1), count=1)
                self.assertEqual(len(wallet.keys_for_manifest(mp, ip)), 2)

    def test_keystore_password(self):
        path = self.write("encrypted-keys", encrypt_keystore(electrum_json(), "pässword"))
        with self.assertRaises(PasswordRequired):
            Wallet.load(path)
        with self.assertRaises(InvalidPassword):
            Wallet.load(path, "wrong")
        wallet = Wallet.load(path, "pässword")
        self.assertEqual(wallet.first_address, FIRST)
        _, _, mp, ip = self.transfer(wallet)
        self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF])

    def test_encrypted_keystore_may_start_with_private_key_prefix(self):
        password = "synthetic prefix collision password"
        key = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
        for prefix in ("xprv", "zprv"):
            with self.subTest(prefix=prefix):
                # The IV is stored first, so these three bytes force the base64
                # ciphertext's first four characters without changing its validity.
                iv = base64.b64decode(prefix) + bytes(range(13))
                document = electrum_json()
                document["keystore"]["xprv"] = base64.b64encode(iv + encrypt_aes(key, iv, ZPRV.encode())).decode()
                self.assertTrue(document["keystore"]["xprv"].startswith(prefix))
                path = self.write("prefix-collision", document)
                with self.assertRaises(PasswordRequired):
                    Wallet.load(path)
                with self.assertRaises(InvalidPassword):
                    Wallet.load(path, "wrong password")
                self.assertEqual(Wallet.load(path, password).first_address, FIRST)
        # A public extended key is neither a private key nor valid AES ciphertext.
        with self.assertRaises(WalletError):
            Wallet.load(self.write("public-in-private-slot", electrum_json(xprv=ZPUB)), password)

    def test_bie1_whole_wallet_and_double_encryption(self):
        for keystore_encrypted in (False, True):
            with self.subTest(keystore_encrypted=keystore_encrypted):
                document = electrum_json()
                if keystore_encrypted:
                    document = encrypt_keystore(document, "secret")
                path = self.write("encrypted-wallet", encrypt_storage(json.dumps(document).encode(), "secret"))
                with self.assertRaises(PasswordRequired):
                    Wallet.load(path)
                with self.assertRaises(InvalidPassword):
                    Wallet.load(path, "wrong")
                wallet = Wallet.load(path, "secret")
                self.assertEqual(wallet.first_address, FIRST)
                _, _, mp, ip = self.transfer(wallet)
                self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF])

    def test_bie1_tampering_fails_authentication(self):
        ciphertext = bytearray(base64.b64decode(encrypt_storage(json.dumps(electrum_json()).encode(), "secret")))
        ciphertext[45] ^= 1
        with self.assertRaises(InvalidPassword):
            Wallet.load(self.write("modified-wallet", base64.b64encode(ciphertext)), "secret")

    def test_unsupported_wallets(self):
        for document in ({"wallet_type": "2of3"}, {"wallet_type": "imported"},
                         {"wallet_type": "standard", "keystore": {"type": "hardware"}},
                         {"wallet_type": "standard", "keystore": {"type": "old"}}):
            with self.subTest(document=document), self.assertRaises(UnsupportedWallet):
                Wallet.load(self.write("unsupported", document))
        with self.assertRaises(UnsupportedWallet):
            Wallet.load(self.write("hardware-encrypted", base64.b64encode(b"BIE2" + bytes(100))))
        encrypted = encrypt_keystore(electrum_json(), "secret")
        encrypted["keystore"]["pw_hash_version"] = 2
        with self.assertRaises(UnsupportedWallet):
            Wallet.load(self.write("future-version", encrypted), "secret")

    def test_watch_only_can_export_but_not_sign(self):
        wallet = Wallet.load(self.write("watch-only", electrum_json(xprv=None)))
        self.assertTrue(wallet.watch_only)
        self.assertEqual(wallet.inventory(1)["addresses"][0]["address"], FIRST)
        with self.assertRaises(UnsupportedWallet):
            wallet.keys_for_manifest("not-opened", "not-opened")

    def test_mismatched_keys_and_stored_addresses(self):
        document = electrum_json()
        raw = bytearray(_b58decode(ZPUB))
        raw[13] ^= 1
        document["keystore"]["xpub"] = _b58encode(bytes(raw))
        with self.assertRaisesRegex(WalletError, "do not match"):
            Wallet.load(self.write("mismatch", document))
        document = electrum_json()
        document["addresses"] = {"receiving": [CHANGE]}
        with self.assertRaisesRegex(WalletError, "addresses do not match"):
            Wallet.load(self.write("mismatch", document))

    def test_duplicate_json_and_bad_key_are_rejected_without_secret_errors(self):
        with self.assertRaises(WalletError):
            Wallet.load(self.write("duplicate", '{"wallet_type":"standard","wallet_type":"imported"}'))
        document = electrum_json(xprv="zprv-this-is-not-a-key")
        with self.assertRaises(WalletError) as error:
            Wallet.load(self.write("malformed", document))
        self.assertNotIn("zprv-this", str(error.exception))

    def test_manifest_inventory_tampering_and_profile(self):
        wallet = Wallet.load(self.write("wallet", electrum_json()))
        for alteration in ("address", "branch", "index", "duplicate", "unknown", "profile", "wallet"):
            with self.subTest(alteration=alteration):
                manifest, inventory, mp, ip = self.transfer(wallet)
                if alteration == "address":
                    inventory["addresses"][0]["address"] = CHANGE
                elif alteration == "branch":
                    inventory["addresses"][0]["branch"] = True
                elif alteration == "index":
                    inventory["addresses"][0]["index"] = 2**31
                elif alteration == "duplicate":
                    inventory["addresses"].append(inventory["addresses"][0])
                elif alteration == "unknown":
                    manifest["utxos"][0]["script_pubkey"] = "0014" + "00" * 20
                elif alteration == "profile":
                    manifest["signing_profile"] = "other"
                else:
                    inventory["zpub"] = "other-wallet"
                self.write(ip.name, inventory)
                self.write(mp.name, manifest)
                with self.assertRaises(WalletError):
                    wallet.keys_for_manifest(mp, ip)

    def test_bip39_bip84_vectors(self):
        wallet = Wallet.from_mnemonic(WORDS, "", "segwit")
        self.assertEqual(wallet.zpub, ZPUB)
        self.assertEqual(wallet.first_address, FIRST)
        self.assertEqual(wallet.derivation, "m/84'/0'/0'")
        _, _, mp, ip = self.transfer(wallet, positions=(0, 2))
        self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF, CHANGE_WIF])
        different = Wallet.from_mnemonic(WORDS, "", "segwit", account=1)
        self.assertNotEqual(different.first_address, FIRST)
        different = Wallet.from_mnemonic(WORDS, "TREZOR", "segwit")
        self.assertNotEqual(different.first_address, FIRST)

    def test_bip39_bip44_legacy_and_signer_compatibility(self):
        from legacy import offline_sweep as signer
        wallet = Wallet.from_mnemonic(WORDS, "", "legacy")
        self.assertEqual(wallet.first_address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
        self.assertEqual(wallet.derivation, "m/44'/0'/0'")
        _, inventory, mp, ip = self.transfer(wallet)
        keys = wallet.keys_for_manifest(mp, ip)
        keyfile = self.write("keys.txt", "\n".join(keys))
        loaded = signer.load_keys(keyfile, 128)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(signer.destination_script(wallet.first_address, "bc").hex(), inventory["addresses"][0]["script_pubkey"])

    def test_all_wallet_inventory_sources_accepted_by_online_boundary(self):
        from btcb2_tui import service
        sources = [Wallet.load(self.write("electrum", electrum_json())),
                   Wallet.from_mnemonic(WORDS, "", "legacy"),
                   Wallet.from_wif_file(self.write("wif", FIRST_WIF), "segwit"),
                   Wallet.from_wif_file(self.write("wif", FIRST_WIF), "legacy")]
        for wallet in sources:
            with self.subTest(source=wallet.source, kind=wallet.kind):
                inventory = wallet.inventory(3)
                self.assertEqual(service.validate_inventory(inventory, wallet.kind), inventory)

    def test_legacy_electrum_and_large_stored_range(self):
        wallet = Wallet.from_mnemonic(WORDS, "", "legacy")
        node = wallet._node
        xprv = _b58encode(bytes.fromhex("0488ade4") + bytes([node.depth]) + node.parent
                          + node.index.to_bytes(4, "big") + node.chain + b"\0" + node.secret)
        document = electrum_json(xpub=wallet.zpub, xprv=xprv)
        inventory = wallet.inventory(240)
        document["addresses"] = {"receiving": [r["address"] for r in inventory["addresses"] if r["branch"] == 0],
                                 "change": [r["address"] for r in inventory["addresses"] if r["branch"] == 1]}
        restored = Wallet.load(self.write("legacy", document))
        self.assertEqual(restored.kind, "legacy")
        self.assertEqual(restored.first_address, wallet.first_address)
        self.assertEqual(restored.suggested_per_branch, 260)
        self.assertEqual(restored.inventory(240), inventory)

    def test_invalid_xpub_curve_point_is_rejected(self):
        raw = bytearray(_b58decode(ZPUB))
        raw[45:] = b"\x02" + b"\xff" * 32
        with self.assertRaisesRegex(WalletError, "Invalid extended key material"):
            Wallet.load(self.write("invalid-point", electrum_json(xpub=_b58encode(bytes(raw)), xprv=None)))

    def test_encrypted_storage_decompression_is_bounded(self):
        # Small bound avoids a large allocation while exercising the real decoder.
        ciphertext = encrypt_storage(json.dumps(electrum_json()).encode(), "secret")
        path = self.write("large-wallet", ciphertext)
        with patch("btcb2_tui.wallet._MAX_FILE", 128):
            from btcb2_tui.wallet import _decrypt_storage
            with self.assertRaises(WalletError):
                _decrypt_storage(base64.b64decode(path.read_bytes()), "secret")

    def test_invalid_mnemonic_and_account(self):
        for phrase in ("abandon " * 12, "not a mnemonic", ""):
            with self.assertRaises(WalletError):
                Wallet.from_mnemonic(phrase, "", "segwit")
        for account in (-1, True, 2**31, "0"):
            with self.assertRaises(WalletError):
                Wallet.from_mnemonic(WORDS, "", "segwit", account=account)
        with self.assertRaises(UnsupportedWallet):
            Wallet.from_mnemonic(WORDS, "", "taproot")

    def test_wif_plain_prefixed_and_dumpwallet(self):
        formats = [FIRST_WIF, "p2wpkh:" + FIRST_WIF,
                   "# Wallet dump created by Bitcoin Core\n" + FIRST_WIF + " 2020-01-02T03:04:05Z label=hello # addr=" + FIRST]
        for text in formats:
            with self.subTest(text=text[:20]):
                wallet = Wallet.from_wif_file(self.write("wif.txt", text), "segwit")
                self.assertEqual(wallet.first_address, FIRST)
                self.assertFalse(wallet.watch_only)
                inventory = wallet.inventory(200)
                self.assertEqual(inventory["per_branch"], 1)
                self.assertEqual(len(inventory["addresses"]), 1)
                self.assertRegex(inventory["zpub"], r"^imported:[0-9a-f]{64}$")
                self.assertNotIn(FIRST_WIF, json.dumps(inventory))
                _, _, mp, ip = self.transfer(wallet)
                self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF])

    def test_wif_order_deduplication_and_invalid_inputs(self):
        a = Wallet.from_wif_file(self.write("a", FIRST_WIF + "\n" + SECOND_WIF), "segwit")
        b = Wallet.from_wif_file(self.write("b", SECOND_WIF + "\n" + FIRST_WIF + "\n" + FIRST_WIF), "segwit")
        self.assertEqual(a.inventory(2), b.inventory(1))
        for text in ("", "# no keys", "not a key", "p2pkh:" + FIRST_WIF, FIRST_WIF + " garbage", _b58encode(b"\x80" + bytes.fromhex("01" * 32))):
            with self.subTest(text=text[:20]), self.assertRaises(WalletError):
                Wallet.from_wif_file(self.write("bad", text), "segwit")

    def test_private_child_checked_against_public_address(self):
        wallet = Wallet.from_mnemonic(WORDS, "", "segwit")
        _, _, mp, ip = self.transfer(wallet)
        wallet._node.secret = (1).to_bytes(32, "big")
        with self.assertRaisesRegex(WalletError, "Private-key/address verification failed"):
            wallet.keys_for_manifest(mp, ip)

    def test_no_network_and_close(self):
        with patch("socket.socket", side_effect=AssertionError("Network disabled")):
            wallet = Wallet.load(self.write("wallet", electrum_json()))
            _, _, mp, ip = self.transfer(wallet)
            self.assertEqual(wallet.keys_for_manifest(mp, ip), [FIRST_WIF])
        wallet.close()
        with self.assertRaises(WalletError):
            wallet.inventory(1)
        with self.assertRaises(WalletError):
            wallet.keys_for_manifest(mp, ip)
        for count in (0, -1, True, 100001):
            with self.assertRaises(WalletError):
                Wallet.load(self.directory / "wallet").inventory(count)


if __name__ == "__main__":
    unittest.main()
