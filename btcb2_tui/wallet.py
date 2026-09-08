"""Offline wallet adapters; never write a wallet, password, seed, or private key.

Electrum interoperability follows its storage.py, crypto.py and bip32.py:
https://github.com/spesmilo/electrum/tree/master/electrum
BIP32/BIP39/BIP44/BIP84 use their published Bitcoin BIP specifications.
Elliptic-curve operations use libsecp256k1 through coincurve; AES uses
cryptography. Wallet addresses always use Bitcoin mainnet encodings.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import unicodedata
import zlib

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mnemonic import Mnemonic


_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_HEADERS = {"legacy": (0x0488B21E, 0x0488ADE4), "segwit": (0x04B24746, 0x04B2430C)}
_PROFILES = {
    "legacy": ("offline-p2pkh-sweep/v1", "knots-unified-p2pkh-compressed-0x21/v1"),
    "segwit": ("offline-p2wpkh-sweep/v2", "knots-unified-p2wpkh-0x21/v2"),
}
_MAX_FILE = 64 * 1024 * 1024
_MAX_ADDRESSES = 100000


class WalletError(ValueError):
    """A wallet or public transfer file cannot safely be used."""


class PasswordRequired(WalletError):
    """The caller should ask for a password using a masked input."""


class InvalidPassword(WalletError):
    """Decryption failed; error text must never contain decrypted data."""


class UnsupportedWallet(WalletError):
    """The input is outside the supported wallet formats."""


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _b58encode(payload: bytes) -> str:
    data = payload + _sha256d(payload)[:4]
    value = int.from_bytes(data, "big")
    result = ""
    while value:
        value, remainder = divmod(value, 58)
        result = _B58[remainder] + result
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + result


def _b58decode(value: str) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 120:
        raise WalletError("Invalid Base58 key encoding")
    number = 0
    for char in value:
        if char not in _B58:
            raise WalletError("Invalid Base58 key encoding")
        number = number * 58 + _B58.index(char)
    data = b"\0" * (len(value) - len(value.lstrip("1")))
    data += number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(data) < 5 or not hmac.compare_digest(_sha256d(data[:-4])[:4], data[-4:]):
        raise WalletError("Key checksum is invalid")
    return data[:-4]


def _p2wpkh(program: bytes) -> str:
    # BIP173 witness-v0 Bech32 (not Bech32m).
    acc = bits = 0
    values = [0]
    for item in program:
        acc = (acc << 8) | item
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    check = 1
    for item in expanded + values + [0] * 6:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ item
        for i, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> i) & 1:
                check ^= generator
    check ^= 1
    checksum = [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    return "bc1" + "".join(_BECH32[item] for item in values + checksum)


def _address(pubkey: bytes, kind: str) -> tuple[str, str]:
    digest = _hash160(pubkey)
    if kind == "segwit":
        return _p2wpkh(digest), "0014" + digest.hex()
    return _b58encode(b"\0" + digest), "76a914" + digest.hex() + "88ac"


def _check_kind(kind: str) -> None:
    if kind not in _HEADERS:
        raise UnsupportedWallet("Choose native SegWit (bc1q) or legacy (1) inputs")


def _unique_json(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise WalletError("Duplicate JSON field in input file")
        result[key] = value
    return result


def _json(data: bytes) -> dict:
    try:
        result = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_json)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise WalletError("The file is not valid wallet or transfer JSON") from None
    if not isinstance(result, dict):
        raise WalletError("Expected a JSON object")
    return result


def _read(path: str | Path) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(_MAX_FILE + 1)
    except OSError:
        raise WalletError("Could not read the selected file; check the path and permissions") from None
    if len(data) > _MAX_FILE:
        raise WalletError("Input file exceeds the 64 MiB size limit")
    return data


def _aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise InvalidPassword("Incorrect password or damaged encrypted wallet") from None


def _decrypt_storage(encoded: bytes, password: str | None) -> bytes:
    if password is None:
        raise PasswordRequired("Enter the password for this encrypted Electrum wallet")
    if len(encoded) < 85 or (len(encoded) - 69) % 16:
        raise WalletError("Damaged encrypted Electrum wallet")
    # Electrum ECPrivkey.from_arbitrary_size_secret reduces this 64-byte value mod n.
    secret = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), b"", 1024)
    scalar = int.from_bytes(secret, "big") % _ORDER
    if not scalar:
        raise InvalidPassword("Incorrect password or damaged encrypted wallet")
    try:
        shared = PublicKey(encoded[4:37]).multiply(scalar.to_bytes(32, "big")).format(compressed=True)
    except ValueError:
        raise WalletError("Damaged encrypted Electrum wallet") from None
    key = hashlib.sha512(shared).digest()
    if not hmac.compare_digest(hmac.new(key[32:], encoded[:-32], hashlib.sha256).digest(), encoded[-32:]):
        raise InvalidPassword("Incorrect password or damaged encrypted wallet")
    compressed = _aes_decrypt(key[16:32], key[:16], encoded[37:-32])
    try:
        decompressor = zlib.decompressobj()
        plaintext = decompressor.decompress(compressed, _MAX_FILE + 1)
        if len(plaintext) > _MAX_FILE or not decompressor.eof or decompressor.unused_data:
            raise WalletError("Encrypted wallet contents are oversized or damaged")
        return plaintext
    except zlib.error:
        raise WalletError("Encrypted wallet contents are damaged") from None


@dataclass(repr=False)
class _Node:
    kind: str
    public: bytes
    chain: bytes
    depth: int = 0
    parent: bytes = b"\0" * 4
    index: int = 0
    secret: bytes | None = None

    @classmethod
    def parse(cls, encoded: str, *, private: bool) -> "_Node":
        raw = _b58decode(encoded)
        if len(raw) != 78:
            raise WalletError("Invalid extended key length")
        kind = next((k for k, headers in _HEADERS.items() if int.from_bytes(raw[:4], "big") == headers[int(private)]), None)
        if kind is None:
            raise UnsupportedWallet("Only mainnet xpub/xprv and zpub/zprv wallet keys are supported")
        if raw[4] == 0 and raw[5:13] != b"\0" * 8:
            raise WalletError("Invalid root extended key metadata")
        secret = None
        try:
            if private:
                if raw[45] != 0:
                    raise ValueError()
                secret = raw[46:]
                public = PrivateKey(secret).public_key.format(compressed=True)
            else:
                if raw[45] not in (2, 3):
                    raise ValueError()
                public = PublicKey(raw[45:]).format(compressed=True)
        except ValueError:
            raise WalletError("Invalid extended key material") from None
        return cls(kind, public, raw[13:45], raw[4], raw[5:9], int.from_bytes(raw[9:13], "big"), secret)

    def xpub(self) -> str:
        return _b58encode(_HEADERS[self.kind][0].to_bytes(4, "big") + bytes([self.depth]) + self.parent + self.index.to_bytes(4, "big") + self.chain + self.public)

    def child(self, index: int, *, private: bool = False) -> "_Node":
        if type(index) is not int or not 0 <= index < 2**32 or self.depth >= 255:
            raise WalletError("Invalid BIP32 derivation path")
        hardened = index >= 2**31
        if private and self.secret is None or hardened and (not private or self.secret is None):
            raise WalletError("This derivation requires a private key")
        data = b"\0" + self.secret if hardened else self.public
        digest = hmac.new(self.chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
        # Fail closed on the astronomically rare invalid child, preserving exact
        # branch/index meanings instead of silently relabelling the next child.
        if int.from_bytes(digest[:32], "big") >= _ORDER:
            raise WalletError("Invalid BIP32 child; this wallet needs manual recovery")
        try:
            if private:
                child = PrivateKey(self.secret).add(digest[:32])
                secret = child.secret
                public = child.public_key.format(compressed=True)
            else:
                secret = None
                public = PublicKey(self.public).add(digest[:32]).format(compressed=True)
        except ValueError:
            raise WalletError("Invalid BIP32 child; this wallet needs manual recovery") from None
        return _Node(self.kind, public, digest[32:], self.depth + 1, _hash160(self.public)[:4], index, secret)


class Wallet:
    """In-memory wallet with public inventory and selected-key export operations.

    Call close() when finished. Python cannot guarantee erasure of every memory
    copy. No password, mnemonic, original JSON, or filesystem path is retained.
    """

    def __init__(self, node: _Node | None, kind: str, *, imported: list[bytes] | None = None):
        _check_kind(kind)
        self.kind = kind
        self._node = node
        self._imported = imported
        self._closed = False
        self.suggested_per_branch = len(imported) if imported is not None else 200
        self.watch_only = imported is None and (node is None or node.secret is None)
        self.derivation = None
        self.source = "Electrum"

    @classmethod
    def load(cls, path: str | Path, password: str | None = None) -> "Wallet":
        raw = _read(path).strip()
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (ValueError, binascii.Error):
            decoded = b""
        if decoded.startswith(b"BIE2"):
            raise UnsupportedWallet("Hardware-encrypted Electrum wallets are unsupported; use a supported offline software-wallet export")
        if decoded.startswith(b"BIE1"):
            raw = _decrypt_storage(decoded, password)
        data = _json(raw)
        if data.get("wallet_type") != "standard":
            raise UnsupportedWallet("Select a standard single-signature Electrum wallet; imported, multisig and old wallets are unsupported here")
        store = data.get("keystore")
        if not isinstance(store, dict) or store.get("type") != "bip32":
            raise UnsupportedWallet("This Electrum wallet needs a standard BIP32 software keystore")
        public = _Node.parse(store.get("xpub"), private=False)
        if public.depth > 253:
            raise UnsupportedWallet("Wallet key is too deep to derive receiving and change addresses")
        encoded_private = store.get("xprv")
        node = public
        if encoded_private is not None:
            if not isinstance(encoded_private, str):
                raise WalletError("Invalid Electrum private keystore")
            try:
                # Ciphertext is base64 and can legitimately start with xprv/zprv.
                # Only a fully valid Base58Check private key counts as plaintext.
                node = _Node.parse(encoded_private, private=True)
            except WalletError:
                try:
                    ciphertext = base64.b64decode(encoded_private, validate=True)
                except (ValueError, binascii.Error):
                    raise WalletError("Invalid Electrum private key or encrypted keystore") from None
                if len(ciphertext) < 32 or len(ciphertext) % 16:
                    raise WalletError("Invalid Electrum private key or encrypted keystore")
                if password is None:
                    raise PasswordRequired("Enter the password for this Electrum wallet")
                if type(store.get("pw_hash_version", 1)) is not int or store.get("pw_hash_version", 1) != 1:
                    raise UnsupportedWallet("Unsupported Electrum password-hash version")
                try:
                    encoded_private = _aes_decrypt(_sha256d(password.encode("utf-8")), ciphertext[:16], ciphertext[16:]).decode("utf-8")
                    node = _Node.parse(encoded_private, private=True)
                except (ValueError, UnicodeError, binascii.Error):
                    raise InvalidPassword("Incorrect password or damaged encrypted keystore") from None
            if not hmac.compare_digest(node.xpub(), public.xpub()):
                raise WalletError("Private and public wallet keys do not match")
        result = cls(node, public.kind)
        addresses = data.get("addresses", {})
        if not isinstance(addresses, dict):
            raise WalletError("Invalid Electrum address lists")
        counts = [200]
        for branch, label in enumerate(("receiving", "change")):
            stored = addresses.get(label, [])
            if not isinstance(stored, list) or len(stored) > _MAX_ADDRESSES:
                raise WalletError("Invalid or oversized Electrum address list")
            counts.append(min(_MAX_ADDRESSES, len(stored) + 20))
            if stored:
                parent = public.child(branch)
                for index, address in enumerate(stored):
                    if address != _address(parent.child(index).public, public.kind)[0]:
                        raise WalletError("Stored Electrum addresses do not match this wallet's public key")
        result.suggested_per_branch = max(counts)
        return result

    @classmethod
    def from_mnemonic(cls, words: str, passphrase: str, kind: str, account: int = 0) -> "Wallet":
        _check_kind(kind)
        if type(account) is not int or not 0 <= account < 2**31:
            raise WalletError("Account must be an integer from 0 to 2147483647")
        if not isinstance(words, str) or not isinstance(passphrase, str):
            raise WalletError("Recovery words and passphrase must be text")
        words = " ".join(unicodedata.normalize("NFKD", words).split())
        # No auto-detection of Electrum seeds: only checksum-valid English BIP39.
        if not Mnemonic("english").check(words):
            raise WalletError("Recovery phrase is not checksum-valid English BIP39 (12, 15, 18, 21 or 24 words)")
        seed = Mnemonic.to_seed(words, passphrase)
        digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        try:
            public = PrivateKey(digest[:32]).public_key.format(compressed=True)
        except ValueError:
            raise WalletError("Invalid BIP32 root key") from None
        node = _Node(kind, public, digest[32:], secret=digest[:32])
        purpose = 84 if kind == "segwit" else 44
        for item in (purpose, 0, account):
            node = node.child(2**31 + item, private=True)
        result = cls(node, kind)
        result.derivation = f"m/{purpose}'/0'/{account}'"
        result.source = "BIP39"
        return result

    @classmethod
    def from_wif_file(cls, path: str | Path, kind: str) -> "Wallet":
        _check_kind(kind)
        try:
            lines = _read(path).decode("utf-8-sig").splitlines()
        except UnicodeError:
            raise WalletError("Select a text export containing compressed WIF private keys") from None
        secrets = {}
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split("#", 1)[0].split()
            token = tokens[0]
            if ":" in token:
                prefix, token = token.split(":", 1)
                expected = "p2wpkh" if kind == "segwit" else "p2pkh"
                if prefix != expected:
                    raise UnsupportedWallet(f"Private-key type on line {line_number} does not match the selected input type")
            # Core dumpwallet rows begin WIF timestamp key=value... . Reject
            # arbitrary extra words, especially mnemonic/seed/JSON input.
            if len(tokens) > 1:
                import datetime
                try:
                    datetime.datetime.strptime(tokens[1], "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    raise WalletError(f"Unrecognized private-key export row on line {line_number}") from None
                if any("=" not in entry for entry in tokens[2:]):
                    raise WalletError(f"Unrecognized private-key export row on line {line_number}")
            try:
                payload = _b58decode(token)
                if len(payload) != 34 or payload[0] != 128 or payload[-1] != 1:
                    raise WalletError("Compressed mainnet WIF required")
                secret = payload[1:-1]
                public = PrivateKey(secret).public_key.format(compressed=True)
            except ValueError:
                raise WalletError(f"Invalid compressed mainnet WIF on line {line_number}") from None
            secrets[public] = secret
            if len(secrets) > _MAX_ADDRESSES:
                raise WalletError("Private-key export exceeds the 100000-key limit")
        if not secrets:
            raise WalletError("No compressed WIF private keys found in this text file")
        result = cls(None, kind, imported=[secrets[public] for public in sorted(secrets)])
        result.source = "WIF export"
        return result

    def _check_open(self) -> None:
        if self._closed:
            raise WalletError("Wallet is closed; open it again to continue")

    @property
    def first_address(self) -> str:
        self._check_open()
        return self._row(0, 0)["address"]

    @property
    def zpub(self) -> str:
        self._check_open()
        if self._imported is not None:
            public = b"".join(PrivateKey(secret).public_key.format(compressed=True) for secret in self._imported)
            return "imported:" + hashlib.sha256(public).hexdigest()
        return self._node.xpub()

    def _row(self, branch: int, index: int) -> dict:
        if type(branch) is not int or branch not in (0, 1) or type(index) is not int or not 0 <= index < 2**31:
            raise WalletError("Invalid public derivation suffix")
        if self._imported is not None:
            if branch != 0 or index >= len(self._imported):
                raise WalletError("Public inventory references an unknown imported key")
            public = PrivateKey(self._imported[index]).public_key.format(compressed=True)
        else:
            public = self._node.child(branch).child(index).public
        address, script = _address(public, self.kind)
        return dict(branch=branch, index=index, address=address, script_pubkey=script)

    def inventory(self, per_branch: int) -> dict:
        self._check_open()
        if type(per_branch) is not int or not 1 <= per_branch <= _MAX_ADDRESSES:
            raise WalletError("Choose an address count from 1 to 100000 per branch")
        if self._imported is not None:
            rows = [self._row(0, i) for i in range(len(self._imported))]
            per_branch = len(rows)
        else:
            rows = []
            for branch in (0, 1):
                parent = self._node.child(branch)
                for index in range(per_branch):
                    address, script = _address(parent.child(index).public, self.kind)
                    rows.append(dict(branch=branch, index=index, address=address, script_pubkey=script))
        return dict(format="electrum-public-inventory/v1", zpub=self.zpub, per_branch=per_branch, addresses=rows)

    def keys_for_manifest(self, manifest_path: str | Path, inventory_path: str | Path) -> list[str]:
        self._check_open()
        if self.watch_only:
            raise UnsupportedWallet("This wallet is watch-only; select the matching offline wallet with private keys")
        manifest = _json(_read(manifest_path))
        inventory = _json(_read(inventory_path))
        if inventory.get("format") != "electrum-public-inventory/v1" or inventory.get("zpub") != self.zpub:
            raise WalletError("Public inventory does not belong to this wallet")
        expected_format, expected_profile = _PROFILES[self.kind]
        if manifest.get("format") != expected_format or manifest.get("signing_profile") != expected_profile:
            raise WalletError("Wrong signing manifest format or profile")
        utxos = manifest.get("utxos")
        if not isinstance(utxos, list) or not utxos:
            raise WalletError("No manifest inputs selected")
        wanted = set()
        for utxo in utxos:
            if not isinstance(utxo, dict) or not isinstance(utxo.get("script_pubkey"), str):
                raise WalletError("Invalid manifest input script")
            wanted.add(utxo["script_pubkey"])
        rows = inventory.get("addresses")
        if not isinstance(rows, list) or not rows or len(rows) > 2 * _MAX_ADDRESSES:
            raise WalletError("Invalid public inventory address list")
        selected = {}
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("script_pubkey"), str):
                raise WalletError("Invalid public inventory entry")
            script = row["script_pubkey"]
            if script in seen:
                raise WalletError("Duplicate public inventory entry")
            seen.add(script)
            if script not in wanted:
                continue
            derived = self._row(row.get("branch"), row.get("index"))
            if derived != row:
                raise WalletError("Public inventory address does not match this wallet")
            selected[script] = derived
        if set(selected) != wanted:
            raise WalletError("Manifest includes an address outside this inventory; extend the public address range")
        result = []
        for row in selected.values():
            if self._imported is not None:
                secret = self._imported[row["index"]]
            else:
                secret = self._node.child(row["branch"], private=True).child(row["index"], private=True).secret
            public = PrivateKey(secret).public_key.format(compressed=True)
            if _address(public, self.kind) != (row["address"], row["script_pubkey"]):
                raise WalletError("Private-key/address verification failed")
            result.append(_b58encode(b"\x80" + secret + b"\x01"))
        return result

    def close(self) -> None:
        """Release references to secrets; do not claim guaranteed memory erasure."""
        if self._node is not None:
            self._node.secret = None
        if self._imported is not None:
            self._imported.clear()
        self._node = None
        self._imported = None
        self._closed = True
