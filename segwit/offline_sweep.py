#!/usr/bin/env python3
"""Offline, one-output P2WPKH sweep builder. No networking or broadcasting.

Review prototype for the pinned Knots unified-sighash fork profile.
Native P2WPKH, ECDSA, SIGHASH_ALL | SIGHASH_UNIFIED (0x21) only.
Independent batches, one P2WPKH or mainnet P2PKH destination output each. Read README.md for the
source pin, activation requirements and actual verification status.

Only signing requires the locally installed `cryptography` package. No automatic
installation, HTTP client, RPC client, subprocess, telemetry, or wallet syncing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any

MAX_MONEY = 21_000_000 * 100_000_000
CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MAX_PARENT_BYTES = 4_000_000
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
SEQUENCE = 0xFFFFFFFF
VERSION = 2
LOCKTIME = 0
SIGHASH = 0x21
SOURCE_COMMIT = "8c85b1585dac23f964e2dd32045624de7f02aa58"
SOURCE_RELEASE = "v29.4.1.knots20260508"
ACTIVATION_HEIGHT = 961640
PROFILE = "knots-unified-p2wpkh-0x21/v2"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class SweepError(Exception):
    """A safe, deliberately non-secret error message."""


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def compact(n: int) -> bytes:
    if n < 0:
        raise SweepError("Negative CompactSize value.")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", n)
    raise SweepError("CompactSize value too large.")


def strict_int(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise SweepError(f"{name} must be an integer in the allowed range.")
    return value


def hex_bytes(value: Any, name: str, size: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise SweepError(f"Invalid hexadecimal {name}.")
    if size is not None and len(value) != 2 * size:
        raise SweepError(f"Incorrect length for {name}.")
    return bytes.fromhex(value)


class Reader:
    def __init__(self, raw: bytes):
        self.raw, self.pos = raw, 0

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.raw):
            raise SweepError("Truncated transaction.")
        out = self.raw[self.pos:self.pos + count]
        self.pos += count
        return out

    def number(self) -> int:
        first = self.read(1)[0]
        if first < 253:
            return first
        sizes = {253: 2, 254: 4, 255: 8}
        n = int.from_bytes(self.read(sizes[first]), "little")
        if n < {253: 253, 254: 65536, 255: 4294967296}[first]:
            raise SweepError("Noncanonical CompactSize encoding.")
        return n

    def vector(self) -> bytes:
        return self.read(self.number())


@dataclass(frozen=True)
class ParsedTx:
    txid: str
    stripped: bytes
    inputs: tuple[tuple[str, int], ...]
    outputs: tuple[tuple[int, bytes], ...]
    witnesses: tuple[tuple[bytes, ...], ...]
    coinbase: bool


def parse_transaction(raw: bytes) -> ParsedTx:
    """Structural decoding only; NOT a chain/consensus validator."""
    if len(raw) > MAX_PARENT_BYTES:
        raise SweepError("Transaction exceeds parser size limit.")
    r = Reader(raw)
    version = r.read(4)
    segwit = r.pos < len(raw) and raw[r.pos] == 0
    if segwit and r.read(2) != b"\x00\x01":
        raise SweepError("Unsupported transaction witness flags.")
    count = r.number()
    if not 1 <= count <= 100_000:
        raise SweepError("Invalid transaction input count.")
    stripped_inputs, inputs = [], []
    for _ in range(count):
        start = r.pos
        txid = r.read(32)[::-1].hex()
        vout = int.from_bytes(r.read(4), "little")
        r.vector()
        r.read(4)
        stripped_inputs.append(raw[start:r.pos])
        inputs.append((txid, vout))
    n_outputs = r.number()
    if not 1 <= n_outputs <= 100_000:
        raise SweepError("Invalid transaction output count.")
    stripped_outputs, outputs = [], []
    total = 0
    for _ in range(n_outputs):
        start = r.pos
        amount = int.from_bytes(r.read(8), "little")
        script = r.vector()
        total += amount
        if amount > MAX_MONEY or total > MAX_MONEY:
            raise SweepError("Parent transaction output value is out of range.")
        outputs.append((amount, script))
        stripped_outputs.append(raw[start:r.pos])
    witnesses: list[tuple[bytes, ...]] = []
    if segwit:
        for _ in range(count):
            n_items = r.number()
            if n_items > 100_000:
                raise SweepError("Witness item count exceeds parser limit.")
            witnesses.append(tuple(r.vector() for _ in range(n_items)))
        if not any(witnesses):
            raise SweepError("Superfluous witness serialization.")
    else:
        witnesses = [()] * count
    locktime = r.read(4)
    if r.pos != len(raw):
        raise SweepError("Trailing bytes after transaction.")
    stripped = (version + compact(count) + b"".join(stripped_inputs)
                + compact(n_outputs) + b"".join(stripped_outputs) + locktime)
    return ParsedTx(sha256d(stripped)[::-1].hex(), stripped, tuple(inputs),
                    tuple(outputs), tuple(witnesses),
                    len(inputs) == 1 and inputs[0] == ("00" * 32, 0xFFFFFFFF))


def polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, gen in enumerate(generators):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def convertbits(values: list[int], from_bits: int, to_bits: int, pad: bool) -> bytes:
    acc = bits = 0
    result = bytearray()
    mask = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            raise SweepError("Invalid address encoding.")
        acc = ((acc << from_bits) | value) & ((1 << (from_bits + to_bits - 1)) - 1)
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & mask)
    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & mask)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & mask):
        raise SweepError("Invalid address padding.")
    return bytes(result)


def destination_script(address: str, expected_hrp: str) -> bytes:
    if address.startswith('1'):
        if expected_hrp != 'bc' or not 26 <= len(address) <= 35:
            raise SweepError('Invalid mainnet P2PKH destination.')
        number = 0
        try:
            for char in address:
                number = number * 58 + B58.index(char)
        except ValueError:
            raise SweepError('Invalid Base58 destination.') from None
        decoded = (b'\x00' * (len(address) - len(address.lstrip('1')))
                   + number.to_bytes((number.bit_length() + 7) // 8, 'big'))
        if (len(decoded) != 25 or decoded[0] != 0
                or sha256d(decoded[:-4])[:4] != decoded[-4:]):
            raise SweepError('Invalid P2PKH destination checksum or network.')
        return b'\x76\xa9\x14' + decoded[1:21] + b'\x88\xac'
    if not 8 <= len(address) <= 90 or any(ord(c) < 33 or ord(c) > 126 for c in address):
        raise SweepError("Invalid destination address length/characters.")
    if address.lower() != address and address.upper() != address:
        raise SweepError("Mixed-case destination address.")
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address) or address[:pos] != expected_hrp:
        raise SweepError("Destination address HRP does not match configured profile.")
    try:
        data = [BECH32.index(c) for c in address[pos + 1:]]
    except ValueError:
        raise SweepError("Invalid Bech32 destination.") from None
    expanded = [ord(c) >> 5 for c in expected_hrp] + [0] + [ord(c) & 31 for c in expected_hrp]
    if polymod(expanded + data) != 1:
        raise SweepError("Destination must have a valid original Bech32 checksum.")
    payload = data[:-6]
    if not payload or payload[0] != 0:
        raise SweepError("Only native witness-v0 P2WPKH destinations are supported.")
    program = convertbits(payload[1:], 5, 8, False)
    if len(program) != 20:
        raise SweepError("Destination must be P2WPKH, not P2WSH or Taproot.")
    return b"\x00\x14" + program


def wif_scalar(wif: str, expected_prefix: int) -> int:
    # Never place the WIF, decoded bytes, or a key fragment into an error.
    if not 50 <= len(wif) <= 53:
        raise SweepError("Invalid compressed WIF.")
    n = 0
    try:
        for char in wif:
            n = n * 58 + B58.index(char)
    except ValueError:
        raise SweepError("Invalid compressed WIF.") from None
    raw = b"\x00" * (len(wif) - len(wif.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 38 or sha256d(raw[:-4])[:4] != raw[-4:]:
        raise SweepError("Invalid compressed WIF.")
    payload = raw[:-4]
    if payload[0] != expected_prefix or payload[-1] != 1:
        raise SweepError("WIF prefix/compression does not match configured profile.")
    scalar = int.from_bytes(payload[1:33], "big")
    if not 1 <= scalar < CURVE_N:
        raise SweepError("Invalid private-key range.")
    return scalar


@dataclass
class Key:
    private: Any
    public: bytes


def load_keys(path: Path, prefix: int) -> dict[bytes, Key]:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        raise SweepError("Signing requires cryptography, installed OFFLINE in advance.") from None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise SweepError("Cannot securely open key file.") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SweepError("Key input must be a regular file.")
        if os.name == "posix" and info.st_mode & 0o077:
            raise SweepError("Key file is readable by group/others; set permissions to 0600.")
        raw = handle.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise SweepError("Key file exceeds size limit.")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise SweepError("Key file must be ASCII compressed WIFs, one per line.") from None
    keys: dict[bytes, Key] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        wif = line.strip()
        if not wif or wif.startswith("#"):
            continue
        try:
            scalar = wif_scalar(wif, prefix)
            private = ec.derive_private_key(scalar, ec.SECP256K1())
            public = private.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
            script = b"\x00\x14" + hash160(public)
        except Exception:
            raise SweepError(f"Invalid/unsupported key on line {line_number}; key content suppressed.") from None
        if script in keys:
            raise SweepError(f"Duplicate private key on line {line_number}.")
        keys[script] = Key(private, public)
    if not keys:
        raise SweepError("Key file contains no keys.")
    return keys


@dataclass(frozen=True)
class Coin:
    txid: str
    vout: int
    value: int
    script: bytes

    @property
    def outpoint(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)

    @property
    def label(self) -> str:
        return f"{self.txid}:{self.vout}"


def unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SweepError("Duplicate JSON field.")
        out[key] = value
    return out


def load_manifest(path: Path) -> tuple[list[Coin], dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise SweepError("Manifest exceeds size limit.")
        data = json.loads(raw, object_pairs_hook=unique_json)
    except (OSError, UnicodeError, ValueError):
        raise SweepError("Cannot read/parse manifest JSON.") from None
    if not isinstance(data, dict) or data.get("format") != "offline-p2wpkh-sweep/v2":
        raise SweepError("Unsupported manifest format.")
    if data.get("signing_profile") != PROFILE:
        raise SweepError("Manifest must select the pinned unified signing profile.")
    parents = data.get("transactions")
    rows = data.get("utxos")
    snapshot = data.get("snapshot")
    if not isinstance(parents, dict) or not isinstance(rows, list) or not rows:
        raise SweepError("Manifest needs raw parent transactions and a nonempty UTXO list.")
    if not isinstance(snapshot, dict):
        raise SweepError("Manifest needs public fork snapshot metadata.")
    strict_int(snapshot.get("height"), "snapshot height", 0, 0x7FFFFFFF)
    hex_bytes(snapshot.get("block_hash"), "snapshot block hash", 32)
    parsed: dict[str, ParsedTx] = {}
    for txid, tx_hex in parents.items():
        expected = hex_bytes(txid, "parent txid", 32).hex()
        if not isinstance(tx_hex, str) or len(tx_hex) > MAX_PARENT_BYTES * 2:
            raise SweepError("Invalid/oversized raw parent transaction.")
        parent = parse_transaction(hex_bytes(tx_hex, "raw parent transaction"))
        if parent.txid != expected:
            raise SweepError("Raw parent transaction does not match its txid.")
        if expected in parsed:
            raise SweepError("Duplicate normalized parent txid.")
        parsed[expected] = parent
    sweeps = []
    seen: set[tuple[str, int]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SweepError("UTXO entries must be objects.")
        txid = hex_bytes(row.get("txid"), "UTXO txid", 32).hex()
        vout = strict_int(row.get("vout"), "UTXO vout", 0, 0xFFFFFFFF)
        point = (txid, vout)
        if point in seen:
            raise SweepError("Duplicate UTXO in manifest.")
        seen.add(point)
        if txid not in parsed or vout >= len(parsed[txid].outputs):
            raise SweepError("UTXO lacks its matching raw parent/output.")
        value, script = parsed[txid].outputs[vout]
        if len(script) != 22 or script[:2] != b"\x00\x14":
            raise SweepError("Every selected input must be native P2WPKH.")
        # Human-entered values/scripts, when present, must match raw parent bytes.
        if "value_sats" in row and strict_int(row["value_sats"], "value_sats", 0, MAX_MONEY) != value:
            raise SweepError("Manifest amount disagrees with the raw parent.")
        if "script_pubkey" in row and hex_bytes(row["script_pubkey"], "script_pubkey") != script:
            raise SweepError("Manifest script disagrees with the raw parent.")
        if parsed[txid].coinbase:
            strict_int(row.get("confirmations"), "coinbase confirmations", 101, 0x7FFFFFFF)
            # This number is an attestation only, not a chain proof.
        if row.get("role", "sweep") != "sweep" or "fork_only_evidence" in row:
            raise SweepError("Remove obsolete seed/carry metadata; all inputs are ordinary sweep inputs.")
        sweeps.append(Coin(txid, vout, value, script))
    known_spends = {point for parent in parsed.values() for point in parent.inputs if point != ("00" * 32, 0xFFFFFFFF)}
    if seen & known_spends:
        raise SweepError("A selected UTXO is already spent by a supplied parent transaction.")
    if sum(c.value for c in sweeps) > MAX_MONEY:
        raise SweepError("Input total exceeds the assumed monetary range.")
    # Preserve supplied order; never silently discard small/uneconomic coins.
    return sweeps, {"snapshot": {"height": snapshot["height"],
                                  "block_hash": snapshot["block_hash"].lower()}}


def estimated_weight(n_inputs: int, output_script_size: int = 22) -> int:
    """One output; strict-DER, compressed pubkeys, low-S ECDSA.

    Stripped input: 41 bytes. Witness per input: at most 108 bytes.
    A low-S DER signature is <=71 bytes, plus 1 sighash byte (0x21).
    """
    if n_inputs < 1:
        raise SweepError("A transaction needs at least one input.")
    if output_script_size not in (22, 25):
        raise SweepError('Unsupported destination script size.')
    output_size = 8 + len(compact(output_script_size)) + output_script_size
    stripped_size = 4 + len(compact(n_inputs)) + 41 * n_inputs + 1 + output_size + 4
    return 4 * stripped_size + 2 + 108 * n_inputs


def estimated_vsize(n_inputs: int, output_script_size: int = 22) -> int:
    return (estimated_weight(n_inputs, output_script_size) + 3) // 4


def input_capacity(max_vbytes: int, max_inputs: int, output_script_size: int = 22) -> int:
    # Pinned release's standard transaction weight ceiling is 400,000 WU.
    if not 110 <= max_vbytes <= 100_000 or not 1 <= max_inputs <= 100_000:
        raise SweepError("Invalid batch size settings.")
    n = 1
    if estimated_weight(1, output_script_size) > 4 * max_vbytes:
        raise SweepError('Size limit cannot fit one input and this destination.')
    while n + 1 <= max_inputs and estimated_weight(n + 1, output_script_size) <= 4 * max_vbytes:
        n += 1
    return n


def parse_rate(text: str) -> Fraction:
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise SweepError("Fee rate must be a positive decimal string in sat/vB.") from None
    if not value.is_finite() or value <= 0 or value > 1_000_000 or value.as_tuple().exponent < -8:
        raise SweepError("Invalid fee rate; use a positive decimal with at most eight fractional digits.")
    return Fraction(value)


def fee_for(vsize: int, rate: Fraction) -> int:
    return (vsize * rate.numerator + rate.denominator - 1) // rate.denominator


def serialize_output(value: int, script: bytes) -> bytes:
    if not 0 <= value <= MAX_MONEY:
        raise SweepError("Output value out of range.")
    return struct.pack("<Q", value) + compact(len(script)) + script


def serialize_base(inputs: list[Coin], value: int, script: bytes) -> bytes:
    vin = b"".join(c.outpoint + b"\x00" + struct.pack("<I", SEQUENCE) for c in inputs)
    return (struct.pack("<I", VERSION) + compact(len(inputs)) + vin
            + b"\x01" + serialize_output(value, script) + struct.pack("<I", LOCKTIME))


def unified_all_prefix(version: int, locktime: int, outpoints: bytes, amounts: bytes,
                       scripts: bytes, sequences: bytes, outputs: bytes) -> bytes:
    """Pinned SignatureHashUnified ALL/no-ANYONECANPAY shared message.

    Components are concatenated consensus serializations, without item counts.
    Spent scripts include their CompactSize lengths. Locktime on the wire is
    still four bytes; only this signing message zero-extends it to five.
    """
    if not -0x80000000 <= version <= 0x7FFFFFFF or not 0 <= locktime <= 0xFFFFFFFF:
        raise SweepError("Version/locktime out of range.")
    return (bytes([0, SIGHASH]) + struct.pack("<i", version)
            + locktime.to_bytes(5, "little")
            + b"".join(hashlib.sha256(part).digest()
                       for part in (outpoints, amounts, scripts, sequences, outputs)))


def unified_witness_v0_digest(prefix: bytes, index: int, script_code: bytes) -> bytes:
    """ALL|UNIFIED witness-v0 tail, then the exact UnifiedSighash tagged SHA256."""
    message = (prefix + b"\x01" + struct.pack("<I", index)
               + compact(len(script_code)) + script_code)
    tag = hashlib.sha256(b"UnifiedSighash").digest()
    return hashlib.sha256(tag + tag + message).digest()


def signature_digests(inputs: list[Coin], value: int, destination: bytes) -> list[bytes]:
    if not inputs or any(len(c.script) != 22 or c.script[:2] != b"\x00\x14" for c in inputs):
        raise SweepError("Unified signing requires native P2WPKH inputs.")
    # Cache all five SINGLE-SHA256 aggregates: linear rather than quadratic.
    prefix = unified_all_prefix(
        VERSION, LOCKTIME, b"".join(c.outpoint for c in inputs),
        b"".join(struct.pack("<Q", c.value) for c in inputs),
        b"".join(compact(len(c.script)) + c.script for c in inputs),
        struct.pack("<I", SEQUENCE) * len(inputs), serialize_output(value, destination))
    return [unified_witness_v0_digest(
        prefix, index, b"\x76\xa9\x14" + coin.script[2:] + b"\x88\xac")
        for index, coin in enumerate(inputs)]


def sign_transaction(inputs: list[Coin], value: int, destination: bytes, keys: dict[bytes, Key]) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    witnesses = []
    for coin, digest in zip(inputs, signature_digests(inputs, value, destination)):
        if coin.script not in keys:
            raise SweepError("A required private key is missing; key content suppressed.")
        key = keys[coin.script]
        if b"\x00\x14" + hash160(key.public) != coin.script:
            raise SweepError("Public key does not match input witness program.")
        signature = key.private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature)
        if s > CURVE_N // 2:
            s = CURVE_N - s
        der = utils.encode_dss_signature(r, s)
        if not 1 <= r < CURVE_N or not 1 <= s <= CURVE_N // 2 or len(der) > 71:
            raise SweepError("Signer produced an unexpected ECDSA signature.")
        key.private.public_key().verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        witness_signature = der + bytes([SIGHASH])
        witnesses.append(b"\x02" + compact(len(witness_signature)) + witness_signature
                         + compact(len(key.public)) + key.public)
    base = serialize_base(inputs, value, destination)
    raw = base[:4] + b"\x00\x01" + base[4:-4] + b"".join(witnesses) + base[-4:]
    # Verify the serialized result as well as the individual signatures.
    parsed = parse_transaction(raw)
    if parsed.stripped != base or parsed.outputs != ((value, destination),):
        raise SweepError("Signed serialization failed round-trip validation.")
    for coin, digest, witness in zip(inputs, signature_digests(inputs, value, destination), parsed.witnesses):
        if len(witness) != 2 or witness[0][-1:] != bytes([SIGHASH]) or witness[1] != keys[coin.script].public:
            raise SweepError("Serialized witness does not match the unified signing profile.")
        keys[coin.script].private.public_key().verify(
            witness[0][:-1], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return raw


@dataclass(frozen=True)
class Batch:
    inputs: list[Coin]
    output_value: int
    fee: int
    txid: str
    estimated_vbytes: int


def make_plan(sweeps: list[Coin], destination: bytes,
              cap: int, rate: Fraction, min_output: int, max_tx_fee: int,
              max_total_fee: int) -> list[Batch]:
    if cap < 1 or not sweeps:
        raise SweepError("Input cap and input list must be nonempty.")
    if len({c.label for c in sweeps}) != len(sweeps):
        raise SweepError("Duplicate sweep input.")
    chunks = [sweeps[i:i + cap] for i in range(0, len(sweeps), cap)]
    result: list[Batch] = []
    total_fees = 0
    for inputs in chunks:
        size = estimated_vsize(len(inputs), len(destination))
        fee = fee_for(size, rate)
        total_fees += fee
        if fee > max_tx_fee or total_fees > max_total_fee:
            raise SweepError("Fee ceiling exceeded; no transactions have been written.")
        value = sum(c.value for c in inputs) - fee
        if not min_output <= value <= MAX_MONEY:
            raise SweepError("A batch cannot fund its fee/minimum output; no UTXOs were silently omitted.")
        txid = sha256d(serialize_base(inputs, value, destination))[::-1].hex()
        result.append(Batch(inputs, value, fee, txid, size))
    final_total = sum(b.output_value for b in result)
    if final_total + total_fees != sum(c.value for c in sweeps):
        raise SweepError("Internal value-conservation check failed.")
    return result


def disable_core_dumps() -> None:
    if os.name == "posix":
        os.umask(0o077)
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, ValueError, OSError):
            pass


def write_private(path: Path, data: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def check_reviewed_plan(path: Path, expected: dict[str, Any]) -> None:
    """Bind signing to the exact public plan reviewed locally, before loading keys."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise SweepError("Reviewed plan exceeds size limit.")
        reviewed = json.loads(raw, object_pairs_hook=unique_json)
    except (OSError, UnicodeError, ValueError):
        raise SweepError("Cannot read reviewed plan JSON.") from None
    if (not isinstance(reviewed, dict)
            or reviewed.get("format") != "offline-p2wpkh-sweep-report/v2"
            or reviewed.get("signed") is not False
            or reviewed.get("review_plan") != expected):
        raise SweepError("Current inputs/settings differ from the reviewed unsigned plan; create and review a new plan.")
    # Also reject inconsistent summaries: the human-facing fields must describe
    # the same nested plan, even though only the regenerated plan is signed.
    batches = expected["transactions"]
    summaries = [{
        "batch": index, "txid": batch["txid"], "depends_on": None,
        "input_count": len(batch["inputs"]), "inputs": [c["outpoint"] for c in batch["inputs"]],
        "input_total_sats": sum(c["value_sats"] for c in batch["inputs"]),
        "output_index": 0, "output_value_sats": batch["output_value_sats"],
        "fee_sats": batch["fee_sats"], "estimated_upper_vbytes": batch["estimated_upper_vbytes"],
    } for index, batch in enumerate(batches, 1)]
    consistent = {
        "mode": "independent", "destination": expected["destination"],
        "profile": PROFILE, "source_commit": SOURCE_COMMIT, "sighash_byte": "21",
        "plan_sha256": plan_hash(expected), "effective_max_inputs": expected["effective_max_inputs"],
        "original_input_count": sum(row["input_count"] for row in summaries), "batch_count": len(batches),
        "total_input_sats": sum(row["input_total_sats"] for row in summaries),
        "total_fee_sats": sum(row["fee_sats"] for row in summaries),
        "final_unspent_output_count": len(batches),
        "final_total_output_sats": sum(row["output_value_sats"] for row in summaries),
        "provenance_unverified_by_this_program": {"snapshot": expected["snapshot"]},
        "transactions": summaries,
    }
    rate_text = reviewed.get("fee_rate_requested_sat_per_vb")
    if (any(reviewed.get(field) != value for field, value in consistent.items())
            or not isinstance(rate_text, str) or str(parse_rate(rate_text)) != expected["fee_rate_sat_per_vb"]):
        raise SweepError("Reviewed report summary/checksum is inconsistent; recreate the unsigned plan.")


def plan_hash(plan: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    disable_core_dumps()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", required=True, help="One mainnet P2WPKH or P2PKH output address")
    parser.add_argument("--keys-file", type=Path, help="Local compressed-WIF file; never put keys in arguments")
    parser.add_argument("--mode", choices=["independent"], default="independent")
    parser.add_argument("--fee-rate", required=True, help="Manually chosen sat/vB decimal; no fee lookup")
    parser.add_argument("--max-inputs", type=int, default=1322)
    parser.add_argument("--max-vbytes", type=int, default=90000)
    parser.add_argument("--min-output-sats", type=int, default=1000, help="Local safety floor, not a verified fork dust rule")
    parser.add_argument("--max-tx-fee-sats", type=int, required=True)
    parser.add_argument("--max-total-fee-sats", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True, help="NEW private output directory; never overwritten")
    parser.add_argument("--plan-only", action="store_true", help="No key file needed; writes report only")
    parser.add_argument("--reviewed-plan", type=Path,
                        help="Required when signing: report.json from the reviewed --plan-only run")
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise SweepError("Output directory already exists; choose a new directory.")
        for name, value in (("minimum output", args.min_output_sats), ("maximum transaction fee", args.max_tx_fee_sats),
                            ("maximum total fee", args.max_total_fee_sats)):
            strict_int(value, name, 1, MAX_MONEY)
        destination = destination_script(args.destination, "bc")
        rate = parse_rate(args.fee_rate)
        cap = input_capacity(args.max_vbytes, args.max_inputs, len(destination))
        destination_address = args.destination.lower() if len(destination) == 22 else args.destination
        sweeps, provenance = load_manifest(args.manifest)
        plan = make_plan(sweeps, destination, cap, rate, args.min_output_sats,
                         args.max_tx_fee_sats, args.max_total_fee_sats)
        review_plan = {
            "signing_profile": PROFILE, "source_commit": SOURCE_COMMIT,
            "source_release": SOURCE_RELEASE, "sighash_byte": "21",
            "mode": "independent", "destination": destination_address,
            "destination_script_pubkey": destination.hex(),
            "snapshot": provenance["snapshot"], "fee_rate_sat_per_vb": str(rate),
            "effective_max_inputs": cap, "max_vbytes": args.max_vbytes,
            "min_output_sats": args.min_output_sats,
            "max_tx_fee_sats": args.max_tx_fee_sats, "max_total_fee_sats": args.max_total_fee_sats,
            "transactions": [{
                "txid": batch.txid,
                "unsigned_tx_hex": serialize_base(batch.inputs, batch.output_value, destination).hex(),
                "inputs": [{"outpoint": c.label, "value_sats": c.value,
                            "script_pubkey": c.script.hex()} for c in batch.inputs],
                "output_value_sats": batch.output_value, "fee_sats": batch.fee,
                "estimated_upper_weight": estimated_weight(len(batch.inputs), len(destination)),
                "estimated_upper_vbytes": batch.estimated_vbytes,
            } for batch in plan],
        }
        keys: dict[bytes, Key] = {}
        if not args.plan_only:
            if provenance["snapshot"]["height"] < ACTIVATION_HEIGHT:
                raise SweepError("Signing requires a fork snapshot at/after mainnet unified activation height 961640.")
            if args.keys_file is None or args.reviewed_plan is None:
                raise SweepError("Signing requires --keys-file and --reviewed-plan; planning needs no keys.")
            check_reviewed_plan(args.reviewed_plan, review_plan)
            keys = load_keys(args.keys_file, 128)
            if any(c.script not in keys for c in sweeps):
                raise SweepError("Key file does not cover every source input.")
        files: dict[str, str] = {}
        records = []
        for index, batch in enumerate(plan, 1):
            record: dict[str, Any] = {
                "batch": index, "txid": batch.txid, "depends_on": None,
                "input_count": len(batch.inputs), "inputs": [c.label for c in batch.inputs],
                "input_total_sats": sum(c.value for c in batch.inputs),
                "output_index": 0, "output_value_sats": batch.output_value,
                "fee_sats": batch.fee, "estimated_upper_vbytes": batch.estimated_vbytes,
            }
            if not args.plan_only:
                raw = sign_transaction(batch.inputs, batch.output_value, destination, keys)
                parsed = parse_transaction(raw)
                weight = 3 * len(parsed.stripped) + len(raw)
                size = (weight + 3) // 4
                if parsed.txid != batch.txid or weight > estimated_weight(len(batch.inputs), len(destination)):
                    raise SweepError("Signed transaction violated its plan or signature-size bound.")
                if weight > args.max_vbytes * 4 or weight > 400_000 or batch.fee < fee_for(size, rate):
                    raise SweepError("Final transaction size/fee validation failed.")
                filename = f"tx_{index:04d}.hex"
                files[filename] = raw.hex() + "\n"
                record.update({"file": filename, "wtxid": sha256d(raw)[::-1].hex(),
                               "weight": weight, "actual_vbytes": size,
                               "actual_fee_rate_sat_per_vb": f"{batch.fee / size:.8f}"})
            records.append(record)
        report = {
            "format": "offline-p2wpkh-sweep-report/v2", "signed": not args.plan_only,
            "mode": args.mode, "destination": destination_address,
            "profile": PROFILE, "source_commit": SOURCE_COMMIT, "sighash_byte": "21",
            "review_plan": review_plan,
            "plan_sha256": plan_hash(review_plan),
            "fee_rate_requested_sat_per_vb": args.fee_rate, "effective_max_inputs": cap,
            "original_input_count": len(sweeps), "batch_count": len(plan),
            "total_input_sats": sum(c.value for c in sweeps),
            "total_fee_sats": sum(b.fee for b in plan),
            "final_unspent_output_count": len(plan),
            "final_total_output_sats": sum(b.output_value for b in plan),
            "provenance_unverified_by_this_program": provenance,
            "transactions": records,
        }
        # All planning, signing, and validation complete before any result is saved.
        args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
        for filename, content in files.items():
            write_private(args.out / filename, content)
        write_private(args.out / "report.json", json.dumps(report, indent=2) + "\n")
        print(f"Created {len(plan)} {'unsigned plan entries' if args.plan_only else 'signed transaction files'} in the local output directory.")
        print("No network or broadcast functionality was invoked. Keep signed files private.")
        return 0
    except SweepError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; no key content printed. Inspect output directory for partial files.", file=sys.stderr)
        return 130
    except Exception:
        # Avoid third-party exception text or tracebacks accidentally exposing secrets.
        print("ERROR: local operation failed; exception details suppressed to protect key material. Inspect output directory for partial files.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
