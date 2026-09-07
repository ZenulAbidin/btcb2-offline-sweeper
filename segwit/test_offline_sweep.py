#!/usr/bin/env python3
"""Offline regressions. All keys/coins are public synthetic test data; never fund.

Run: python -m unittest -v test_offline_sweep.py
The production digest helpers are checked against all eight applicable upstream
ALL|UNIFIED witness-v0 vectors. The independent decoder, reference digests and
ECDSA checks then assess actual serialized production signatures. No node or
consensus interpreter is invoked by this Python suite.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import offline_sweep as sweep

# Process-global tripwire; it records and rejects networking/process attempts.
# This supplements external network isolation; it is not an OS sandbox.
FORBIDDEN_EVENTS: list[str] = []


def reject_network_and_process(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.posix_spawn")) or event in ("os.system", "pty.spawn"):
        FORBIDDEN_EVENTS.append(event)
        raise RuntimeError("Network/process action forbidden during offline tests")


sys.addaudithook(reject_network_and_process)


def tearDownModule():
    if FORBIDDEN_EVENTS:
        raise AssertionError("Network/process audit events occurred: " + ", ".join(FORBIDDEN_EVENTS))


def h(data):
    return hashlib.sha256(data).digest()


def hh(data):
    return h(h(data))


def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def vec(data):
    return cs(len(data)) + data


def encoded_output(value, script):
    return value.to_bytes(8, "little") + vec(script)


def decode(raw):
    """Independent wire decoder used for output/size/digest interoperability."""
    offset = 0

    def take(n):
        nonlocal offset
        data = raw[offset:offset+n]
        if len(data) != n:
            raise AssertionError("Truncated synthetic transaction")
        offset += n
        return data

    def number():
        n = take(1)[0]
        return n if n < 253 else int.from_bytes(take({253: 2, 254: 4, 255: 8}[n]), "little")

    version = take(4)
    witness = raw[offset:offset+2] == b"\x00\x01"
    if witness:
        take(2)
    count = number()
    inputs = []
    for _ in range(count):
        outpoint = take(36)
        script = take(number())
        sequence = take(4)
        inputs.append((outpoint, script, sequence))
    outputs = [(int.from_bytes(take(8), "little"), take(number())) for _ in range(number())]
    witnesses = [[take(number()) for _ in range(number())] for _ in range(count)] if witness else [[] for _ in range(count)]
    locktime = take(4)
    if offset != len(raw):
        raise AssertionError("Trailing synthetic transaction bytes")
    stripped = (version + cs(count) + b"".join(p + vec(s) + q for p, s, q in inputs)
                + cs(len(outputs)) + b"".join(encoded_output(*o) for o in outputs) + locktime)
    return dict(version=version, inputs=inputs, outputs=outputs, witnesses=witnesses,
                locktime=locktime, stripped=stripped)


def script_code(script):
    assert len(script) == 22 and script[:2] == b"\x00\x14"
    return b"\x76\xa9\x14" + script[2:] + b"\x88\xac"


def reference_unified(tx, spent, index, *, hash_type=0x21, code=None):
    """Separate raw-transaction implementation of this profile only."""
    outpoints = b"".join(v[0] for v in tx["inputs"])
    amounts = b"".join(value.to_bytes(8, "little") for value, _ in spent)
    scripts = b"".join(vec(script) for _, script in spent)
    sequences = b"".join(v[2] for v in tx["inputs"])
    outputs = b"".join(encoded_output(*out) for out in tx["outputs"])
    code = script_code(spent[index][1]) if code is None else code
    message = (bytes([0, hash_type]) + tx["version"] + tx["locktime"] + b"\x00"
               + h(outpoints) + h(amounts) + h(scripts) + h(sequences) + h(outputs)
               + b"\x01" + index.to_bytes(4, "little") + vec(code))
    tag = h(b"UnifiedSighash")
    return h(tag + tag + message)


def reference_bip143(tx, spent, index, hash_type):
    """BTC witness-v0 digest including undefined hash-type treatment.

    This intentionally permits every appended byte, without STRICTENC, so
    rejection demonstrates a cryptographic difference rather than relay policy.
    """
    base_type = hash_type & 0x1F
    anyone_can_pay = bool(hash_type & 0x80)
    zero = bytes(32)
    prevouts = zero if anyone_can_pay else hh(b"".join(v[0] for v in tx["inputs"]))
    sequences = zero if anyone_can_pay or base_type in (2, 3) else hh(b"".join(v[2] for v in tx["inputs"]))
    if base_type not in (2, 3):
        outputs = hh(b"".join(encoded_output(*out) for out in tx["outputs"]))
    elif base_type == 3 and index < len(tx["outputs"]):
        outputs = hh(encoded_output(*tx["outputs"][index]))
    else:
        outputs = zero
    outpoint, _, sequence = tx["inputs"][index]
    amount, script = spent[index]
    return hh(tx["version"] + prevouts + sequences + outpoint + vec(script_code(script))
              + amount.to_bytes(8, "little") + sequence + outputs + tx["locktime"]
              + hash_type.to_bytes(4, "little"))


def synthetic_key(scalar):
    private = ec.derive_private_key(scalar, ec.SECP256K1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    script = b"\x00\x14" + hashlib.new("ripemd160", h(public)).digest()
    return script, sweep.Key(private, public)


def public_fixture():
    # Scalar constants 1, 2, 3 are public test values, deliberately not secrets.
    s1, k1 = synthetic_key(1)
    s2, k2 = synthetic_key(2)
    destination, _ = synthetic_key(3)
    coins = [sweep.Coin("11" * 32, 1, 210000, s1),
             sweep.Coin("22" * 32, 0, 310000, s1),
             sweep.Coin("33" * 32, 2, 410000, s2)]
    return coins, destination, {s1: k1, s2: k2}


def verify(public, signature, digest):
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public).verify(
        signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


class UpstreamVectorTests(unittest.TestCase):
    def test_all_eight_published_all_unified_witness_v0_vectors(self):
        fixture = Path(__file__).parent / "fixtures" / "unified_sighash.json"
        records = json.loads(fixture.read_text())
        relevant = [(i, row) for i, row in enumerate(records[1:], 1) if row[3:5] == [33, 1]]
        self.assertEqual(len(relevant), 8)
        for row_number, (code_hex, raw_hex, index, _, _, spent, expected) in relevant:
            with self.subTest(upstream_row=row_number):
                tx = decode(bytes.fromhex(raw_hex))
                prefix = sweep.unified_all_prefix(
                    int.from_bytes(tx["version"], "little", signed=True),
                    int.from_bytes(tx["locktime"], "little"),
                    b"".join(v[0] for v in tx["inputs"]),
                    b"".join(value.to_bytes(8, "little") for value, _ in spent),
                    b"".join(vec(bytes.fromhex(script)) for _, script in spent),
                    b"".join(v[2] for v in tx["inputs"]),
                    b"".join(encoded_output(*out) for out in tx["outputs"]))
                got = sweep.unified_witness_v0_digest(prefix, index, bytes.fromhex(code_hex))
                # Upstream explicitly stores raw hash bytes, not uint256::GetHex().
                self.assertEqual(got.hex(), expected)


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coins, cls.destination, cls.keys = public_fixture()
        cls.value = sum(c.value for c in cls.coins) - 1000
        cls.raw = sweep.sign_transaction(cls.coins, cls.value, cls.destination, cls.keys)
        cls.tx = decode(cls.raw)
        cls.spent = [(c.value, c.script) for c in cls.coins]

    def test_serialized_signatures_are_unified_canonical_low_s_and_compressed(self):
        self.assertEqual(self.tx["outputs"], [(self.value, self.destination)])
        self.assertEqual(len(self.tx["inputs"]), 3)
        self.assertEqual(self.tx["version"], (2).to_bytes(4, "little"))
        self.assertEqual(self.tx["locktime"], bytes(4))
        self.assertEqual(self.tx["witnesses"][0][1], self.tx["witnesses"][1][1])
        digests = sweep.signature_digests(self.coins, self.value, self.destination)
        for i, witness in enumerate(self.tx["witnesses"]):
            with self.subTest(input=i):
                self.assertEqual(len(witness), 2)
                item, public = witness
                self.assertEqual(item[-1], 0x21)
                self.assertEqual(len(public), 33)
                self.assertIn(public[0], (2, 3))
                self.assertLessEqual(len(item), 72)
                r, s = utils.decode_dss_signature(item[:-1])
                self.assertEqual(utils.encode_dss_signature(r, s), item[:-1])
                self.assertGreaterEqual(s, 1)
                self.assertLessEqual(s, sweep.CURVE_N // 2)
                independent_digest = reference_unified(self.tx, self.spent, i)
                self.assertEqual(digests[i], independent_digest)
                verify(public, item[:-1], independent_digest)
        self.assertEqual(self.tx["stripped"], sweep.serialize_base(self.coins, self.value, self.destination))

    def test_btc_bip143_rejects_all_256_byte_values_for_each_signature(self):
        rejected = 0
        for i, (item, public) in enumerate(self.tx["witnesses"]):
            for hash_type in range(256):
                with self.subTest(input=i, hash_type=hash_type):
                    with self.assertRaises(InvalidSignature):
                        verify(public, item[:-1], reference_bip143(self.tx, self.spent, i, hash_type))
                    rejected += 1
        self.assertEqual(rejected, 768)

    def test_bip143_positive_controls_verify_and_fail_unified(self):
        for i, coin in enumerate(self.coins):
            with self.subTest(input=i):
                digest = reference_bip143(self.tx, self.spent, i, 1)
                signature = self.keys[coin.script].private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                verify(self.keys[coin.script].public, signature, digest)
                with self.assertRaises(InvalidSignature):
                    verify(self.keys[coin.script].public, signature, reference_unified(self.tx, self.spent, i))

    def test_committed_field_mutations_reject_33_signatures(self):
        rejected = 0
        for i, (item, public) in enumerate(self.tx["witnesses"]):
            j = (i + 1) % len(self.spent)
            changed = []
            tx = copy.deepcopy(self.tx); tx["version"] = (3).to_bytes(4, "little")
            changed.append(("version", tx, self.spent, {}))
            tx = copy.deepcopy(self.tx); tx["locktime"] = (1).to_bytes(4, "little")
            changed.append(("locktime", tx, self.spent, {}))
            tx = copy.deepcopy(self.tx); point, script, sequence = tx["inputs"][j]
            tx["inputs"][j] = (bytes([point[0] ^ 1]) + point[1:], script, sequence)
            changed.append(("other outpoint", tx, self.spent, {}))
            tx = copy.deepcopy(self.tx); point, script, sequence = tx["inputs"][j]
            tx["inputs"][j] = (point, script, b"\xfe\xff\xff\xff")
            changed.append(("other sequence", tx, self.spent, {}))
            spent = self.spent.copy(); spent[j] = (spent[j][0] + 1, spent[j][1])
            changed.append(("other amount", self.tx, spent, {}))
            spent = self.spent.copy(); spent[j] = (spent[j][0], spent[j][1][:-1] + bytes([spent[j][1][-1] ^ 1]))
            changed.append(("other scriptPubKey", self.tx, spent, {}))
            tx = copy.deepcopy(self.tx); tx["outputs"][0] = (self.value - 1, self.destination)
            changed.append(("output amount", tx, self.spent, {}))
            tx = copy.deepcopy(self.tx); tx["outputs"][0] = (self.value, self.destination[:-1] + bytes([self.destination[-1] ^ 1]))
            changed.append(("output destination", tx, self.spent, {}))
            tx = copy.deepcopy(self.tx); tx["inputs"].reverse()
            changed.append(("input order", tx, self.spent, {}))
            changed.append(("scriptCode", self.tx, self.spent, {"code": self.spent[i][1]}))
            changed.append(("sighash byte", self.tx, self.spent, {"hash_type": 1}))
            for name, tx, spent, kwargs in changed:
                with self.subTest(input=i, field=name):
                    with self.assertRaises(InvalidSignature):
                        verify(public, item[:-1], reference_unified(tx, spent, i, **kwargs))
                    rejected += 1
        self.assertEqual(rejected, 33)

    def test_missing_or_mismatched_keys_and_wrong_script_type_rejected(self):
        with self.assertRaises(sweep.SweepError):
            sweep.sign_transaction(self.coins, self.value, self.destination, {})
        wrong = self.keys.copy()
        wrong[self.coins[0].script] = self.keys[self.coins[-1].script]
        with self.assertRaises(sweep.SweepError):
            sweep.sign_transaction(self.coins, self.value, self.destination, wrong)
        malformed = [replace(self.coins[0], script=b"\x51\x20" + bytes(32))]
        with self.assertRaises(sweep.SweepError):
            sweep.signature_digests(malformed, self.value, self.destination)

    def test_signed_1469_input_transaction_stays_below_standard_weight(self):
        coin = self.coins[0]
        coins = [replace(coin, txid=f"{i + 1:064x}", vout=0, value=10000) for i in range(1469)]
        plan = sweep.make_plan(coins, self.destination, 1469, Fraction(5, 4), 1000, 200000, 200000)
        self.assertEqual(len(plan), 1)
        batch = plan[0]
        raw = sweep.sign_transaction(batch.inputs, batch.output_value, self.destination, self.keys)
        parsed = decode(raw)
        weight = len(parsed["stripped"]) * 3 + len(raw)
        self.assertLessEqual(weight, 399742)
        self.assertLess(weight, 400000)
        self.assertEqual(len(parsed["inputs"]), 1469)
        self.assertEqual(len(parsed["outputs"]), 1)
        self.assertTrue(all(len(w) == 2 and w[0][-1] == 0x21 for w in parsed["witnesses"]))
        self.assertEqual(batch.txid, hh(parsed["stripped"])[::-1].hex())
        self.assertGreaterEqual(Fraction(batch.fee, (weight + 3) // 4), Fraction(5, 4))
        spent = [(c.value, c.script) for c in coins]
        for index in (0, 252, 253, 1468):
            sig, public = parsed["witnesses"][index]
            verify(public, sig[:-1], reference_unified(parsed, spent, index))


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.coins, self.destination, self.keys = public_fixture()

    def test_weight_bound_compactsize_boundaries_and_exact_capacities(self):
        self.assertEqual(sweep.estimated_weight(1), 438)
        self.assertEqual(sweep.estimated_weight(252), 68710)
        self.assertEqual(sweep.estimated_weight(253), 68990)
        self.assertEqual(sweep.input_capacity(90000, 100000), 1322)
        self.assertEqual(sweep.input_capacity(100000, 100000), 1469)
        self.assertEqual(sweep.estimated_weight(1322), 359758)
        self.assertEqual(sweep.estimated_vsize(1322), 89940)
        self.assertEqual(sweep.estimated_weight(1469), 399742)
        self.assertEqual(sweep.estimated_vsize(1469), 99936)
        self.assertGreater(sweep.estimated_weight(1323), 360000)
        self.assertGreater(sweep.estimated_weight(1470), 400000)
        self.assertEqual(sweep.input_capacity(90000, 700), 700)

    def test_independent_batches_one_output_exact_value_and_manual_rate(self):
        plan = sweep.make_plan(self.coins, self.destination, 2, sweep.parse_rate("1.25"), 1000, 1000, 2000)
        self.assertEqual([len(b.inputs) for b in plan], [2, 1])
        self.assertNotIn(self.destination, self.keys)
        self.assertEqual([c.label for b in plan for c in b.inputs], [c.label for c in self.coins])
        txids = {b.txid for b in plan}
        self.assertFalse(any(c.txid in txids for b in plan for c in b.inputs))
        for batch in plan:
            raw = sweep.sign_transaction(batch.inputs, batch.output_value, self.destination, self.keys)
            tx = decode(raw)
            self.assertEqual(tx["outputs"], [(batch.output_value, self.destination)])
            self.assertEqual(batch.fee, (batch.estimated_vbytes * 5 + 3) // 4)
            self.assertEqual(sum(c.value for c in batch.inputs), batch.output_value + batch.fee)
        self.assertEqual(sum(b.output_value + b.fee for b in plan), sum(c.value for c in self.coins))

    def test_fees_fail_closed_and_never_silently_drop_small_inputs(self):
        args = [self.coins, self.destination, 2, Fraction(5, 4), 1000]
        for tx_fee, total_fee in ((1, 10000), (10000, 1)):
            with self.subTest(tx_fee=tx_fee, total_fee=total_fee):
                with self.assertRaises(sweep.SweepError):
                    sweep.make_plan(*args, tx_fee, total_fee)
        with self.assertRaises(sweep.SweepError):
            sweep.make_plan([replace(self.coins[0], value=1)], self.destination, 1, Fraction(1), 1000, 1000, 1000)
        with self.assertRaises(sweep.SweepError):
            sweep.make_plan([self.coins[0], self.coins[0]], self.destination, 2, Fraction(1), 1000, 1000, 1000)

    def test_fractional_rate_rounds_up_and_invalid_rates_rejected(self):
        self.assertEqual(sweep.parse_rate("1.25"), Fraction(5, 4))
        self.assertEqual(sweep.fee_for(110, sweep.parse_rate("1.25")), 138)
        self.assertEqual(sweep.fee_for(110, sweep.parse_rate("0.00000001")), 1)
        for rate in ("0", "-1", "NaN", "Infinity", "1000001", "0.000000001", "bad"):
            with self.subTest(rate=rate):
                with self.assertRaises(sweep.SweepError):
                    sweep.parse_rate(rate)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        coins, self.destination, _ = public_fixture()
        self.scripts = [c.script for c in coins]
        self.outputs = [(c.value, c.script) for c in coins]
        parent = ((2).to_bytes(4, "little") + b"\x01" + bytes.fromhex("77" * 32)
                  + bytes(4) + b"\x00" + b"\xff" * 4 + cs(len(self.outputs))
                  + b"".join(encoded_output(*o) for o in self.outputs) + bytes(4))
        self.parent_id = hh(parent)[::-1].hex()
        self.manifest = {"format": "offline-p2wpkh-sweep/v2", "signing_profile": sweep.PROFILE,
                         "snapshot": {"height": 961640, "block_hash": "88" * 32},
                         "transactions": {self.parent_id: parent.hex()},
                         "utxos": [{"txid": self.parent_id, "vout": i,
                                    "value_sats": value, "script_pubkey": script.hex()}
                                   for i, (value, script) in enumerate(self.outputs)]}

    def load(self, manifest):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic_manifest.json"
            path.write_text(json.dumps(manifest))
            return sweep.load_manifest(path)

    def test_raw_parent_is_authoritative_and_same_address_utxos_remain_distinct(self):
        coins, provenance = self.load(self.manifest)
        self.assertEqual(len(coins), 3)
        self.assertEqual(coins[0].script, coins[1].script)
        self.assertNotEqual(coins[0].outpoint, coins[1].outpoint)
        self.assertEqual([(c.value, c.script) for c in coins], self.outputs)
        self.assertEqual(provenance["snapshot"]["height"], 961640)
        for row in self.manifest["utxos"]:
            row.pop("value_sats"); row.pop("script_pubkey")
        self.assertEqual(self.load(self.manifest)[0], coins)

    def test_v1_profile_seed_duplicate_mismatch_and_missing_parent_rejected(self):
        cases = []
        data = copy.deepcopy(self.manifest); data["format"] = "offline-p2wpkh-sweep/v1"; cases.append(("v1", data))
        data = copy.deepcopy(self.manifest); data["signing_profile"] = "bip143"; cases.append(("profile", data))
        data = copy.deepcopy(self.manifest); data["utxos"][0]["role"] = "seed"; cases.append(("seed", data))
        data = copy.deepcopy(self.manifest); data["utxos"].append(data["utxos"][0].copy()); cases.append(("duplicate", data))
        data = copy.deepcopy(self.manifest); data["utxos"][0]["value_sats"] += 1; cases.append(("amount", data))
        data = copy.deepcopy(self.manifest); data["utxos"][0]["script_pubkey"] = self.destination.hex(); cases.append(("script", data))
        data = copy.deepcopy(self.manifest); data["transactions"] = {}; cases.append(("missing parent", data))
        data = copy.deepcopy(self.manifest); data["transactions"][self.parent_id] = data["transactions"][self.parent_id][:-8] + "01000000"; cases.append(("parent mismatch", data))
        for name, data in cases:
            with self.subTest(case=name):
                with self.assertRaises(sweep.SweepError):
                    self.load(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
