"""Synthetic hostile-explorer bounds and bounded concurrent work regressions."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_online import FakeExplorer
from test_service import fixture


class ScanLimitTests(unittest.TestCase):
    def for_each_builder(self, check):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                builder = importlib.import_module(f"{kind}.build_manifest")
                signer, manifest, _, _, inventory = fixture(Path(name), kind)
                check(builder, signer, manifest, inventory)

    def test_oversized_address_response_rejected_before_rows_are_processed(self):
        def check(builder, signer, manifest, inventory):
            client = FakeExplorer(manifest, inventory)
            normal = client.get
            coin = normal("/address/" + inventory["addresses"][0]["address"] + "/utxo")[0]
            def get(path):
                if path.startswith("/address/"):
                    return [coin] * (builder.MAX_SCAN_COINS + 1)
                return normal(path)
            with patch.object(builder, "public_coin", wraps=builder.public_coin) as parse:
                with self.assertRaisesRegex(ValueError, "Too many explorer outputs"):
                    builder.collect(inventory, get, workers=1)
                parse.assert_not_called()
        self.for_each_builder(check)

    def test_total_coin_budget_includes_multiple_addresses_and_exclusions(self):
        def check(builder, signer, manifest, inventory):
            client = FakeExplorer(manifest, inventory)
            normal = client.get
            def get(path):
                result = normal(path)
                if path.startswith("/address/"):
                    result[0]["status"] = {"confirmed": False}
                return result
            with patch.object(builder, "MAX_SCAN_COINS", 1):
                with self.assertRaisesRegex(ValueError, "Too many explorer outputs"):
                    builder.collect(inventory, get, workers=1)
            self.assertFalse(any(path.endswith("/hex") for path in client.gets))
        self.for_each_builder(check)

    def test_aggregate_parent_bytes_are_limited_before_parsing_next_parent(self):
        def check(builder, signer, manifest, inventory):
            first_txid, first_raw = next(iter(manifest["transactions"].items()))
            second_raw = "03000000" + first_raw[8:]
            second_txid = signer.sha256d(bytes.fromhex(second_raw))[::-1].hex()
            manifest["transactions"][second_txid] = second_raw
            manifest["utxos"][1]["txid"] = second_txid
            client = FakeExplorer(manifest, inventory)
            with patch.object(builder, "MAX_PARENT_HEX_CHARS", len(first_raw) + 10), \
                 patch.object(signer, "parse_transaction", wraps=signer.parse_transaction) as parse:
                with self.assertRaisesRegex(ValueError, "Parent data exceeds"):
                    builder.collect(inventory, client.get, workers=1)
                self.assertEqual(parse.call_count, 1)
            self.assertFalse(any(path.endswith("/outspends") for path in client.gets))
        self.for_each_builder(check)

    def test_parent_output_budget_precedes_outspend_queries(self):
        def check(builder, signer, manifest, inventory):
            client = FakeExplorer(manifest, inventory)
            with patch.object(builder, "MAX_PARENT_OUTPUTS", 1):
                with self.assertRaisesRegex(ValueError, "Parent output count"):
                    builder.collect(inventory, client.get, workers=1)
            self.assertFalse(any(path.endswith("/outspends") for path in client.gets))
        self.for_each_builder(check)

    def test_unknown_api_fields_do_not_accumulate_in_saved_evidence(self):
        def check(builder, signer, manifest, inventory):
            client = FakeExplorer(manifest, inventory)
            normal = client.get
            def get(path):
                result = normal(path)
                if path.startswith("/address/"):
                    result[0]["arbitrary"] = "DO NOT RETAIN " * 10000
                    result[0]["status"]["arbitrary"] = "DO NOT RETAIN"
                    if inventory["addresses"][0]["address"] in path:
                        result[0]["status"]["confirmed"] = False
                if path.endswith("/outspends"):
                    result[0]["arbitrary"] = "DO NOT RETAIN " * 10000
                return result
            output, evidence = builder.collect(inventory, get, workers=1)
            self.assertEqual(len(output["utxos"]), 1)
            self.assertEqual(len(evidence["excluded"]), 1)
            self.assertNotIn("DO NOT RETAIN", json.dumps(evidence))
        self.for_each_builder(check)

    def test_first_failed_future_does_not_eagerly_enqueue_the_inventory(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind):
                builder = importlib.import_module(f"{kind}.build_manifest")
                consumed, started = [], []
                def items():
                    for index in range(10000):
                        consumed.append(index)
                        yield index
                def query(index):
                    started.append(index)
                    if index == 0:
                        raise ValueError("first query failed")
                    return index
                with self.assertRaisesRegex(ValueError, "first query failed"):
                    list(builder.bounded_map(query, items(), 3))
                self.assertLessEqual(len(consumed), 3)
                self.assertLessEqual(len(started), 3)

    def test_collect_first_address_failure_does_not_request_entire_inventory(self):
        from btcb2_tui.wallet import Wallet
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind):
                builder = importlib.import_module(f"{kind}.build_manifest")
                wallet = Wallet.from_mnemonic("abandon " * 11 + "about", "", kind)
                try:
                    inventory = wallet.inventory(10)
                finally:
                    wallet.close()
                first = inventory["addresses"][0]["address"]
                requests = []
                all_requested = threading.Event()
                def get(path):
                    if path == "/block-height/961640":
                        return builder.CHECKPOINT
                    if path == "/blocks/tip/hash":
                        return "66" * 32
                    if path == "/block/" + "66" * 32:
                        return {"height": 961641}
                    if path.startswith("/address/"):
                        requests.append(path)
                        if len(requests) == len(inventory["addresses"]):
                            all_requested.set()
                        if path == "/address/" + first + "/utxo":
                            # A slow first request gives an eager scheduler time to
                            # drain its entire queue before the failure surfaces.
                            all_requested.wait(.2)
                            raise ValueError("first address failed")
                        return []
                    raise AssertionError("Unexpected request after the failed scan")
                with self.assertRaisesRegex(ValueError, "first address failed"):
                    builder.collect(inventory, get, workers=3)
                self.assertLessEqual(len(requests), 3)
                self.assertLess(len(requests), len(inventory["addresses"]))

    def test_consumer_error_closes_pending_scan_work(self):
        def check(builder, signer, manifest, inventory):
            client = FakeExplorer(manifest, inventory)
            normal = client.get
            def get(path):
                value = normal(path)
                if path.startswith("/address/") and inventory["addresses"][0]["address"] in path:
                    return value + value
                return value
            with self.assertRaisesRegex(ValueError, "Duplicate outpoint"):
                builder.collect(inventory, get, workers=1)
            self.assertEqual(sum(path.startswith("/address/") for path in client.gets), 1)
        self.for_each_builder(check)

    def test_saved_json_limit_is_enforced(self):
        for kind in ("segwit", "legacy"):
            with self.subTest(kind=kind):
                builder = importlib.import_module(f"{kind}.build_manifest")
                with patch.object(builder, "MAX_JSON_BYTES", 20):
                    with self.assertRaisesRegex(ValueError, "64 MiB safety limit"):
                        builder.bounded_json({"data": "x" * 100})


if __name__ == "__main__":
    unittest.main()
