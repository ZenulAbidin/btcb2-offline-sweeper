# Sweeping BTCB2 from legacy addresses

This bundle spends **legacy P2PKH (`1…`) inputs using compressed keys** and `SIGHASH_ALL | SIGHASH_UNIFIED` (`0x21`). Destinations may be P2PKH (`1…`) or native P2WPKH (`bc1q…`). It is a separate legacy-only version: do not mix its files or manifests with the SegWit bundle.

The Electrum helpers support standard deterministic **xpub-based legacy wallets**. They do not support old non-BIP32 Electrum wallets, imported-key wallets, multisig, P2SH, Taproot, mixed input types, or uncompressed keys. The signer itself accepts externally prepared compressed-WIF keys and matching P2PKH manifests.

**These scripts are review prototypes, not audited wallet software. Keep private keys offline.** Prepare Python and `cryptography` before going offline.

## 1. Export public addresses in offline Electrum

Adjust paths for your machine:

```python
exec(open(r'C:\offline\electrum_helpers.py', encoding='utf-8').read())
export_public_inventory(r'C:\offline\public_inventory.json', per_branch=2000)
```

This exports both receiving and change branches. It cannot discover addresses outside the selected range. Only this public inventory goes online.

## 2. Build the manifest online

Place the public inventory, `build_manifest.py` and this bundle's `offline_sweep.py` together:

```sh
python build_manifest.py --inventory public_inventory.json --out fork_data
```

It sends public address/transaction queries to `mempool.guide`, checks the fork checkpoint and unspent outputs, and downloads raw parent transactions. Review exclusions in `fork_data/verification.json`. Transfer `fork_data/manifest.json` offline as `manifest.json`. An address list is not a signing manifest.

## 3. Export selected keys in offline Electrum

With the helper loaded:

```python
export_manifest_keys(r'C:\offline\manifest.json', r'C:\offline\public_inventory.json', r'C:\offline\keys.txt')
```

The password prompt stays local. Keep `keys.txt` offline; it contains one compressed WIF per input key, with Electrum's `p2pkh:` prefix removed.

## 4. Review, then sign offline

Replace `DESTINATION`. Confirm that any exchange address is explicitly for BTCB2/BLAKE2b. Fee settings below are examples; check fork-specific fees before choosing them.

```sh
python offline_sweep.py --manifest manifest.json --destination DESTINATION --fee-rate 1 --max-tx-fee-sats 100000 --max-total-fee-sats 500000 --plan-only --out plan_review
```

Check every input, the exact destination, amount and fees in `plan_review/report.json`. Then use identical settings:

```sh
python offline_sweep.py --manifest manifest.json --keys-file keys.txt --destination DESTINATION --fee-rate 1 --max-tx-fee-sats 100000 --max-total-fee-sats 500000 --reviewed-plan plan_review/report.json --out signed_review
```

Both output directories must be new. **The unsigned plan's `txid` is null intentionally:** legacy signatures change transaction IDs. The final ID appears in the signed report. A compressed-key one-input spend is conservatively 192 vbytes to P2PKH or 189 vbytes to native P2WPKH.

## 5. Check and broadcast on the fork

Transfer only the signed `tx_*.hex` files and public reports online. Decode/check them and test with a fork node before broadcasting. Correct unified signatures cannot replay onto BTC; checking a `21` label alone does not prove correct signing. Wait for the exchange's required confirmations.

Keep the original wallet and seed backup: they may still control BTC. A second spend after consolidation requires a new manifest and the consolidation address's key. This legacy signer cannot spend a consolidation output sent to a SegWit address; use the SegWit bundle for that second input.

## Verification

Five local test groups passed: 17 published legacy ALL|UNIFIED vectors; independent synthetic signature verification and BTC rejection across all 256 sighash-byte values; size/fee checks through 600 inputs; manifest/helper checks; and plan-to-sign handling of the final transaction ID. Tests used public synthetic keys only. Electrum integration was simulated, not tested with a real wallet GUI. No C++ interpreter/full-node validation was performed for this new legacy version.

Run `python -m unittest -v test_legacy` to repeat the bundled tests. Vectors: [pinned Knots release](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/test/data/unified_sighash.json). Algorithm: [unified sighash specification](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/doc/unified-sighash.md). Upstream fixture license is included.
