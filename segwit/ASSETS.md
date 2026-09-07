# Companion files

| File | Use |
|---|---|
| `index.html` | Readable, printable tutorial; open locally in a browser |
| `README.md` | Tutorial source for a forum, repository or blog |
| `assets/workflow.svg` | Diagram of online/offline responsibilities |
| `assets/files.svg` | Diagram explaining the four main file types |
| `electrum_helpers.py` | Offline console functions for public address inventory and selected key export |
| `build_manifest.py` | Online fork-UTXO and raw-parent manifest builder |
| `offline_sweep.py` | Reviewed-prototype unified signer; native P2WPKH inputs, P2WPKH/P2PKH destination |
| `example_manifest.json` | Schema example with invalid placeholders; not usable for signing |
| `test_assets.py` | Synthetic tests for the builder, key export and legacy destination |
| `test_cli.py`, `test_offline_sweep.py` | Signer regressions using public test keys |
| `fixtures/unified_sighash.json` | Published upstream test vectors |
| `UPSTREAM_COPYING` | Upstream license text associated with the fixtures |
| `SHA256SUMS` | Checksums for the packaged assets |

The only external Python dependency needed for the builder/signer tests and actual signing is `cryptography`; prepare it in a trusted environment before going offline. The Electrum helpers use Electrum's own runtime.

To repeat the synthetic tests from this folder:

```sh
python -m unittest discover -v
```

Local result on 7 September 2026: 23 tests ran, 22 passed and one Unix-only permission test was skipped on Windows. No real private keys were accessed. The public-data builder was tested with synthetic API responses; this generic version was not run against another person's wallet. The Electrum helpers' automated tests use a simulated wallet, not a live Electrum GUI. The preceding wallet-specific implementation was used separately; these are not the user's personal files.

The upstream vectors came from [Knots v29.4.1](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/test/data/unified_sighash.json). Passing these tests is not a security audit or independent full-node validation.

Do not bundle your generated public inventory, manifest, key files, signed transactions, or screenshots with this public tutorial.
