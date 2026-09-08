# BTCB2 Sweeper

An interactive Python terminal app for sweeping Bitcoin BIP110 / BLAKE2b (BTCB2) fork outputs with two computers and a USB drive. Menus and file browsers guide you through exporting addresses, finding fork coins, reviewing and signing offline, and broadcasting online.

**[Download the Windows apps](https://github.com/ZenulAbidin/btcb2-offline-sweeper/releases)** · **[Start here: USB walkthrough](docs/QUICKSTART.md)** · **[Wallet compatibility](docs/wallet-compatibility.md)**

| App | Computer | What it does |
|---|---|---|
| `BTCB2-Offline.exe` | Disconnected computer holding the wallet | Opens a supported wallet, exports public addresses, reviews a sweep request, and signs approved transactions. |
| `BTCB2-Online.exe` | Internet-connected computer | Finds BTCB2 outputs from public addresses, prepares a request, reviews signed transactions, and broadcasts only after confirmation. |

Download each app's Windows x64 ZIP from Releases, extract it, and double-click the EXE. Python and Electrum do not need to be installed to run the EXEs. The ZIPs include instructions and third-party license notices.

## Four steps, three USB transfers

1. **Offline:** select a supported wallet source and export its public address inventory to USB.
2. **Online:** open the inventory, scan for BTCB2 coins, and save the returned fork-data folder to USB.
3. **Offline:** open its manifest, enter the destination and fee, review the complete plan, then approve signing and export the signed folder to USB.
4. **Online:** open the signed folder, review it again, and explicitly confirm broadcasting to BTCB2.

The apps can be closed between steps. Keep wallet files, recovery phrases, passwords and private-key exports on the offline computer. Transfer only the public inventory, fork-data folder and signed folder. Those public files still reveal wallet activity.

## Wallets and supported coins

Native Electrum standard BIP32 wallet files are supported, including password-protected files. Other wallets can use supported **BIP39 recovery phrases** with a BIP44 legacy or BIP84 native SegWit account, or a compressed WIF private-key export. This covers compatible software-wallet configurations from Sparrow, BlueWallet, BitPay and Mycelium; it does not mean their native backup files are interchangeable. Bitcoin Core support is through a legacy `dumpwallet` text export, not direct `wallet.dat` access.

Inputs and destinations must be mainnet P2PKH (`1…`) or native P2WPKH (`bc1q…`, a 20-byte witness program). Each sweep spends one input type. P2SH / BIP49 (`3…`), multisig, Taproot (`bc1p…`), Lightning, hardware-wallet signing, descriptor-wallet files, and uncompressed private keys are unsupported. See the [compatibility guide](docs/wallet-compatibility.md) before entering a recovery phrase.

## Status and trust

**v0.1.0 is a prerelease.** An internal security review and cross-review by separate AI agents were completed; [read the findings and verification record](docs/AUDIT.md). This is not an independent external security audit or full-node consensus validation. The interface uses the existing review-prototype signers with `SIGHASH_ALL | SIGHASH_UNIFIED` (`0x21`). Automated tests cover synthetic wallets, digest vectors, transaction serialization, validation and USB workflows. [Read the security model and limitations](docs/SECURITY.md).

The default online explorer is `mempool.guide`; compatible HTTPS Esplora endpoints can be selected in the app. A fork checkpoint check rejects a known incompatible chain, but an explorer is still a trusted data source. Ensure the receiving wallet or service explicitly supports BTCB2 / BLAKE2b. Current BTC unspentness does not establish current fork unspentness.

## Run from Python or build your own EXEs

For source users, install a maintained Python version (3.13.15 recommended; the code supports 3.12+) and run:

```sh
python -m pip install -r requirements.txt
python launch_offline.py
python launch_online.py
```

Run only the relevant app on each computer. Install dependencies before disconnecting the offline computer.

```sh
python scripts/run_tests.py
```

Windows build instructions, dependency hashes, binary smoke checks and GitHub release automation are documented in [docs/BUILDING.md](docs/BUILDING.md).

## Original command-line tools

The existing [SegWit guide](segwit/README.md), [legacy guide](legacy/README.md), and [downloadable script bundles](bundles/) remain available for advanced use. Do not mix their manifests between input types. An address inventory is not a signing manifest; spending a later consolidation output needs a fresh manifest and its corresponding key.

## References

- [Pinned Knots unified-sighash specification](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/doc/unified-sighash.md)
- [Upstream test vectors](https://github.com/bitcoinknots/bitcoin/blob/v29.4.1.knots20260508/src/test/data/unified_sighash.json)
- [Fork developer documentation](https://bitcoin-blake2b.org/developers)

Upstream fixture license text is preserved as `segwit/UPSTREAM_COPYING` and `legacy/UPSTREAM_COPYING`, and included in release ZIPs.
