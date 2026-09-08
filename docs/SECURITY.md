# Security model and limitations

BTCB2 Sweeper v0.1.0 is a **prerelease** built around the repository's existing signing prototypes. An internal security review and cross-review by separate AI agents were completed; [AUDIT.md](AUDIT.md) records the findings, fixes and tests. This is not an independent external security audit or validation against a BTCB2 full node. The guided interface and internal review do not establish production readiness.

## Two computers

The offline app opens secrets and signs locally. The online app works with public transfer files and has no wallet-import interface. Release builds exclude the online app and explorer-builder modules from the offline executable, and exclude the wallet adapter and recovery-phrase libraries from the online executable. The build checks the frozen archives to verify this separation.

This separation is a property of the application, not an operating-system sandbox. Physically disconnect the signing computer. A compromised computer, malicious USB device, screen recorder or modified executable can defeat the workflow. Python cannot guarantee that all secret values are erased from RAM or that the operating system never pages them to disk.

## Wallet secrets

Keep your original wallet and recovery backups. The same secrets can still control BTC and other fork assets. The app must never receive secrets on the online computer or write them into a USB transfer package. Recovery phrases should be entered only on the disconnected computer. WIF and legacy Core dumpwallet exports are private keys in plain text; keep those exports offline.

Hardware-wallet signing is not supported. Entering a hardware-wallet recovery phrase into desktop software changes its security assumptions and should not be treated as normal hardware-wallet integration.

## Review and network trust

Check the complete destination independently on the offline screen before signing. Amounts and fees must match your intention. The destination must be supported by a BTCB2 / BLAKE2b receiver. Confirming a broadcast submits a signed transaction and can cause an irreversible transfer.

The online explorer supplies public outputs and parent transactions. The signers verify parent transactions and transaction structure; the explorer checkpoint check helps distinguish the fork. These checks do not prove that an explorer is truthful, complete, or current. Offline validation cannot independently establish the present chain tip or whether an output was spent elsewhere after the request was made. Public inventories and packages reveal wallet addresses, balances and transaction intent.

Unified signatures use `SIGHASH_ALL | SIGHASH_UNIFIED` (`0x21`). The signing message must actually use the unified rules: adding a byte suffix alone is not replay protection. Ordinary BTC signatures may still replay on the fork. Do not use a generic Bitcoin wallet to sign these requests.

## Tests and release trust

Tests use synthetic secrets, upstream digest vectors, signature/serialization checks and mocked integrations. No test or checksum substitutes for a security audit, real full-node consensus validation, or checking the receiver's fork support.

Releases include SHA-256 hashes, locked build inputs, build information and third-party licenses. Hashes detect differences relative to a trusted published checksum; they do not independently authenticate an already-compromised release page. Current Windows EXEs are **not Authenticode-signed** and may trigger Windows reputation warnings. Review the source and build process if you need stronger assurance; do not disable system protection as a troubleshooting step.

If reporting a bug publicly, redact wallet files, keys, phrases, passwords, addresses and transaction data. Use synthetic examples wherever possible.
