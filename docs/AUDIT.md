# v0.1.0 internal security and operational review

Reviewed on 2026-09-08 before publication. This was an internal, AI-assisted source review with separate agent cross-review, executable checks, adversarial regressions and synthetic transaction tests. It is **not an external security audit or certification**. No real wallet was imported and no real transaction was broadcast during development or review.

## Scope and trust boundaries

The review covered the new terminal interfaces, wallet adapters, offline service, online scanner and broadcaster, changes to both existing signing scripts, transfer-file validation, dependencies, Windows packaging and GitHub publication workflow. The existing signers were reviewed with their tests and upstream vectors; their consensus behavior has not been independently established against a BTCB2 full node.

Threats considered included malicious or corrupt USB files, dishonest explorer responses, replacing a request after approval, accidental disclosure of keys, mistaken destination/fee approval, interrupted broadcasts, repeated sends, unsupported wallet configurations and publishing the wrong files or source version. The signing computer and executable must themselves be trusted. A compromised operating system or malicious USB hardware is outside the application's protection.

## Findings and resolutions

All findings below were addressed before the release build. The evidence describes the checks actually performed; it does not establish absence of other vulnerabilities.

| Finding | Consequence | Resolution and verification |
|---|---|---|
| Temporary private-key files in the initial service integration | Plaintext keys could survive a crash or remain recoverable on disk. | The guided signer now supplies keys in memory after the reviewed plan is checked. File-writer spies check interrupted signing, and a rejected-plan test verifies that the key provider is never called. Round-trip tests also search public transfer outputs for synthetic secrets. Original command-line key-file support remains an explicit advanced-user feature. |
| Request replacement between review and action | The action could use a different plan from the one approved. | Signing and broadcasting compare the approved plan digest; the broadcaster freezes and revalidates signed bytes before any network request. Changed-plan regressions reject substitutions. |
| Crash leaves a persistent broadcast lock | A saved receipt could become permanently unusable. | OS-owned file locks replace existence-based locks. Tests verify mutual exclusion, stale-file reuse and release after killing the actual lock-owning process. Receipts preserve sending/uncertain states and do not automatically resend. |
| Stale confirmation metadata | An unknown or newly unconfirmed transaction could retain an old confirmation label or height. | Clear obsolete fields when status changes. Regression tests cover transitions and reopening receipts. |
| Encrypted Electrum data starts with an extended-key prefix | Some valid encrypted wallets would be misidentified as plaintext and fail to open. | Validate a complete extended key before classifying it as plaintext. Controlled ciphertext fixtures exercise both `xprv` and `zprv` prefixes with missing, wrong and correct passwords. |
| Eager scan scheduling and excessive retained data | Large or malicious responses could consume excessive memory or continue unnecessary requests after a failure. | Bound concurrent outstanding work, address/coin counts, parent transaction data and serialized evidence. The same 20-address failure regression issues at most three requests after the fix; both original builders issued all 20 in that controlled scenario. |
| Slow HTTP headers or bodies defeat inactivity timeouts | A server sending occasional bytes could keep an operation waiting indefinitely. | Apply a monotonic response deadline to raw header/body reads while retaining standard HTTPS certificate verification. Real socket tests exercise slow headers, slow bodies and normal body reads after connection handoff. OS DNS behavior is not proven to meet this deadline. |
| Stale files in the release directory | An unrelated file could be uploaded with the binaries. | Require exactly six named assets and exactly five payload checksum entries; publish an explicit argument list. Extra/missing/mismatched files prevent publication. |
| Stale license staging | Unrelated files could enter both EXEs and ZIPs despite a clean release directory. | Build licenses in a fresh temporary directory and reject nonempty staging. The pre-fix sentinel reproduction is rejected after the fix. |
| Existing release tag points to different source | Correctly hashed binaries could be attached to the wrong source version. | Require clean source provenance and resolve the target GitHub tag, including annotated tags, to the build's commit. A mismatched target prevents the release command. |
| Known advisory in a build dependency | The initial setuptools pin had a published source-distribution exclusion vulnerability. | Upgrade to hash-pinned setuptools 83.0.0. The installed fix and Unicode exclusion behavior were checked. This was not a demonstrated exploit of the Windows EXEs; see the [setuptools advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-h35f-9h28-mq5c). |
| Incomplete final transaction review | Users could not compare signed transaction IDs with later receipts. | Display signed IDs and distinguish unsigned legacy IDs, which change on signing. Review dialogs were checked at 80×25, 80×30 and 120×30 terminal sizes. |

## Audit of the audit

Separate agents reviewed fixes outside their implementation ownership. Wallet work was cross-checked by the workflow reviewer; workflow, locks and network deadlines by the packaging reviewer; packaging by both wallet and workflow reviewers. The primary agent reviewed integration and the report. These reviewers share an AI toolchain and are not independent external auditors.

The second review found the stale license staging and tag provenance issues after the first release-directory fix. It also found a defect in the crash test: a Windows virtual-environment launcher could be killed while its child still owned the lock. The corrected test launches the base interpreter and asserts that the reported lock-holder PID equals the process being killed.

Selected regressions were tested against original implementations or isolated restorations of the original behavior: encrypted-key prefix detection, stale confirmation handling, eager scan scheduling and slow-response handling. They failed on the original behavior and passed on the fixes. This checks that those tests detect the stated bugs; it is not exhaustive mutation testing.

## Validation evidence

The final local Windows source run completed 107 tests: 106 passed and one POSIX-permissions test was skipped. Both role self-tests also passed. GitHub Actions records the separate Linux/Windows release checks.

- Both original signer suites and the complete application suite run through `python scripts/run_tests.py`. They cover published derivation/digest vectors, signature and transaction validation, replay rejection, malformed files, secret-free public transfers, confirmation defaults and broadcast recovery.
- Synthetic full workflows cover BIP39 legacy and SegWit accounts, encrypted Electrum fixtures and compressed WIF imports, through inventory, mocked scan, plan, signing, exported bundle, mocked broadcast and receipt reopening. External network access is blocked in these round-trip tests.
- Electrum encryption fixtures are synthetic; encryption logic was compared with pinned upstream source, and address derivation with published vectors. No upstream BIE1 ciphertext fixture or live Electrum-created wallet was tested, and this is not a claim that every Electrum wallet configuration works.
- One read-only request through the actual HTTPS transport confirmed the configured explorer's required fork checkpoint. No wallet addresses or transactions were submitted in that check.
- The 14 pinned Windows dependency versions were checked against their PyPI JSON advisory data after the setuptools upgrade; no published advisories were returned at review time. This is a dated known-advisory check, not a source audit of every dependency or embedded native library.
- Release builds run self-tests inside both actual one-file Windows EXEs, inspect frozen module separation and verify the exact release inventory and checksums. Build metadata records the source commit and clean-tree status. CI reruns tests on Linux and Windows before publishing a tagged prerelease.

## Remaining limitations

- No independent full-node consensus validation, real-chain signing/broadcast test, external penetration test or third-party security audit has been performed. The release remains a prerelease around review-prototype signers.
- Wallet support is format- and script-specific. See [wallet compatibility](wallet-compatibility.md). Native files from arbitrary wallets, P2SH/BIP49, multisig, Taproot, Lightning and hardware-wallet signing are unsupported. Selecting a compatible brand is not sufficient to establish a compatible account.
- Physical isolation is required. Module separation is not an OS sandbox. Python cannot guarantee erasure of secrets from RAM or prevent operating-system paging. Public USB packages expose addresses and transaction intent.
- Explorer checks verify supplied transaction data and a known fork checkpoint, but do not prove explorer honesty, completeness, present unspentness or chain consensus. An uncertain broadcast may require manual investigation; the app deliberately does not automatically resend it.
- Windows binaries are not Authenticode-signed. SHA-256 checksums alone cannot authenticate a compromised release page. Build inputs are pinned, but bit-for-bit reproducible EXEs are not claimed.
- The response deadline applies to the guided online transport. The original advanced command-line tools retain their own transport behavior. Large legitimate scans still take time, and the guided busy dialog has no in-place cancel control.

See [SECURITY.md](SECURITY.md) for the operating model and [BUILDING.md](BUILDING.md) for release verification. Rerun and extend this review when signing, wallet parsing, transport, dependency or packaging behavior changes.
