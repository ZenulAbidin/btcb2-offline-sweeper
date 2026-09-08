# Wallet compatibility

The [bitcoin.org wallet selector](https://bitcoin.org/en/choose-your-wallet) was used to identify common wallet families. Compatibility here means a **specific key format and address type** can be loaded by this sweeper. It is not an endorsement by bitcoin.org or any wallet developer, and it does not mean every backup made by that wallet can be opened.

## Pick the format you actually have

| Wallet or source | Use in the offline app | Supported scope and exclusions |
|---|---|---|
| Electrum | Electrum wallet file | Standard deterministic BIP32 xpub legacy or zpub native SegWit wallet; plain JSON, encrypted private keystore, or BIE1 password-encrypted file. Imported-key, multisig, 2FA, old non-BIP32 and hardware-encrypted wallets are unsupported. Electrum's own seed format is not BIP39; use the wallet file. |
| Sparrow software wallet | BIP39 recovery phrase | A single-signature BIP39 wallet using BIP44 or BIP84, with the original passphrase and account. No direct Sparrow database import, multisig or hardware signing. Sparrow documents BIP39 and Electrum as distinct keystore choices. [Sparrow guide](https://sparrowwallet.com/docs/quick-start.html) |
| BlueWallet on-chain wallet | BIP39 recovery phrase | Standard BIP84 account 0, or a confirmed BIP44 account. Other imported BlueWallet formats, BIP49, Lightning, Aezeed and SLIP39 are unsupported. BlueWallet supports more formats than this sweeper. [BlueWallet formats](https://github.com/BlueWallet/BlueWallet/wiki/Supported-wallet-types), [import guide](https://bluewallet.io/docs/import-wallet/) |
| BitPay single-signature Bitcoin wallet | BIP39 recovery phrase | Only a confirmed standard BIP39/BIP44 legacy configuration. Check derived addresses against the original wallet. Encrypted JSON/plain-text app backups and shared wallets are unsupported. BitPay documents recovery phrases and encrypted JSON as separate backup formats. [BitPay recovery](https://support.bitpay.com/hc/en-us/articles/115003004363-I-lost-access-to-my-wallet-or-device-How-do-I-recover-my-wallet) |
| Mycelium HD software wallet | BIP39 recovery phrase | Matching BIP44 or BIP84 account, scanned separately. Mycelium can combine BIP44, BIP49 and BIP84 funds in one displayed account; this sweeper cannot spend the BIP49 portion. Imported single keys need their own WIF export. [Mycelium's account design](https://github.com/mycelium-com/wallet-android/issues/483) |
| Bitcoin Core legacy wallet | WIF / Core dumpwallet text | A pre-existing legacy `dumpwallet` export containing compressed private keys. Core's RPC dump is a key text export; the native `wallet.dat`, descriptor exports and `bitcoin-wallet dump` database-dump format are not supported. [Core 29 dumpwallet reference](https://bitcoincore.org/en/doc/29.0.0/rpc/wallet/dumpwallet/) |
| Other compatible software wallets | BIP39 phrase or compressed WIF text | Conditional support when the exact format, account path and supported address type match. A wallet brand alone is insufficient to determine this. |
| Green, Wasabi, Bitcoin Safe, Bitcoin Wallet, Bither and other native backups | No dedicated native adapter | Do not select an unrelated format or rename the backup. A compatible standard BIP39/WIF source may work only if its account and script type match; alternative seed formats, multisig, descriptors and application-specific backups are not handled. |
| Hardware wallets | Unsupported signing integration | The app cannot ask hardware devices to sign BTCB2 transactions. Importing their recovery words into desktop software changes the protection model; it is not hardware-wallet support. |

The BIP39 rows are compatibility inferences from standard formats plus this application's supported derivations, not a claim that every historical version and backup of each brand has been tested. Tests exercise synthetic format fixtures and published derivation vectors. Compare an address from your own wallet before scanning or signing.

## BIP39 accounts and address types

Choose **Legacy** for `1…` P2PKH addresses, or **Native SegWit** for `bc1q…` P2WPKH addresses with a 20-byte witness program. The phrase alone does not identify the account or address type.

| Choice | Account path | Receiving and change branches |
|---|---|---|
| Legacy / BIP44 | `m/44'/0'/ACCOUNT'` | `/0/INDEX` and `/1/INDEX` |
| Native SegWit / BIP84 | `m/84'/0'/ACCOUNT'` | `/0/INDEX` and `/1/INDEX` |

These follow the [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) and [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) standards. Start with the account you used in the original wallet; account 0 is not a guarantee that all funds are covered. If the wallet used multiple accounts or both address types, repeat the inventory and sweep process for each supported account/type. The source account uses Bitcoin's `0'` coin type because these are the original Bitcoin keys.

A BIP39 passphrase derives a different wallet for every different value. A wrong but valid passphrase can show plausible new addresses with zero funds. It is independent of the password that locks a wallet app. The app currently accepts English BIP39 word lists; non-English phrases and Electrum-native phrases should not be entered as BIP39.

## Address range and unsupported funds

An inventory is a finite list of addresses. The online scan cannot discover addresses that were not exported. Include receiving and change ranges covering the original wallet's use, and increase the range if necessary. Compare addresses with the original wallet before trusting the result.

`3…` P2SH/BIP49, multisig, `bc1p…` Taproot, Lightning channel funds and uncompressed private keys cannot be swept by these signers. A mixed wallet can therefore have a larger original balance than the amount this tool supports. Changing the selected address type does not convert an existing output.
