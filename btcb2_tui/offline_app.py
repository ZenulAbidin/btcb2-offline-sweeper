"""Guided offline wallet workflow. Never imports the online component."""
from __future__ import annotations

import json
from pathlib import Path

from . import service
from .ui import Cancelled, HELP, UI, detailed_report
from .wallet import Wallet, WalletError


def choose_kind(ui):
    return ui.choose("Your original wallet's address type",
        "Choose by the addresses your ORIGINAL wallet used.\n"
        "A wallet brand can have several account types.\n"
        "Addresses starting with 3 or bc1p are not supported in this release.", [
            ("segwit", "Native SegWit: bc1q... (single-key, BIP84 for recovery phrases)"),
            ("legacy", "Legacy: 1... (compressed keys, BIP44 for recovery phrases)")])


def load_wallet(ui):
    source = ui.choose("Open your wallet OFFLINE", "Select the format of your wallet or recovery backup.\n"
        "Keep the computer disconnected. Recovery words and passwords stay in memory.", [
        ("electrum", "Electrum: open a wallet file (including password protected files)"),
        ("bip39", "BIP39 recovery words: BlueWallet, Sparrow, compatible software wallets"),
        ("keys", "Private-key text export: WIF / legacy Bitcoin Core dumpwallet"),
        ("help", "Which wallets and backup formats are supported?")])
    if source == "help":
        ui.review("Wallet compatibility", WALLET_HELP)
        return load_wallet(ui)
    if source == "electrum":
        path = ui.browse("Choose your Electrum wallet file")
        password = ui.ask("Wallet password", "Enter this wallet's password. Leave blank only if it has no password.",
                          secret=True, allow_empty=True)
        try:
            return ui.busy("Opening wallet", lambda progress: Wallet.load(path, password or None))
        finally:
            password = None
    kind = choose_kind(ui)
    if source == "keys":
        path = ui.browse("Choose private-key export (keep this file offline)")
        return ui.busy("Opening private-key export", lambda progress: Wallet.from_wif_file(path, kind))
    ui.review("Before entering recovery words",
        "Use the standard BIP39 backup for a software wallet you own.\n\n"
        "Enter the words only on this disconnected computer. They are never saved to a file.\n"
        "Do not export hardware-wallet recovery words just to use this tool: hardware-device\n"
        "signing is not supported. Electrum's own recovery words use a different format;\n"
        "open its wallet file instead. SLIP39 shares are not BIP39 words.\n\n"
        "Supported routes: BIP44 legacy or BIP84 native SegWit, one account at a time.\n"
        "You will verify a known wallet address before using the exported address list.", confirm=True)
    words = ui.ask("BIP39 recovery words", "Enter 12, 15, 18, 21 or 24 English recovery words, separated by spaces.", secret=True)
    passphrase = None
    try:
        passphrase = ui.ask("Optional BIP39 passphrase",
            "This is the EXTRA recovery passphrase, not your app PIN or login password.\n"
            "Leave blank if your backup did not use one. Every different passphrase creates a different wallet.",
            secret=True, allow_empty=True)
        account = ui.number("Wallet account", "Account number. The first account is 0.\n"
                            "Repeat the process separately for additional accounts.", 0, minimum=0, maximum=100000)
        return ui.busy("Opening recovery backup", lambda progress: Wallet.from_mnemonic(words, passphrase, kind, account))
    finally:
        words = passphrase = None


def export_inventory(ui):
    wallet = load_wallet(ui)
    try:
        count = ui.number("How far to check", "Check this many addresses on BOTH receiving and change branches.\n"
            "The suggested range includes addresses recorded in an Electrum file.\n"
            "A recovery phrase cannot tell us how many addresses you used. Increase the range for older or busy wallets.\n"
            "All keys in a private-key export are checked regardless of this setting.",
            wallet.suggested_per_branch, maximum=100000)
        inventory = ui.busy("Preparing public address list", lambda progress: wallet.inventory(count))
        known = ui.ask("Check that this is your wallet",
            f"Source: {wallet.source}\nAccount path: {wallet.derivation or 'From your wallet file / key export'}\n"
            f"First address: {wallet.first_address}\n\n"
            "Enter a receiving address you already KNOW belongs to this original wallet.\n"
            "Compare against your original wallet's address list or your records:")
        # Bech32 is case insensitive; Base58 is case sensitive.
        known = known.lower() if known.lower().startswith("bc1") else known
        if known not in {row["address"] for row in inventory["addresses"]}:
            raise service.ServiceError("That address was not found in this range. Check the backup, passphrase, account, address type and scan range. No address list was saved.")
        target = ui.browse("Save PUBLIC address list to USB", mode="save", filename="public_inventory.json")
        service.export_public_inventory(inventory, target)
        ui.review("Step 1 complete - take this file ONLINE",
            f"Saved {len(inventory['addresses']):,} public addresses to:\n{target}\n\n"
            "Take this file to the ONLINE computer. Open BTCB2-Online and choose\n"
            "Find my BTCB2 funds. This file contains public addresses and a public wallet identifier.\n\n"
            "Keep a copy of this exact public file: the offline signing step needs it.\n"
            "The wallet, recovery words, password and keys stay on this computer.", action="Done")
    finally:
        wallet.close()


def _kind_for_manifest(path):
    data = service.read_json(path)
    kinds = {"offline-p2wpkh-sweep/v2": "segwit", "offline-p2pkh-sweep/v1": "legacy"}
    if data.get("format") not in kinds:
        raise service.ServiceError("Choose manifest.json from the online scan result, not an address list or wallet file.")
    kind = kinds[data["format"]]
    service.validate_manifest(data, kind)
    return kind


def _sign_review(ui, kind, manifest, review_path, report):
    ui.review("Review the complete sweep", detailed_report(report), action="Choose wallet to sign")
    inventory = ui.browse("Open the ORIGINAL public_inventory.json")
    wallet = load_wallet(ui)
    keys = []
    try:
        if wallet.kind != kind:
            raise service.ServiceError("This wallet's address type does not match the manifest. Choose the original wallet/account.")
        # Verify wallet ownership before offering the final signing action.
        keys = ui.busy("Checking wallet against selected funds",
                       lambda progress: wallet.keys_for_manifest(manifest, inventory))
        out = ui.output_folder("Choose where to save the signed result (offline)", "signed")
        ui.confirm_destination(report, "Sign")
        result = ui.busy("Signing OFFLINE", lambda progress: service.sign(kind, manifest, keys, review_path, out,
                        expected_plan_sha256=report["plan_sha256"]))
    finally:
        keys.clear()
        wallet.close()
    ui.review("Signed locally - no coins sent yet", detailed_report(result) + f"\n\nSaved folder:\n{out}\n\n"
        "Next: export the signed result to your USB. Only the reviewed report and signed transactions will be copied.",
        action="Choose USB folder")
    export_signed(ui, source=out)


def prepare_sign(ui):
    manifest = ui.browse("Step 3: open manifest.json from ONLINE")
    kind = _kind_for_manifest(manifest)
    destination = ui.ask("Where should the BTCB2 go?", "Paste the destination from your BTCB2 / BLAKE2b receiving wallet.\n"
        "If using an exchange, verify its selected deposit network is BTCB2 / BLAKE2b.\n"
        "The destination must start with 1 or be a supported bc1q address.")
    fee = ui.ask("Network fee rate", "Enter your chosen BTCB2 fee rate in sat/vB, for example 1 or 0.5.\n"
        "Use the fork network's fee information from the online computer. The examples are not recommendations.")
    max_tx = ui.number("Fee limit per transaction", "Maximum fee you permit for ONE transaction, in satoshis.\n"
        "100,000 sats = 0.001 BTCB2. The app will stop if this limit would be exceeded.", 100000)
    max_total = ui.number("Fee limit for the whole sweep", "Maximum TOTAL fee you permit, in satoshis.\n"
        "500,000 sats = 0.005 BTCB2. Review the calculated fee on the next screen.", 500000)
    out = ui.output_folder("Choose where to save your unsigned review plan", "plan")
    report = ui.busy("Preparing the review plan", lambda progress:
        service.plan(kind, manifest, destination, fee, max_tx, max_total, out))
    ui.message("Review plan saved", f"Saved:\n{out / 'report.json'}\n\n"
        "You can cancel now and resume later with 'Open a saved plan and sign'.")
    _sign_review(ui, kind, manifest, out / "report.json", report)


def resume_sign(ui):
    review_path = ui.browse("Open your saved UNSIGNED report.json")
    report = service.read_json(review_path)
    kind = service.validate_report(report)
    if report["signed"] is not False:
        raise service.ServiceError("This report is already signed. Use Export signed result to USB.")
    manifest = ui.browse("Open the manifest.json used for this plan")
    if _kind_for_manifest(manifest) != kind:
        raise service.ServiceError("This manifest and plan have different wallet types.")
    _sign_review(ui, kind, manifest, review_path, report)


def export_signed(ui, source=None):
    if source is None:
        source = ui.browse("Choose the signed result folder", mode="folder")
    report = service.inspect_signed_bundle(source)
    ui.review("Files allowed onto the USB", detailed_report(report) +
        "\n\nOnly report.json and its validated transaction .hex files will be copied.\n"
        "Keep the signed files private until you are ready to broadcast.", action="Choose USB folder")
    target = ui.output_folder("Choose a folder on your USB", "signed-transfer")
    service.export_signed_bundle(source, target)
    ui.review("Step 3 complete - take this folder ONLINE", f"USB folder:\n{target}\n\n"
        "Take the whole folder to the ONLINE computer. Open BTCB2-Online and choose\n"
        "Review signed files and broadcast. It will check the files again before asking to send.", action="Done")


def main():
    ui = UI("offline")
    try:
        ui.review("Start on the disconnected computer", "Keep this computer disconnected from Wi-Fi, Ethernet and mobile networks.\n\n"
            "This app opens wallets and signs transactions locally. It never broadcasts.\n"
            "Use BTCB2-Online on your other computer for internet steps.\n\n"
            "This is a review prototype with no external security audit or full-node validation.\n"
            "Keep your original wallet and recovery backup safe.", action="Open offline menu", confirm=True)
    except Cancelled:
        return 0
    while True:
        try:
            action = ui.choose("Offline menu", "Start at step 1, then return for step 3 after the online scan.", [
                ("inventory", "1. Open my wallet and save a public address list"),
                ("sign", "3. Open the returned funds file, review and sign"),
                ("resume", "Open a saved plan and sign"),
                ("export", "Export a signed result to USB"),
                ("help", "Help: the two-computer process"), ("quit", "Exit")])
            if action == "quit":
                return 0
            if action == "help":
                ui.review("Help", HELP, action="Menu")
            else:
                {"inventory": export_inventory, "sign": prepare_sign,
                 "resume": resume_sign, "export": export_signed}[action](ui)
        except Cancelled:
            continue
        except (WalletError, service.ServiceError) as error:
            ui.message("Could not complete this step", str(error))
        except (KeyboardInterrupt, EOFError):
            return 0
        except Exception:
            ui.message("Could not complete this step", "Check the selected files and available disk space, then try again.\n"
                "Technical exception details are hidden to protect wallet secrets. No broadcast is possible in this app.")


WALLET_HELP = """Choose the backup FORMAT, not just the wallet brand

Electrum: open a standard single-signature BIP32 wallet file, including password-protected
files. Supports xpub legacy and zpub native SegWit. No imported/2FA/hardware/old Electrum
wallet files. Compressed imported keys can use the separate private-key export route.

BlueWallet and Sparrow software wallets: a standard English BIP39 recovery phrase can
recover BIP84 native SegWit or BIP44 legacy accounts. Enter the original extra passphrase,
if any, and choose the original account number. Native app backup files are not accepted.

Other BIP39 software wallets: use this route only when their documented account path is
BIP44 or BIP84. Wallets on bitcoin.org also include BitPay and Mycelium; compatibility is
determined by the actual backup, path and address type, not the name on the app.

Bitcoin Core: accepts the compressed WIF keys in an EXISTING legacy dumpwallet text export.
Native wallet.dat, descriptor wallet databases and descriptor exports are not supported.
An HD seed key in an old dump is not a substitute for exporting its used address keys.

Other key exports: ASCII text with one compressed mainnet WIF per line. Electrum's p2pkh:
and p2wpkh: prefixes are supported only when they match your selected address type.

Not supported: 3-address / BIP49 inputs, Taproot / BIP86, multisig, Lightning balances,
SLIP39 shares, native app backups other than the Electrum files described above, or direct
hardware-device signing. Never assume that entering recovery words adds these capabilities.

The wizard checks an existing address from your wallet before exporting a public scan list.
If it cannot find that address, fix the backup, passphrase, account, address type or range.
"""
