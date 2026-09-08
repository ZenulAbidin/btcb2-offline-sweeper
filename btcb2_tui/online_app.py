"""Public-data workflow. This module never imports the wallet adapter."""
from __future__ import annotations

import json

from . import online, service
from .ui import Cancelled, HELP, UI, detailed_report, money


def endpoint(ui, default="https://mempool.guide/api"):
    value = ui.ask("BTCB2 explorer", "Use the compatible HTTPS Esplora API for BTCB2 / BLAKE2b.\n"
        "The app checks the fork checkpoint before scanning or sending.\n"
        "This service sees the public addresses or signed transactions you submit.", default)
    return online.validate_endpoint(value)


def find_funds(ui):
    path = ui.browse("Step 2: open the public address list from OFFLINE")
    inventory = service.validate_inventory(service.read_json(path))
    first_script = inventory["addresses"][0]["script_pubkey"]
    kind = "segwit" if first_script.startswith("0014") else "legacy"
    api = endpoint(ui)
    out = ui.output_folder("Choose where to save the returned fork-data folder (USB)", "fork-data")
    ui.review("Ready to check your public addresses",
        f"Addresses: {len(inventory['addresses']):,}\nServer: {api}\n\n"
        "Every supplied receiving and change address will be checked. Large lists can take several minutes.\n"
        "The list is a fixed scan range; a successful scan does not prove that later addresses are empty.\n\n"
        "The scan only reads public chain data. It cannot spend funds.", action="Find funds", confirm=True)
    result = ui.busy("Finding your BTCB2 funds", lambda progress:
        online.collect_inventory(kind, inventory, api, out, progress=progress))
    evidence = result["evidence"]
    text = (f"Found: {money(evidence['included_sats'])}\n"
            f"Spendable outputs found: {evidence['included_outputs']:,}\n"
            f"Addresses checked: {evidence['addresses_checked']:,}\n"
            f"Excluded outputs: {len(evidence['excluded']):,}\n\n"
            f"Saved folder:\n{out}\n\n"
            "Take this folder and your original public address list to the OFFLINE computer.\n"
            "Open BTCB2-Offline and select step 3. Choose manifest.json inside this folder.\n\n"
            "Read verification.json for the full evidence and exclusions. A balance covers only this scan range.\n"
            "New receipts after the recorded snapshot are excluded. Explorer data is not full-node validation.\n\n"
            "Exclusion details:\n" + json.dumps(evidence["excluded"], indent=2))
    ui.review("Step 2 complete - take these files OFFLINE", text, action="Done")


def receipt_text(receipt):
    labels = {"pending": "Not submitted", "sending": "Uncertain - check before any resend",
              "accepted": "Accepted by server; awaiting confirmation",
              "already_known": "Found on the fork server", "uncertain": "Uncertain - check before any resend"}
    rows = [f"Destination: {receipt['destination']}", f"Server: {receipt['endpoint']}", ""]
    for tx in receipt["transactions"]:
        state = f"Confirmed in block {tx.get('block_height')}" if tx.get("confirmed") else labels[tx["state"]]
        rows.extend([tx["txid"], state, ""])
    rows.append("A server acceptance is not a confirmation or an exchange credit. Check status again later.")
    return "\n".join(rows)


def broadcast(ui):
    source = ui.browse("Step 4: choose the signed folder from OFFLINE", mode="folder")
    report = ui.busy("Checking signed files", lambda progress: service.inspect_signed_bundle(source))
    ui.review("Review the signed sweep", detailed_report(report) +
        "\n\nAll transaction files have been checked against the report, including their signatures.\n"
        "You can still go Back. Nothing has been broadcast.", action="Choose broadcast server")
    api = endpoint(ui)
    previous = ui.choose("Save progress safely", "If you already tried sending this bundle, reopen its receipt folder.\n"
        "This lets the app check uncertain results before sending any remaining transactions.", [
            (False, "First attempt: create a new receipt folder"),
            (True, "Continue using an existing receipt folder")])
    receipts = (ui.browse("Choose the existing receipt folder", mode="folder") if previous else
                ui.output_folder("Choose LOCAL storage for broadcast receipts", "receipts"))
    ui.review("Broadcast location", f"BTCB2 server:\n{api}\n\nReceipt folder:\n{receipts}\n\n"
        "Keep the receipt folder. If a network error occurs, check transaction status before trying again.",
        action="Review final confirmation")
    ui.confirm_destination(report, "Broadcast")
    try:
        result = ui.busy("Broadcasting to BTCB2", lambda progress:
            online.broadcast_bundle(source, api, receipts, progress=progress,
                                    expected_plan_sha256=report["plan_sha256"]))
    except Exception:
        ui.message("Check receipts before trying again", f"A receipt may have been saved at:\n{receipts}\n\n"
            "Use 'Check transaction status' to see which transactions the server knows.\n"
            "Reopen this same receipt folder if you return to the broadcast step.")
        raise
    ui.review("Broadcast results", receipt_text(result) + f"\n\nSaved:\n{receipts / 'receipts.json'}", action="Done")


def check_status(ui):
    path = ui.browse("Open receipts.json from a previous broadcast")
    result = ui.busy("Checking confirmations", lambda progress: online.check_status(path, progress=progress))
    ui.review("Transaction status", receipt_text(result), action="Done")


def main():
    ui = UI("online")
    while True:
        try:
            action = ui.choose("Online menu", "Use public files from the offline computer.\n"
                "Wallet files, recovery words, passwords and private keys belong on the OFFLINE computer.", [
                    ("scan", "2. Find my BTCB2 funds from the public address list"),
                    ("broadcast", "4. Review signed files and broadcast"),
                    ("status", "Check transaction status from a saved receipt"),
                    ("help", "Help: the two-computer process"), ("quit", "Exit")])
            if action == "quit":
                return 0
            if action == "help":
                ui.review("Help", HELP, action="Menu")
            else:
                {"scan": find_funds, "broadcast": broadcast, "status": check_status}[action](ui)
        except Cancelled:
            continue
        except service.ServiceError as error:
            ui.message("Could not complete this step", str(error))
        except (KeyboardInterrupt, EOFError):
            return 0
        except Exception:
            ui.message("Could not complete this step", "Check the selected files, connection and available disk space.\n"
                "If you were broadcasting, inspect the saved receipt before another attempt.")
