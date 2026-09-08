"""Shared terminal widgets; no wallet loading or network operations."""
from __future__ import annotations

import datetime
import os
import uuid
from pathlib import Path

from prompt_toolkit.application import Application, get_app
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.filters import has_focus
from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
from prompt_toolkit.layout import HSplit, Layout
from prompt_toolkit.shortcuts import input_dialog, message_dialog, radiolist_dialog
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Button, Dialog, Label, RadioList, TextArea


class Cancelled(Exception):
    """A user returned to the menu without committing an operation."""


STYLE = Style.from_dict({
    "dialog": "bg:#102334 #e7eef4",
    "dialog.body": "bg:#102334 #e7eef4",
    "dialog.body text-area": "bg:#19354a #ffffff",
    "dialog frame.label": "bg:#102334 #54d6bd bold",
    "button": "bg:#29475a #ffffff",
    "button.focused": "bg:#54d6bd #102334 bold",
    "radio-selected": "#54d6bd bold",
    "frame.border": "#477288",
    "dialog shadow": "bg:#08151e",
})


def safe_text(value):
    """Never let a filename or remote string inject terminal control sequences."""
    return "".join(c if c in "\n\t" or (ord(c) >= 32 and not 0x7f <= ord(c) <= 0x9f)
                   else "?" for c in str(value))


def run_dialog(app):
    bindings = KeyBindings()
    @bindings.add("escape", eager=True)
    @bindings.add("c-c", eager=True)
    def cancel(event):
        event.app.exit(result=None)
    app.key_bindings = merge_key_bindings([app.key_bindings, bindings])
    return app.run()


class UI:
    def __init__(self, role):
        self.role = role
        self.last_folder = Path.home() / "Documents"
        if not self.last_folder.is_dir():
            self.last_folder = Path.cwd()

    def title(self, title):
        return f"BTCB2 {self.role.upper()}  |  {title}"

    def message(self, title, text):
        run_dialog(message_dialog(title=self.title(title), text=safe_text(text), style=STYLE))

    def choose(self, title, text, choices, default=None):
        items = RadioList(values=[(key, safe_text(label)) for key, label in choices],
                          default=default, select_on_focus=True)
        select = lambda: get_app().exit(result=items.current_value)
        dialog = Dialog(title=self.title(title), body=HSplit([
            Label(text=safe_text(text) + "\n\nArrows: choose   Enter: open   Tab: buttons   Esc: back"), items]),
            buttons=[Button(text="Continue", handler=select),
                     Button(text="Back", handler=lambda: get_app().exit(result=None))], with_background=True)
        bindings = KeyBindings()
        bindings.add("tab")(focus_next)
        bindings.add("s-tab")(focus_previous)
        bindings.add("enter", filter=has_focus(items), eager=True)(lambda event: select())
        app = Application(layout=Layout(dialog, focused_element=items), key_bindings=bindings,
                          mouse_support=True, style=STYLE, full_screen=True)
        value = run_dialog(app)
        if value is None:
            raise Cancelled()
        return value

    def ask(self, title, text, default="", secret=False, allow_empty=False, paths=False):
        while True:
            value = run_dialog(input_dialog(title=self.title(title), text=safe_text(text),
                default=default, password=secret, ok_text="Continue", cancel_text="Back",
                completer=PathCompleter(expanduser=True) if paths else None, style=STYLE))
            if value is None:
                raise Cancelled()
            # Passwords and BIP39 passphrases may deliberately contain whitespace.
            result = value if secret else value.strip()
            if result or allow_empty:
                return result
            self.message("A value is needed", "Enter a value, or press Esc to return to the menu.")

    def number(self, title, text, default=None, minimum=1, maximum=2_100_000_000_000_000):
        while True:
            raw = self.ask(title, text, str(default) if default is not None else "")
            try:
                value = int(raw)
                if not minimum <= value <= maximum:
                    raise ValueError()
                return value
            except ValueError:
                self.message("Check the number", f"Enter a whole number from {minimum:,} to {maximum:,}.")

    def review(self, title, text, action="Continue", confirm=False):
        """Scrollable review; cancel is always the initially focused action."""
        body = TextArea(text=safe_text(text), read_only=True, scrollbar=True,
                        wrap_lines=True, focusable=True, height=20)
        cancel = Button(text="Back", handler=lambda: get_app().exit(result=False))
        accept = Button(text=action, width=max(12, len(action) + 4),
                        handler=lambda: get_app().exit(result=True))
        dialog = Dialog(title=self.title(title), body=HSplit([
            Label(text="Tab to the text to scroll with arrows / Page Up / Page Down. Esc: back."),
            body]), buttons=[cancel, accept], with_background=True)
        bindings = KeyBindings()
        bindings.add("tab")(focus_next)
        bindings.add("s-tab")(focus_previous)
        bindings.add("escape")(lambda event: event.app.exit(result=False))
        bindings.add("c-c")(lambda event: event.app.exit(result=False))
        app = Application(layout=Layout(dialog, focused_element=cancel if confirm else body),
                          key_bindings=bindings, mouse_support=True, style=STYLE, full_screen=True)
        if not app.run():
            raise Cancelled()

    def confirm_destination(self, report, verb):
        destination = report["destination"]
        typed = self.ask(f"Confirm {verb.lower()}",
            "Compare this with your receiving wallet or BTCB2 deposit screen.\n"
            "The receiving service must support BTCB2 / BLAKE2b.\n\n"
            f"Destination: {destination}\n\nType the COMPLETE destination to confirm:")
        if typed != destination:
            self.message("Addresses do not match", "Nothing was signed or broadcast. Review the destination and try again.")
            raise Cancelled()
        self.review(f"Ready to {verb.lower()}", summary(report) +
                    ("\n\nSigning saves authorized transactions. It does not send them."
                     if verb == "Sign" else
                     "\n\nBroadcast sends the signed transactions to the selected BTCB2 server.\n"
                     "A successful broadcast cannot be undone."), action=verb, confirm=True)

    def browse(self, title, mode="open", filename=None, start=None):
        """Keyboard/mouse file browser including removable drive roots on Windows."""
        folder = Path(start) if start else self.last_folder
        if not folder.is_dir():
            folder = self.last_folder
        while True:
            choices = [("path", "Type or paste a path..."), ("drives", "Computer / USB drives...")]
            if mode in ("folder", "save"):
                choices.insert(0, ("select", "Use this folder"))
            if folder.parent != folder:
                choices.append(("up", "[..] Parent folder"))
            try:
                entries = sorted(folder.iterdir(), key=lambda p: (not p.is_dir(), p.name.casefold()))
                for index, entry in enumerate(entries[:2000]):
                    if entry.is_dir() or mode == "open":
                        choices.append((index, ("[Folder] " if entry.is_dir() else "         ") + entry.name))
            except OSError:
                self.message("Folder unavailable", "This folder or USB drive cannot be read. Select another location.")
                entries = []
            value = self.choose(title, f"Current folder: {folder}\n"
                                "Open a folder, or select a file. Type/paste a path for any unlisted item.", choices)
            if value == "up":
                folder = folder.parent
            elif value == "drives":
                roots = [Path("/")]
                if os.name == "nt":
                    import ctypes
                    bits = ctypes.windll.kernel32.GetLogicalDrives()
                    roots = [Path(chr(65+i) + ":\\") for i in range(26) if bits & (1 << i)]
                roots.insert(0, Path.home())
                try:
                    folder = self.choose("Computer / USB drives", "Reconnect the USB if its drive is missing.",
                                         [(p, str(p)) for p in roots])
                except Cancelled:
                    continue
            elif value == "path":
                try:
                    path = Path(self.ask(title, "Paste a full path. Tab completes folder and file names.",
                                         str(folder) + os.sep, paths=True).strip('"')).expanduser()
                except Cancelled:
                    continue
                if path.is_dir():
                    folder = path
                elif mode == "open" and path.is_file():
                    self.last_folder = path.parent
                    return path
                elif mode == "save" and path.parent.is_dir() and not path.exists():
                    self.last_folder = path.parent
                    return path
                else:
                    self.message("Check the path", "Choose an existing file to open, or a new filename to save. Existing files are never replaced.")
            elif value == "select":
                self.last_folder = folder
                if mode == "folder":
                    return folder
                name = self.ask("Save as", "Choose a new filename in this folder:", filename or "public_inventory.json")
                if Path(name).name != name or name in (".", ".."):
                    self.message("Use a filename", "Enter just the filename. Choose its folder in the previous screen.")
                    continue
                target = folder / name
                if target.exists():
                    self.message("File already exists", "Choose a different filename. Your existing file will be kept.")
                    continue
                return target
            else:
                path = entries[value]
                if path.is_dir():
                    folder = path
                else:
                    self.last_folder = folder
                    return path

    def output_folder(self, title, prefix):
        parent = self.browse(title, mode="folder")
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return parent / f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"

    def busy(self, title, operation):
        """Run slow work on a worker thread while the terminal stays responsive."""
        import asyncio
        import threading
        state = {"message": "Working...", "result": None, "error": None}
        lock = threading.Lock()
        def progress(message):
            with lock:
                state["message"] = safe_text(message)
            app.invalidate()
        label = Label(text=lambda: state["message"])
        dialog = Dialog(title=self.title(title), body=HSplit([label, Label(
            text="Keep this window open. Files are ready only when the completion screen appears.")]),
            with_background=True)
        app = Application(layout=Layout(dialog), style=STYLE, full_screen=True)
        async def task():
            try:
                state["result"] = await asyncio.to_thread(operation, progress)
            except BaseException as error:
                state["error"] = error
            finally:
                app.exit()
        app.run(pre_run=lambda: app.create_background_task(task()))
        if state["error"]:
            raise state["error"]
        return state["result"]


def money(sats):
    return f"{sats // 100_000_000:,}.{sats % 100_000_000:08d} BTCB2 ({sats:,} sats)"


def summary(report):
    return (f"Destination\n{report['destination']}\n\n"
            f"From your wallet:  {money(report['total_input_sats'])}\n"
            f"Network fee:       {money(report['total_fee_sats'])}\n"
            f"Destination gets:  {money(report['final_total_output_sats'])}\n\n"
            f"Inputs: {report['original_input_count']:,}   Transactions: {report['batch_count']:,}\n"
            "Network: BTCB2 / BLAKE2b   Signing profile: unified 0x21")


def detailed_report(report):
    lines = [summary(report), "", "Transaction details"]
    for tx in report["transactions"]:
        lines += [f"\nTransaction {tx['batch']}: {tx['input_count']} input(s)",
                  f"  Sends {money(tx['output_value_sats'])}", f"  Fee {money(tx['fee_sats'])}"]
        if report.get("signed"):
            lines.append("  Signed transaction ID: " + tx["txid"])
        else:
            lines.append("  Unsigned plan ID (not a broadcast ID): " + tx["txid"])
        lines.extend("  Input: " + point for point in tx["inputs"])
    lines += ["", "Plan reference: " + report["plan_sha256"],
              "Review all inputs and amounts. The complete report is also saved as report.json."]
    return "\n".join(lines)


HELP = """Two computers, three USB transfers

1. OFFLINE: Open your supported wallet or recovery backup. Save the public address list to USB.
2. ONLINE: Open that public list. Find current BTCB2 funds and save the returned folder to USB.
3. OFFLINE: Open manifest.json from that folder. Choose your BTCB2 destination and fee limits.
   Review the amount and destination, then sign. Export the signed folder to USB.
4. ONLINE: Open the signed folder, review it, and deliberately choose Broadcast.
   Save the receipt folder and check confirmations before relying on the transfer.

Only the public address list, fork data and signed transaction folder travel between computers.
Keep wallet files, recovery words, passwords and private keys on the offline computer.
Signed files authorize a spend; only share them when ready to broadcast.

The offline computer must stay physically disconnected from networking. The app never asks it
to connect or download anything. The online app never needs a wallet file, seed or private key.

Supported spending types: native SegWit (bc1q, single-key) and legacy (1, compressed keys).
3-address wallets, Taproot bc1p, multisig, Lightning balances and hardware-device signing are
not supported. The same wallet brand can contain several different wallet types.

These tools remain unaudited review prototypes. Explorer answers are not full-node validation.
Do not interpret a friendly interface or passing tests as a security audit.
Keep your original wallet and recovery backup: they may still control BTC.

Controls: arrows choose an item; Enter opens it; Tab moves focus to buttons.
Esc goes back. File browsing includes Computer / USB drives and a paste-path option.
Saved results can be reopened after restarting. Existing files are never overwritten.
"""
