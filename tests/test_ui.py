"""Check the approval boundary and ordinary-user cancellation paths."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from btcb2_tui import offline_app, online_app, service
from btcb2_tui.ui import Cancelled, UI, money, safe_text


class UITests(unittest.TestCase):
    def test_real_menu_can_select_and_cancel(self):
        with create_pipe_input() as pipe, create_app_session(input=pipe, output=DummyOutput()):
            pipe.send_text("\t\r")
            self.assertEqual(UI("offline").choose("Test", "Choose", [("x", "First"), ("y", "Second")]), "x")
            pipe.send_text("\x1b[B\r")
            self.assertEqual(UI("offline").choose("Test", "Choose", [("x", "First"), ("y", "Second")]), "y")
            pipe.send_text("\x03")
            with self.assertRaises(Cancelled):
                UI("offline").ask("Test", "Enter")

    def test_review_defaults_to_back_for_spending(self):
        with create_pipe_input() as pipe, create_app_session(input=pipe, output=DummyOutput()):
            pipe.send_text("\r")
            with self.assertRaises(Cancelled):
                UI("offline").review("Confirm", "Never approve by default", action="Sign", confirm=True)

    def test_busy_returns_result_and_propagates_safe_error(self):
        with create_pipe_input() as pipe, create_app_session(input=pipe, output=DummyOutput()):
            self.assertEqual(UI("online").busy("Work", lambda progress: 42), 42)
            with self.assertRaises(service.ServiceError):
                UI("offline").busy("Work", lambda progress: (_ for _ in ()).throw(service.ServiceError("Safe")))

    def test_mismatched_destination_never_reaches_confirmation(self):
        ui = UI("offline")
        ui.ask = Mock(return_value="wrong-address")
        ui.message = Mock()
        ui.review = Mock()
        with self.assertRaises(Cancelled):
            ui.confirm_destination({"destination": "expected-address"}, "Sign")
        ui.review.assert_not_called()

    def test_bad_known_address_does_not_export_and_wallet_is_closed(self):
        wallet = Mock(suggested_per_branch=200, source="BIP39", derivation="m/84'/0'/0'", first_address="first")
        wallet.inventory.return_value = {"addresses": [{"address": "first"}]}
        ui = Mock()
        ui.number.return_value = 200
        ui.ask.return_value = "wrong-wallet"
        ui.busy.side_effect = lambda title, operation: operation(lambda message: None)
        with patch.object(offline_app, "load_wallet", return_value=wallet), patch.object(service, "export_public_inventory") as export:
            with self.assertRaises(service.ServiceError):
                offline_app.export_inventory(ui)
            export.assert_not_called()
        wallet.close.assert_called_once()

    def test_cancel_sign_never_calls_sign_and_clears_keys(self):
        wallet = Mock(kind="segwit")
        keys = ["synthetic-secret"]
        wallet.keys_for_manifest.return_value = keys
        ui = Mock()
        ui.busy.side_effect = lambda title, operation: operation(lambda message: None)
        ui.confirm_destination.side_effect = Cancelled()
        with patch.object(offline_app, "load_wallet", return_value=wallet), patch.object(service, "sign") as sign, \
                patch.object(offline_app, "detailed_report", return_value="review"):
            with self.assertRaises(Cancelled):
                offline_app._sign_review(ui, "segwit", Path("manifest.json"), Path("report.json"), {})
            sign.assert_not_called()
        self.assertEqual(keys, [])
        wallet.close.assert_called_once()

    def test_cancel_broadcast_never_sends(self):
        ui = Mock()
        ui.browse.return_value = Path("signed")
        ui.busy.side_effect = lambda title, operation: operation(lambda message: None)
        ui.confirm_destination.side_effect = Cancelled()
        with patch.object(service, "inspect_signed_bundle", return_value={}), \
                patch.object(online_app, "detailed_report", return_value="review"), \
                patch.object(online_app, "endpoint", return_value="https://example.invalid/api"), \
                patch.object(online_app.online, "broadcast_bundle") as send:
            with self.assertRaises(Cancelled):
                online_app.broadcast(ui)
            send.assert_not_called()

    def test_plain_display_and_exact_amount(self):
        self.assertEqual(money(123456789), "1.23456789 BTCB2 (123,456,789 sats)")
        self.assertNotIn("\x1b", safe_text("\x1b[2Jbad-file"))

    def test_file_browser_can_paste_existing_file_and_rejects_overwrite(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "public.json"
            path.write_text("{}")
            ui = UI("online")
            ui.choose = Mock(return_value="path")
            ui.ask = Mock(return_value=str(path))
            self.assertEqual(ui.browse("Open"), path)
            ui.message = Mock()
            ui.ask = Mock(side_effect=[str(path), Cancelled()])
            with self.assertRaises(Cancelled):
                # First path is refused; next main-browser Esc exits.
                ui.choose = Mock(side_effect=["path", Cancelled()])
                ui.browse("Save", mode="save")
            ui.message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
