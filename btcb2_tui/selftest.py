"""Synthetic release smoke tests. Never reads a user's wallet or contacts a server."""
from __future__ import annotations

import hashlib
import importlib
import json
import struct
import tempfile
from pathlib import Path

from . import __version__, service


def run(role):
    # Tests use the published generator public key, never an actual funded wallet.
    public = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    for kind in ("segwit", "legacy"):
        signer = service.signer_for(kind)
        program = signer.hash160(public)
        script = b"\x00\x14" + program if kind == "segwit" else b"\x76\xa9\x14" + program + b"\x88\xac"
        parent = (struct.pack("<I", 2) + b"\x01" + b"\x55" * 32 + b"\x00" * 4 + b"\x00" +
                  b"\xff" * 4 + b"\x01" + signer.serialize_output(100000, script) + b"\x00" * 4)
        txid = signer.sha256d(parent)[::-1].hex()
        with tempfile.TemporaryDirectory(prefix="btcb2-selftest-") as name:
            root = Path(name)
            manifest = dict(format=service._MANIFESTS[kind], signing_profile=signer.PROFILE,
                snapshot=dict(height=961641, block_hash="66" * 32), transactions={txid: parent.hex()},
                utxos=[dict(txid=txid, vout=0, value_sats=100000, script_pubkey=script.hex())])
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            report = service.plan(kind, path, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1", 1000, 1000, root / "plan")
            assert report["total_input_sats"] == 100000 and report["signed"] is False
            if role == "offline":
                # Published synthetic key 1, only used against a fabricated parent.
                signed = service.sign(kind, path, ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"],
                    root / "plan/report.json", root / "signed", expected_plan_sha256=report["plan_sha256"])
                assert service.inspect_signed_bundle(root / "signed") == signed
    if role == "offline":
        wallet_module = importlib.import_module("btcb2_tui.wallet")
        wallet = wallet_module.Wallet.from_mnemonic("abandon " * 11 + "about", "", "segwit")
        try:
            assert wallet.first_address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        finally:
            wallet.close()
    else:
        online = importlib.import_module("btcb2_tui.online")
        assert online.validate_endpoint("https://example.invalid/api") == "https://example.invalid/api"
    # Construct the real TUI without needing a real console during CI.
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import DummyInput
    from prompt_toolkit.output import DummyOutput
    from prompt_toolkit.shortcuts import input_dialog, radiolist_dialog
    from .ui import STYLE
    with create_app_session(input=DummyInput(), output=DummyOutput()):
        input_dialog(title="Self-test", text="Synthetic", style=STYLE)
        radiolist_dialog(title="Self-test", values=[("ok", "Synthetic")], style=STYLE)
    print(f"BTCB2 {role} {__version__}: synthetic self-test passed; no network used.")
    return 0
