"""Argument parsing shared by both executables, without importing either role."""
import argparse

from . import __version__


def arguments(role):
    parser = argparse.ArgumentParser(description=f"BTCB2 {role} interactive assistant. Run without arguments for the guided menus.")
    parser.add_argument("--version", action="version", version=f"BTCB2 {role} {__version__}")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic local checks without a wallet or network")
    return parser.parse_args()


def start(role, main):
    try:
        return main()
    except (KeyboardInterrupt, EOFError):
        return 0
    except Exception:
        # No user-wallet paths, exception messages or tracebacks at this boundary.
        print(f"BTCB2 {role} could not open its terminal interface.")
        print("On Windows, double-click the executable or open it in Windows Terminal.")
        print("Wallet secrets and technical exception details have not been printed.")
        return 1
