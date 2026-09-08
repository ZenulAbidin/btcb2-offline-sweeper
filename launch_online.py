"""Windows online entry point. Deliberately has no wallet imports."""
from btcb2_tui.entry import arguments, start


def main():
    args = arguments("online")
    if args.self_test:
        from btcb2_tui.selftest import run
        return run("online")
    from btcb2_tui.online_app import main as app_main
    return start("online", app_main)


if __name__ == "__main__":
    raise SystemExit(main())
