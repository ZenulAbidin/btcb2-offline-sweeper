"""Windows offline entry point. Deliberately has no online imports."""
from btcb2_tui.entry import arguments, start


def main():
    args = arguments("offline")
    if args.self_test:
        from btcb2_tui.selftest import run
        return run("offline")
    from btcb2_tui.offline_app import main as app_main
    return start("offline", app_main)


if __name__ == "__main__":
    raise SystemExit(main())
