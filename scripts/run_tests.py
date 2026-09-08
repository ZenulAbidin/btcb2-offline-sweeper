"""Run each original bundle in isolation, then the guided application's tests."""

from pathlib import Path
import subprocess
import sys


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    for folder in ("segwit", "legacy"):
        print(f"\nRunning {folder} tests", flush=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-v"],
                       cwd=root / folder, check=True)
    if not list((root / "tests").glob("test_*.py")):
        raise SystemExit("Application tests are missing; refusing an untested release.")
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                   cwd=root, check=True)
    for role in ("offline", "online"):
        subprocess.run([sys.executable, str(root / f"launch_{role}.py"), "--self-test"],
                       cwd=root, check=True)


if __name__ == "__main__":
    main()
