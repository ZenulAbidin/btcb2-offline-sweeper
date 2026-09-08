"""Verify the exact release inventory; optionally publish only verified assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def current_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("The release version must have three numeric components.")
    return version


def asset_names(version: str) -> list[str]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid release version.")
    return ["BTCB2-Offline.exe", "BTCB2-Online.exe",
            f"BTCB2-Offline-v{version}-windows-x64.zip",
            f"BTCB2-Online-v{version}-windows-x64.zip", "build-info.json", "SHA256SUMS"]


def reject_extra_files(directory: Path, version: str) -> None:
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ValueError("The release destination must be an ordinary directory.")
    if not directory.exists():
        return
    expected = set(asset_names(version))
    for path in directory.iterdir():
        if path.name not in expected or path.is_symlink() or not path.is_file():
            raise ValueError(f"Unexpected release output: {path.name}. Choose a clean dist directory.")


def verify_release(directory: Path, version: str, *, require_clean=False,
                   expected_commit=None) -> list[Path]:
    """Require no missing/extra paths and a complete, exact SHA256SUMS manifest."""
    directory = Path(directory)
    reject_extra_files(directory, version)
    names = asset_names(version)
    if {path.name for path in directory.iterdir()} != set(names):
        raise ValueError("The release is incomplete; all six expected assets are required.")
    sums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match[2] in sums:
            raise ValueError("The release checksum manifest is malformed or contains duplicates.")
        sums[match[2]] = match[1]
    if set(sums) != set(names) - {"SHA256SUMS"}:
        raise ValueError("The release checksum manifest does not list exactly the five payload assets.")
    for name, expected in sums.items():
        with (directory / name).open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != expected:
            raise ValueError(f"Release checksum mismatch: {name}")
    info = json.loads((directory / "build-info.json").read_text(encoding="utf-8"))
    if info.get("version") != version:
        raise ValueError("Build information does not match this release version.")
    if require_clean and info.get("source_tree_dirty") is not False:
        raise ValueError("Publishing requires a build from a clean source checkout.")
    if expected_commit is not None and info.get("source_commit") != expected_commit:
        raise ValueError("Build information does not match the checked-out source commit.")
    return [directory / name for name in names]


def verify_remote_tag(tag: str, expected_commit: str) -> None:
    """Check the target GitHub repository's tag, including annotated tag chains.

    gh's repository placeholders honor GH_REPO, just like the subsequent release
    command, so an alternate target cannot bypass the provenance comparison.
    """
    endpoint = f"repos/{{owner}}/{{repo}}/git/ref/tags/{tag}"
    for _ in range(16):
        response = json.loads(subprocess.check_output(["gh", "api", endpoint], cwd=ROOT, text=True))
        target = response.get("object", {})
        sha, kind = target.get("sha"), target.get("type")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("GitHub returned an invalid release tag target.")
        if kind == "commit":
            if sha != expected_commit:
                raise ValueError("The GitHub release tag points to a different source commit.")
            return
        if kind != "tag":
            raise ValueError("The GitHub release tag does not resolve to a source commit.")
        endpoint = f"repos/{{owner}}/{{repo}}/git/tags/{sha}"
    raise ValueError("The GitHub annotated tag chain is too deep.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / "dist")
    parser.add_argument("--publish", metavar="TAG", help="Publish a verified clean build as a prerelease")
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    version = current_version()
    if args.publish is not None and args.publish != f"v{version}":
        raise SystemExit("The release tag must match the source version.")
    commit = None
    if args.publish is not None or args.require_clean:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip():
            raise SystemExit("Release verification requires a clean checked-out source tree.")
    assets = verify_release(args.directory.resolve(), version,
                            require_clean=args.require_clean or args.publish is not None,
                            expected_commit=commit)
    print("Verified exactly six release assets and all five payload checksums.")
    if args.publish is not None:
        verify_remote_tag(args.publish, commit)
        # A structured argv list deliberately avoids shell wildcards and interpolation.
        subprocess.run(["gh", "release", "create", args.publish, *map(str, assets),
                        "--verify-tag", "--prerelease", "--title", f"BTCB2 Sweeper {args.publish}",
                        "--notes-file", str(ROOT / "docs" / "RELEASE_NOTES.md")], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
