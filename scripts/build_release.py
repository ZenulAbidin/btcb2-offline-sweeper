"""Build two isolated Windows executables, verify them, and package a release.

Run scripts/build_windows.ps1 for the complete dependency/test/build sequence.
This script never uploads files or signs/broadcasts a real transaction.
"""

from __future__ import annotations

import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
import zipfile

try:
    from .release_assets import reject_extra_files, verify_release
except ImportError:  # Direct invocation from the repository root.
    from release_assets import reject_extra_files, verify_release

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
DIST = ROOT / "dist"


def run(args: list[str], **kwargs) -> None:
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def collect_licenses(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise RuntimeError("License staging must be empty; refusing unreviewed existing files.")
    for bundle in ("segwit", "legacy"):
        shutil.copyfile(ROOT / bundle / "UPSTREAM_COPYING",
                        destination / f"{bundle}-UPSTREAM_COPYING.txt")
    for name in ("prompt-toolkit", "wcwidth", "cryptography", "cffi", "pycparser",
                 "coincurve", "mnemonic", "pyinstaller"):
        distribution = metadata.distribution(name)
        matches = [entry for entry in (distribution.files or ())
                   if entry.name.upper().startswith(("LICENSE", "COPYING"))]
        if not matches:
            raise RuntimeError(f"No license found in installed distribution: {name}")
        for index, entry in enumerate(matches):
            shutil.copyfile(distribution.locate_file(entry),
                            destination / f"{name}-{index}-{entry.name}")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        python_license = Path(sys.base_prefix) / "LICENSE"
    if not python_license.is_file():
        raise RuntimeError("Cannot find the bundled Python license.")
    shutil.copyfile(python_license, destination / "Python-LICENSE.txt")


def audit_archive(executable: Path, role: str) -> None:
    # Inspect the shipped archive, not merely the source import graph.
    from PyInstaller.archive.readers import CArchiveReader

    archive = CArchiveReader(str(executable))
    python_archive = archive.open_embedded_archive("PYZ.pyz")
    included = set(python_archive.toc)
    forbidden = ({"btcb2_tui.online", "btcb2_tui.online_app", "btcb2_tui.http_deadline",
                  "segwit.build_manifest", "legacy.build_manifest"}
                 if role == "offline" else
                 {"btcb2_tui.wallet", "btcb2_tui.offline_app", "mnemonic", "coincurve"})
    found = [module for module in included
             if any(module == blocked or module.startswith(blocked + ".")
                    for blocked in forbidden)]
    if found:
        raise RuntimeError(f"Unexpected modules in {role} executable: {found}")


def _build_with_licenses(notices: Path) -> None:
    if sys.platform != "win32" or platform.architecture()[0] != "64bit":
        raise SystemExit("Build on 64-bit Windows with 64-bit Python 3.12.")
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("Release builds require Python 3.12 and requirements-windows.lock.")
    with (ROOT / "pyproject.toml").open("rb") as handle:
        version = tomllib.load(handle)["project"]["version"]
    sys.path.insert(0, str(ROOT))
    from btcb2_tui import __version__
    if version != __version__:
        raise SystemExit("Package and application versions differ.")
    reject_extra_files(DIST, version)
    try:
        initial_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        initial_dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        initial_commit, initial_dirty = "unknown (source archive build)", None
    BUILD.mkdir(exist_ok=True)
    DIST.mkdir(exist_ok=True)
    os.environ["PYINSTALLER_CONFIG_DIR"] = str(BUILD / "pyinstaller-cache")
    collect_licenses(notices)
    assets = []
    for role in ("offline", "online"):
        name = f"BTCB2-{role.title()}"
        arguments = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                     "--onefile", "--console", "--noupx", "--name", name,
                     "--distpath", str(DIST), "--workpath", str(BUILD / role),
                     "--specpath", str(BUILD), "--paths", str(ROOT),
                     "--add-data", f"{notices};third-party-licenses",
                     "--hidden-import", "segwit.offline_sweep",
                     "--hidden-import", "legacy.offline_sweep"]
        if role == "offline":
            # coincurve's native extension loads its vendored CFFI backend dynamically.
            arguments += ["--hidden-import", "coincurve._cffi_backend",
                          "--collect-data", "mnemonic", "--exclude-module", "btcb2_tui.online",
                          "--exclude-module", "btcb2_tui.online_app",
                          "--exclude-module", "btcb2_tui.http_deadline",
                          "--exclude-module", "segwit.build_manifest",
                          "--exclude-module", "legacy.build_manifest"]
        else:
            arguments += ["--hidden-import", "segwit.build_manifest",
                          "--hidden-import", "legacy.build_manifest",
                          "--exclude-module", "btcb2_tui.wallet",
                          "--exclude-module", "btcb2_tui.offline_app",
                          "--exclude-module", "coincurve", "--exclude-module", "mnemonic"]
        run(arguments + [str(ROOT / f"launch_{role}.py")])
        executable = DIST / f"{name}.exe"
        # PyInstaller one-file extraction and dynamically imported modules are exercised here.
        run([str(executable), "--self-test"], timeout=90)
        audit_archive(executable, role)
        archive_path = DIST / f"{name}-v{version}-windows-x64.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(executable, executable.name)
            archive.write(ROOT / "docs" / "QUICKSTART.md", "START-HERE.md")
            archive.write(ROOT / "docs" / "SECURITY.md", "SECURITY.md")
            archive.write(ROOT / "docs" / "wallet-compatibility.md", "wallet-compatibility.md")
            archive.write(ROOT / "docs" / "AUDIT.md", "AUDIT.md")
            for license_path in sorted(notices.iterdir()):
                archive.write(license_path, f"third-party-licenses/{license_path.name}")
        assets.extend([executable, archive_path])
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                         text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"],
                                            cwd=ROOT, text=True).strip()) or initial_dirty
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown (source archive build)"
        dirty = None
    if commit != initial_commit:
        raise RuntimeError("Source commit changed during the build; rebuild from a stable checkout.")
    info = DIST / "build-info.json"
    info.write_text(json.dumps({
        "version": version, "source_commit": commit, "source_tree_dirty": dirty,
        "python": platform.python_version(), "platform": platform.platform(),
        "dependencies": {name: metadata.version(name) for name in
                         ("altgraph", "cffi", "coincurve", "cryptography", "mnemonic", "packaging",
                          "pefile", "prompt-toolkit", "pycparser", "pyinstaller",
                          "pyinstaller-hooks-contrib", "pywin32-ctypes", "setuptools", "wcwidth")},
        "checks": ["offline executable self-test", "online executable self-test",
                   "frozen module separation"],
        "authenticode_signed": False,
    }, indent=2) + "\n", encoding="utf-8")
    assets.append(info)
    (DIST / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(assets)), encoding="ascii")
    verify_release(DIST, version)
    print(f"\nRelease v{version} is ready in {DIST}")


def main() -> None:
    BUILD.mkdir(exist_ok=True)
    # A fresh scope prevents leftovers or unrelated files entering either binary.
    with tempfile.TemporaryDirectory(prefix="licenses-", dir=BUILD) as name:
        _build_with_licenses(Path(name))


if __name__ == "__main__":
    main()
