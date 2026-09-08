"""Refresh the original CLI bundle checksums and deterministic ZIPs.

Only paths already listed in each bundle's SHA256SUMS are packaged. New source
files must be added deliberately to that list; wallet/working files are never
discovered by walking the directory.
"""

import hashlib
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def refresh(kind: str) -> Path:
    folder = ROOT / kind
    checksums = folder / "SHA256SUMS"
    paths = []
    for line in checksums.read_text(encoding="ascii").splitlines():
        if not line.strip():
            continue
        _, name = line.split("  ", 1)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError(f"Unsafe bundle path: {name}")
        source = (folder / name).resolve(strict=True)
        if not source.is_relative_to(folder.resolve()) or not source.is_file():
            raise ValueError(f"Invalid bundle file: {name}")
        paths.append(name)
    if len(paths) != len(set(paths)) or "SHA256SUMS" in paths:
        raise ValueError("Duplicate or self-referential checksum entry.")
    checksums.write_text("".join(f"{digest(folder / name)}  {name}\n" for name in paths),
                         encoding="ascii", newline="\n")
    archive_path = ROOT / "bundles" / f"btcb2-{kind}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(paths + ["SHA256SUMS"]):
            info = zipfile.ZipInfo(f"{kind}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (folder / name).read_bytes())
    return archive_path


def main() -> None:
    archives = [refresh(kind) for kind in ("legacy", "segwit")]
    (ROOT / "bundles" / "SHA256SUMS").write_text(
        "".join(f"{digest(path)}  {path.name}\n" for path in archives),
        encoding="ascii", newline="\n")
    print("Refreshed both original script bundles and all three checksum files.")


if __name__ == "__main__":
    main()
