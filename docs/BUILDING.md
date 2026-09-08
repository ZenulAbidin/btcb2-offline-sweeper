# Building and releasing Windows executables

Build on Windows x64 with the conventional (GIL-enabled) [CPython 3.13.15 release](https://www.python.org/downloads/release/python-31315/). The build checks this exact patch version and rejects other interpreters. PyInstaller bundles the interpreter and dependencies; users of the EXEs do not need Python. A Windows EXE must be built on Windows. Build in a clean virtual environment so unrelated local packages do not enter the archive.

## Local build

Install the conventional Windows x64 Python 3.13.15 installer first. From the repository root in PowerShell:

```powershell
py -3.13 -m venv .venv-build
.\scripts\build_windows.ps1 -Python .\.venv-build\Scripts\python.exe
```

The script installs `requirements-windows.lock` using `--require-hashes --only-binary=:all:`, runs both original bundles in separate processes and then the application tests, creates the two executables, runs each executable's `--self-test`, verifies the frozen module separation, and packages the downloads. An error stops the build.

Outputs appear in `dist/`:

| File | Purpose |
|---|---|
| `BTCB2-Offline.exe` | Single-file Windows console app for the disconnected computer |
| `BTCB2-Online.exe` | Single-file Windows console app for the connected computer |
| `BTCB2-Offline-v<VERSION>-windows-x64.zip` | Offline executable, instructions and licenses |
| `BTCB2-Online-v<VERSION>-windows-x64.zip` | Online executable, instructions and licenses |
| `SHA256SUMS` | SHA-256 hashes of the EXEs, ZIPs and build information |
| `build-info.json` | Version, source commit, interpreter, dependency versions and build checks |

`scripts/build_release.py` is the packaging-only entrypoint; use the PowerShell wrapper for the complete tested build. After dependencies are installed, `-SkipInstall` skips only installation, not tests. Never use a build environment containing real wallet files. No build step needs wallet access or submits a transaction.

The build refuses unexpected files in `dist/`, including ZIPs from an older version. Move old outputs out before building a new version. `python scripts/release_assets.py` checks that the folder contains exactly the six current assets and that all five payloads match the complete checksum manifest. Publishing additionally requires a clean source checkout and matching recorded source commit; local builds retain an honest `source_tree_dirty` marker.

## Updating dependencies

`requirements.txt` pins direct runtime dependencies for source users; `requirements-build.txt` adds packaging tools. The Windows lock additionally pins every transitive wheel and its SHA-256 hash for conventional CPython 3.13.15 x64. Update the exact interpreter baseline and package pins deliberately, resolve in a fresh Windows environment, and obtain hashes from the corresponding PyPI wheel. Review the resulting lock change and rerun the entire build. The hash file is intentionally platform-specific; use `requirements.txt` for Linux source tests.

PyInstaller's [one-file packaging options](https://pyinstaller.org/en/stable/usage.html) are configured in `scripts/build_release.py`. Source signer modules are imported explicitly into each build; only the online app includes explorer builders. Mnemonic word lists and required native libraries are bundled with the offline executable. Upstream, Python and dependency licenses are included.

## GitHub automation

The `Test, build, and release` workflow tests source on Ubuntu and builds/tests the frozen programs on Windows. Branch pushes, pull requests and manual runs create a downloadable `windows-release` Actions artifact. They do not publish a release.

To publish:

1. Update `btcb2_tui.__version__`, `pyproject.toml`, `CHANGELOG.md` and `docs/RELEASE_NOTES.md` together.
2. Commit the reviewed source, then create and push a matching version tag, for example `v0.1.0`.
3. The tag workflow checks the version, runs all checks, verifies the exact downloaded asset inventory, hashes and clean source provenance, and creates a **GitHub prerelease** with both EXEs, both ZIPs, checksums and build information. GitHub also supplies the tagged source archives. Uploads use explicit filenames; publishing takes its argument list from `scripts/release_assets.py`, never a wildcard.

Release publishing uses the workflow's scoped GitHub token. All third-party Actions are pinned to full commit hashes. Only the final release job has `contents: write`; build jobs use read-only repository permissions. If a release already exists, publishing fails rather than silently replacing it.

Version pins and metadata make the build inspectable. Byte-for-byte reproducibility is not claimed: Windows images, PE timestamps and archive metadata can differ. The current release process does not apply an Authenticode signature.

## Refreshing the original script downloads

When a file in `legacy/` or `segwit/` changes, run `python scripts/refresh_script_bundles.py`. This refreshes their `SHA256SUMS`, both `bundles/*.zip` downloads, and `bundles/SHA256SUMS`. ZIP membership comes only from the existing checksum allowlists; new source files must be listed deliberately. ZIP timestamps and permissions are fixed so repeating the command with unchanged source produces identical archives.
