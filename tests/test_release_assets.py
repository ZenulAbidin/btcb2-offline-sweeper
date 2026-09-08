"""Release integrity regressions use temporary synthetic artifact files only."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import release_assets
from scripts.release_assets import asset_names, reject_extra_files, verify_release, verify_remote_tag


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="btcb2-release-audit-")
        self.folder = Path(self.temporary.name)
        self.version = "0.1.0"
        for name in asset_names(self.version):
            (self.folder / name).write_bytes(b"synthetic artifact")
        self.info = {"version": self.version, "source_commit": "a" * 40, "source_tree_dirty": False}
        self.save_info()

    def tearDown(self):
        self.temporary.cleanup()

    def save_info(self):
        (self.folder / "build-info.json").write_text(json.dumps(self.info), encoding="utf-8")
        self.update_sums()

    def update_sums(self):
        payloads = [name for name in asset_names(self.version) if name != "SHA256SUMS"]
        (self.folder / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.folder / name).read_bytes()).hexdigest()}  {name}\n"
            for name in payloads), encoding="ascii")

    def test_exact_current_inventory_is_accepted(self):
        result = verify_release(self.folder, self.version, require_clean=True, expected_commit="a" * 40)
        self.assertEqual([path.name for path in result], asset_names(self.version))

    def test_old_zip_or_unreviewed_extra_is_rejected_before_build_and_publish(self):
        for name in ("BTCB2-Offline-v0.0.1-windows-x64.zip", "unreviewed.exe"):
            with self.subTest(name=name):
                extra = self.folder / name
                extra.write_bytes(b"unreviewed")
                with self.assertRaisesRegex(ValueError, "Unexpected release output"):
                    reject_extra_files(self.folder, self.version)
                with self.assertRaisesRegex(ValueError, "Unexpected release output"):
                    verify_release(self.folder, self.version)
                extra.unlink()

    def test_manifest_requires_all_payloads_and_no_duplicate_or_extra_entries(self):
        path = self.folder / "SHA256SUMS"
        original = path.read_text()
        variants = ["\n".join(original.splitlines()[:-1]) + "\n",
                    original + original.splitlines()[0] + "\n",
                    original + "0" * 64 + "  ../outside\n"]
        for text in variants:
            with self.subTest(text=text):
                path.write_text(text, encoding="ascii")
                with self.assertRaises(ValueError):
                    verify_release(self.folder, self.version)
        path.write_text(original, encoding="ascii")

    def test_modified_or_missing_artifact_fails(self):
        path = self.folder / "BTCB2-Offline.exe"
        path.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            verify_release(self.folder, self.version)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verify_release(self.folder, self.version)

    def test_dirty_unknown_or_mismatched_source_is_never_publishable(self):
        for dirty in (True, None, 0, "false"):
            with self.subTest(dirty=dirty):
                self.info["source_tree_dirty"] = dirty
                self.save_info()
                with self.assertRaisesRegex(ValueError, "clean source checkout"):
                    verify_release(self.folder, self.version, require_clean=True)
        self.info["source_tree_dirty"] = False
        self.save_info()
        with self.assertRaisesRegex(ValueError, "source commit"):
            verify_release(self.folder, self.version, require_clean=True, expected_commit="b" * 40)

    def test_remote_tag_must_resolve_to_built_source_including_annotated_tags(self):
        with patch.object(release_assets.subprocess, "check_output", return_value=json.dumps(
                {"object": {"type": "commit", "sha": "b" * 40}})):
            with self.assertRaisesRegex(ValueError, "different source commit"):
                verify_remote_tag("v0.1.0", "a" * 40)
        responses = [json.dumps({"object": {"type": "tag", "sha": "b" * 40}}),
                     json.dumps({"object": {"type": "commit", "sha": "a" * 40}})]
        with patch.object(release_assets.subprocess, "check_output", side_effect=responses) as query:
            verify_remote_tag("v0.1.0", "a" * 40)
            self.assertEqual(query.call_args_list[1].args[0][-1],
                             "repos/{owner}/{repo}/git/tags/" + "b" * 40)

    def test_publish_rejects_extra_before_remote_access_and_passes_exact_argv(self):
        argv = ["release_assets.py", "--directory", str(self.folder), "--publish", "v0.1.0"]
        extra = self.folder / "unreviewed.exe"
        extra.write_bytes(b"do not publish")
        with patch.object(release_assets, "current_version", return_value=self.version), \
                patch("sys.argv", argv), \
                patch.object(release_assets.subprocess, "check_output", side_effect=["a" * 40, ""]), \
                patch.object(release_assets, "verify_remote_tag") as remote, \
                patch.object(release_assets.subprocess, "run") as publish:
            with self.assertRaisesRegex(ValueError, "Unexpected release output"):
                release_assets.main()
            remote.assert_not_called()
            publish.assert_not_called()
        extra.unlink()
        with patch.object(release_assets, "current_version", return_value=self.version), \
                patch("sys.argv", argv), \
                patch.object(release_assets.subprocess, "check_output", side_effect=["a" * 40, ""]), \
                patch.object(release_assets, "verify_remote_tag") as remote, \
                patch.object(release_assets.subprocess, "run") as publish:
            release_assets.main()
            remote.assert_called_once_with("v0.1.0", "a" * 40)
            arguments = publish.call_args.args[0]
            self.assertEqual(arguments[4:10], [str(self.folder / name) for name in asset_names(self.version)])
            self.assertNotIn("*", " ".join(arguments))

    def test_license_collection_rejects_stale_unreviewed_file(self):
        from scripts.build_release import collect_licenses

        staging = self.folder / "licenses"
        staging.mkdir()
        sentinel = staging / "DO-NOT-SHIP-private-wallet.txt"
        sentinel.write_text("synthetic sentinel", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "License staging must be empty"):
            collect_licenses(staging)
        self.assertEqual(sentinel.read_text(), "synthetic sentinel")


if __name__ == "__main__":
    unittest.main()
