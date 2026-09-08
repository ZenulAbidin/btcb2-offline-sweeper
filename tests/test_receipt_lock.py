"""Regression tests for a crash leaving a permanently blocked broadcast."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from btcb2_tui.receipt_lock import ReceiptLock


class ReceiptLockTests(unittest.TestCase):
    def test_os_releases_lock_after_abrupt_process_exit(self):
        with tempfile.TemporaryDirectory() as name:
            # Windows venv python.exe can be a redirector that launches another
            # interpreter. Kill the actual lock owner, not only that launcher.
            process = subprocess.Popen([sys._base_executable, "-c",
                "from btcb2_tui.receipt_lock import ReceiptLock; import os, sys; "
                "lock=ReceiptLock(sys.argv[1]); assert lock.acquire(); "
                "print('LOCKED',os.getpid(),flush=True); sys.stdin.read()", name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), f"LOCKED {process.pid}")
                lock = ReceiptLock(name)
                self.assertFalse(lock.acquire())
                process.kill()
                process.wait(timeout=10)
                self.assertTrue((Path(name) / ".broadcast.lock").exists())
                self.assertTrue(lock.acquire())
                lock.release()
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)

    def test_existing_stale_lock_file_is_safe_to_reuse(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / ".broadcast.lock"
            path.write_bytes(b"")
            first, second = ReceiptLock(name), ReceiptLock(name)
            try:
                self.assertTrue(first.acquire())
                self.assertFalse(second.acquire())
                first.release()
                self.assertTrue(second.acquire())
            finally:
                first.release()
                second.release()


if __name__ == "__main__":
    unittest.main()
