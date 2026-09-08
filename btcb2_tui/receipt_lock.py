"""Process-owned receipt locks; the OS releases ownership even after a crash."""
import errno
import os
from pathlib import Path
import stat


class ReceiptLock:
    """Nonblocking lock. Keep its inode: deleting a lock file creates a race."""

    def __init__(self, folder):
        self.path = Path(folder) / ".broadcast.lock"
        self.fd = None

    def acquire(self):
        if self.path.is_symlink():
            raise ValueError("Receipt lock must be a regular file.")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Receipt lock must be a regular file.")
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = fd
            return True
        except OSError as error:
            os.close(fd)
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                return False
            raise
        except BaseException:
            os.close(fd)
            raise

    def release(self):
        if self.fd is not None:
            # Closing releases the lock on Windows and POSIX. Do not unlink.
            os.close(self.fd)
            self.fd = None
