"""Single-instance guard via fcntl.flock.

Second invocation while another is running → exit 0 (silent, not an error).
Kernel releases the lock automatically when the process dies (crash, SIGKILL, OOM).
No stale-lock cleanup needed - POSIX guarantees release on fd close.
"""
from __future__ import annotations

import fcntl
import os
import sys
from pathlib import Path
from typing import NoReturn

from ccc._logging import log


class LockHandle:
    """Holds the lock fd for the process lifetime. DO NOT close until exit."""

    __slots__ = ("fd", "path")

    def __init__(self, fd: int, path: Path) -> None:
        self.fd = fd
        self.path = path

    def release(self) -> None:
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


def acquire_or_exit(lock_path: Path) -> LockHandle:
    """Acquire exclusive non-blocking lock. Exit 0 if another instance holds it."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        _exit_silent()
    # Write our PID for debuggability. Not used for correctness.
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    except OSError:
        pass
    return LockHandle(fd, lock_path)


def _exit_silent() -> NoReturn:
    log.info("another instance is running, exiting")
    sys.exit(0)
