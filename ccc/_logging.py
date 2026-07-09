# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Logging setup for ccc.

One logger named "ccc" is configured by `configure()` (called once from
`cli.main`). Every module uses `from ccc._logging import log` and calls
`log.info(...)` / `log.warning(...)` / `log.error(...)`. Output goes to
stderr by default so stdout stays clean for any future machine-readable
output (audit dumps, status JSON, etc.).

Format is intentionally plain - this is a cron tool whose logs land in
journald or a log file, both of which add their own timestamps. The
operator can flip --verbose to see DEBUG-level events.
"""
from __future__ import annotations

import logging
import sys

log = logging.getLogger("ccc")


def configure(verbose: bool = False) -> None:
    """Wire up the ccc logger once.

    Safe to call multiple times; subsequent calls just adjust the level.
    Designed to be invoked from `cli.main()` and from test fixtures.
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Idempotent: if a handler is already attached (test re-entry, repeated
    # cli invocations in same process), reuse it instead of stacking.
    if log.handlers:
        log.setLevel(level)
        for h in log.handlers:
            h.setLevel(level)
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("ccc: %(levelname)s: %(message)s"))
    log.addHandler(handler)
    log.setLevel(level)
    # Don't bubble up to root - cron may have weird handlers attached.
    log.propagate = False
