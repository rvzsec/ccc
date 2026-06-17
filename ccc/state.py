"""Persistent state - three flat files, no database.

state_dir/
├── ccc.lock        # flock handle (managed by lock.py)
├── last_run.txt    # single ISO-8601 UTC timestamp of last SUCCESSFUL run
├── recent.json     # {cve_id: {hash, seen_at}} - rotated at 14 days
└── audit.jsonl     # append-only log of every alert sent

If last_run.txt is missing or stale, we cap lookback at config.max_lookback_hours.
If recent.json is corrupt, we log + treat as empty (worst case: one bonus alert).
All writes are atomic via os.replace.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ccc._logging import log

# Hash cache rotation: entries older than this are pruned on every write.
RECENT_TTL = timedelta(days=14)


# ---------- last_run.txt ----------

def read_last_run(state_dir: Path) -> datetime | None:
    """Return last successful run timestamp (UTC) or None."""
    path = state_dir / "last_run.txt"
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OSError) as e:
        log.warning("bad last_run.txt (%s), treating as missing", e)
        return None


def write_last_run(state_dir: Path, ts: datetime) -> None:
    """Atomically write last_run.txt. Call ONLY on successful poll cycle."""
    state_dir.mkdir(parents=True, exist_ok=True)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    _atomic_write(state_dir / "last_run.txt", ts.isoformat(timespec="seconds"))


def compute_window(
    state_dir: Path,
    now: datetime,
    overlap_minutes: int,
    max_lookback_hours: int,
) -> tuple[datetime, datetime]:
    """Compute (start, end) for NVD lastModStartDate window.

    start = max(last_run - overlap, now - max_lookback)
    end   = now
    """
    last = read_last_run(state_dir)
    floor = now - timedelta(hours=max_lookback_hours)
    if last is None:
        start = floor
    else:
        start = last - timedelta(minutes=overlap_minutes)
        if start < floor:
            start = floor
    return (start, now)


# ---------- recent.json (hash cache) ----------

def _hash_alert(
    cve_id: str,
    cvss_score: float | None,
    kev: bool,
    epss: float | None,
    vuln_status: str,  # accepted for signature stability, intentionally ignored
) -> str:
    """Hash the alert-significant fields. Re-alert only when this changes.

    Oracle audit A4: vuln_status is excluded from the hash. NVD oscillates
    CVE entries between 'Modified' and 'Analyzed' as analysts re-touch them
    with no semantic change, which would otherwise fire pointless [UPDATED]
    re-alerts (or, with alert_on_update=false, silently overwrite the hash
    and mask a real later change).
    """
    # EPSS is bucketed (1 decimal) so 0.51->0.52 noise doesn't trigger UPDATED.
    epss_bucket = "" if epss is None else f"{round(epss, 1):.1f}"
    cvss_str = "" if cvss_score is None else f"{cvss_score:.1f}"
    payload = f"{cve_id}|{cvss_str}|{int(kev)}|{epss_bucket}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def load_recent(state_dir: Path) -> dict[str, dict[str, Any]]:
    """Load recent.json. Returns empty dict on missing/corrupt."""
    path = state_dir / "recent.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("recent.json root is not a dict")
        return data
    except (json.JSONDecodeError, ValueError, OSError) as e:
        log.warning("recent.json corrupt (%s), starting fresh", e)
        return {}


def save_recent(state_dir: Path, recent: dict[str, dict[str, Any]], now: datetime) -> None:
    """Atomically write recent.json after rotating stale entries."""
    cutoff = now - RECENT_TTL
    cutoff_iso = cutoff.isoformat()
    pruned = {
        cve: entry
        for cve, entry in recent.items()
        if entry.get("seen_at", "") >= cutoff_iso
    }
    state_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(state_dir / "recent.json", json.dumps(pruned, indent=2, sort_keys=True))


def check_and_mark(
    recent: dict[str, dict[str, Any]],
    cve_id: str,
    cvss_score: float | None,
    kev: bool,
    epss: float | None,
    vuln_status: str,
    now: datetime,
) -> tuple[bool, bool]:
    """Check if this CVE-state was already alerted.

    Returns (should_alert, is_update):
      (True,  False) → never seen, fresh alert
      (True,  True)  → seen but hash changed, re-alert with [UPDATED] tag
      (False, False) → seen with same hash, suppress

    Mutates `recent` in-place to record the new hash + timestamp.
    """
    h = _hash_alert(cve_id, cvss_score, kev, epss, vuln_status)
    prev = recent.get(cve_id)
    if prev is None:
        recent[cve_id] = {"hash": h, "seen_at": now.isoformat()}
        return (True, False)
    if prev.get("hash") == h:
        return (False, False)
    # Hash changed → material update worth re-alerting.
    recent[cve_id] = {"hash": h, "seen_at": now.isoformat()}
    return (True, True)


# ---------- audit.jsonl ----------

# Rotate audit.jsonl when it crosses this size. Keep AUDIT_BACKUPS old files.
# At typical volume (a few alerts/hr) the live file stays well below 10 MB
# even across years. Rotation is a safety net for high-volume tenants.
AUDIT_MAX_BYTES = 10 * 1024 * 1024
AUDIT_BACKUPS = 5


def audit_alert(state_dir: Path, entry: dict[str, Any]) -> None:
    """Append-only audit log. One JSON object per line.

    Rotates when the live file exceeds AUDIT_MAX_BYTES (10 MB by default),
    keeping AUDIT_BACKUPS (5) older generations as audit.jsonl.1 ... .5.
    Oldest beyond AUDIT_BACKUPS is unlinked.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "audit.jsonl"
    _maybe_rotate_audit(path)
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    # Append is atomic for line-sized writes on local FS.
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _maybe_rotate_audit(path: Path) -> None:
    """Shift audit.jsonl -> .1 -> .2 -> ... -> .N when size cap is hit."""
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < AUDIT_MAX_BYTES:
        return
    # Drop the oldest.
    oldest = path.with_suffix(path.suffix + f".{AUDIT_BACKUPS}")
    try:
        oldest.unlink()
    except OSError:
        pass
    # Shift each backup up one slot.
    for i in range(AUDIT_BACKUPS - 1, 0, -1):
        src = path.with_suffix(path.suffix + f".{i}")
        dst = path.with_suffix(path.suffix + f".{i + 1}")
        if src.exists():
            try:
                os.replace(src, dst)
            except OSError:
                pass
    # Move current live file into .1
    try:
        os.replace(path, path.with_suffix(path.suffix + ".1"))
    except OSError:
        pass


# ---------- helpers ----------

def _atomic_write(target: Path, content: str) -> None:
    """Write to temp + os.replace + parent dir fsync. Crash-durable.

    POSIX `rename`/`replace` is atomic for the directory entry but the entry
    update itself is not durable until the parent directory's metadata is
    fsynced. Power loss between os.replace and the next dir flush can revert
    the rename on ext4 without data=journal. Oracle audit E1.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
        # Durability barrier on parent directory entry.
        try:
            dir_fd = os.open(str(target.parent), os.O_DIRECTORY)
        except OSError:
            return  # platform doesn't support O_DIRECTORY; replace is the best we can do
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
