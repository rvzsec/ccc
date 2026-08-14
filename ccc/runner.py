# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""One poll cycle.

Pure orchestration: fetch -> enrich -> match -> dedup -> alert -> persist.
No `click`, no `sys.exit`, no stdout writes. Returns a `RunReport` or raises
a typed exception that `cli.py` translates into an exit code.

This is the seam between "what does ccc do" (here) and "what's the CLI
contract" (cli.py).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ccc._logging import log
from ccc.config import BatchPeriod, Config, Product
from ccc.enrich import EnrichError, fetch_epss, fetch_kev
from ccc.matcher import Match, find_matches
from ccc.notifier import (
    NotifyError,
    match_to_entry,
    send_alert,
    send_digest_alert,
)
from ccc.nvd import NvdClient, NvdError
from ccc.state import (
    audit_alert,
    check_and_mark,
    compute_window,
    hash_alert,
    load_pending,
    load_recent,
    save_pending,
    save_recent,
    write_last_run,
)


@dataclass
class RunReport:
    """Result of one poll cycle. The CLI prints this; tests assert on it."""

    cves_fetched: int = 0
    matched: int = 0
    sent: int = 0
    updated: int = 0
    suppressed: int = 0
    batch_digests: int = 0
    batch_individual: int = 0
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def summary_line(self) -> str:
        parts = [f"sent={self.sent}", f"updated={self.updated}", f"suppressed={self.suppressed}"]
        if self.batch_digests:
            parts.append(f"batch_digests={self.batch_digests}")
            parts.append(f"batch_cves={self.batch_individual}")
        return " ".join(parts)


class RunnerError(Exception):
    """Base for runner failures the CLI translates to non-zero exits."""

    exit_code: int = 1


class NvdFailure(RunnerError):
    """NVD fetch failed; do NOT advance last_run; next run retries window."""

    exit_code = 2


class EnrichFailure(RunnerError):
    """KEV enrichment failed and no usable cache; do NOT advance last_run."""

    exit_code = 2


class DeliveryFailure(RunnerError):
    """Webhook (or post-webhook state save) failed mid-batch.

    Already-sent individual CVEs are durable on disk; the failing CVE's hash
    is rolled back so the next run retries it. Accumulated digest entries
    stay in pending_batches.json so a failed (or never-attempted) flush is
    retried on the next run. last_run NOT advanced.
    """

    exit_code = 3


def _audit_one(
    cfg: Config,
    cve: Any,
    is_update: bool,
    kev: bool,
    epss: float | None,
    match: Any,
    now: datetime,
    dry_run: bool,
) -> None:
    """Audit-log one alert (best-effort, disk-full must not block)."""
    try:
        audit_alert(
            cfg.state_dir,
            {
                "ts": now.isoformat(timespec="seconds"),
                "cve": cve.cve_id,
                "is_update": is_update,
                "kev": kev,
                "epss": epss,
                "cvss": cve.cvss_score,
                "severity": cve.cvss_severity,
                "products": [p.name for p in match.products],
                "dry_run": dry_run,
            },
        )
    except OSError as audit_err:
        log.warning("audit log write failed for %s: %s", cve.cve_id, audit_err)


def _audit_digest(
    cfg: Config,
    tier_name: str,
    entry: dict[str, Any],
    now: datetime,
    dry_run: bool,
) -> None:
    """Audit-log one tier-digest entry (best-effort, disk-full must not block)."""
    try:
        audit_alert(
            cfg.state_dir,
            {
                "ts": now.isoformat(timespec="seconds"),
                "cve": entry["cve_id"],
                "is_update": False,
                "kev": bool(entry.get("kev")),
                "epss": entry.get("epss"),
                "cvss": entry.get("cvss_score"),
                "severity": entry.get("severity"),
                "products": entry.get("products") or [tier_name],
                "tier": tier_name,
                "digest": True,
                "dry_run": dry_run,
            },
        )
    except OSError as audit_err:
        log.warning("audit log write failed for %s: %s", entry["cve_id"], audit_err)


def _period_delta(period: BatchPeriod) -> timedelta:
    """Digest cadence -> timedelta. daily = 1 day, weekly = 7 days."""
    return timedelta(days=7) if period == "weekly" else timedelta(days=1)


def _bucket_period(period_map: dict[str, BatchPeriod], name: str) -> BatchPeriod:
    """Effective digest period for a tier bucket (defaults to daily)."""
    p = period_map.get(name)
    return p if p is not None else "daily"


def run_once(
    cfg: Config,
    products: list[Product],
    dry_run: bool,
    webhook_url: str | None = None,
) -> RunReport:
    """Execute one poll cycle.

    `webhook_url` defaults to `str(cfg.google_chat_webhook)` - extracted as
    a parameter so tests can drive the runner without a real URL.
    """
    now = datetime.now(timezone.utc)
    start, end = compute_window(
        cfg.state_dir,
        now,
        overlap_minutes=cfg.poll_overlap_minutes,
        max_lookback_hours=cfg.max_lookback_hours,
    )
    report = RunReport(window_start=start, window_end=end)

    log.info(
        "window %s -> %s (%.1fh)",
        start.isoformat(timespec="seconds"),
        end.isoformat(timespec="seconds"),
        (end - start).total_seconds() / 3600,
    )

    # 1. fetch NVD
    cves = []
    try:
        with NvdClient(api_key=cfg.nvd_api_key) as client:
            for cve in client.fetch_window(start, end):
                cves.append(cve)
    except NvdError as e:
        raise NvdFailure(f"NVD failure: {e}") from e

    report.cves_fetched = len(cves)
    log.info("NVD returned %d CVE(s) in window", len(cves))

    # 2. enrich + match + gate (skipped entirely on an empty window)
    matches: list[Match] = []
    if cves:
        try:
            kev_map = fetch_kev(cfg.state_dir)
        except EnrichError as e:
            raise EnrichFailure(f"KEV failure: {e}") from e
        epss_map = fetch_epss([c.cve_id for c in cves])
        matches = find_matches(cves, products, cfg, kev_map, epss_map)
    report.matched = len(matches)
    log.info("%d CVE(s) matched products and passed gate", len(matches))

    # 3. delivery phase - runs even with zero matches so accumulated
    #    digests still flush when their period comes due.
    recent = load_recent(cfg.state_dir)
    pending = load_pending(cfg.state_dir)
    # Drop buckets for tiers that no longer exist in config.
    valid_tiers = {p.category for p in products}
    for stale in [n for n in pending if n not in valid_tiers]:
        del pending[stale]

    url = webhook_url if webhook_url is not None else str(cfg.google_chat_webhook)
    # Batch period + accent color + display label come from the product's
    # category; every product in a tier shares them, so lookups are keyed by
    # tier name.
    period_map: dict[str, BatchPeriod] = {p.category: p.batch_period for p in products}
    accent_map: dict[str, str | None] = {p.category: p.accent_color for p in products}
    label_map: dict[str, str | None] = {}
    for p in products:
        if p.category not in label_map:
            label_map[p.category] = p.category_label or p.category

    # Route each match. Individual-mode products alert immediately (one card
    # per CVE, dedup via recent.json). Batch-mode products accumulate entries
    # in pending_batches.json keyed by TIER (category) and flush as ONE digest
    # per tier when the period elapses - grouped by product inside the card.
    # A CVE matching BOTH types gets the individual alert AND a line in the
    # tier digest (mirrors the old dual behavior).
    individual_queue: list[tuple[Match, bool]] = []  # (match, is_update)

    for m in matches:
        cid = m.cve.cve_id
        cid_in_recent = cid in recent  # snapshot before individual marks it
        batch_products = [p for p in m.products if p.alert_mode == "batch"]
        individual_products = [p for p in m.products if p.alert_mode == "individual"]

        if individual_products:
            should_alert, is_update = check_and_mark(
                recent,
                cid,
                m.cve.cvss_score,
                m.kev,
                m.epss,
                m.cve.vuln_status,
                now,
            )
            if not should_alert:
                report.suppressed += 1
                continue
            # Suppress UPDATED re-alerts unless explicitly enabled in config.
            if is_update and not cfg.alert_on_update:
                report.suppressed += 1
                continue
            individual_queue.append((m, is_update))

        if not batch_products or cid_in_recent:
            # Already alerted (individual or a previous flush) - skip.
            if batch_products and cid_in_recent:
                report.suppressed += 1
            continue

        # Group the matched batch products by tier; a CVE matching products
        # in several tiers lands in each tier's digest.
        by_tier: dict[str, list[str]] = {}
        for bp in batch_products:
            by_tier.setdefault(bp.category, []).append(bp.name)

        for tier_name, prod_names in by_tier.items():
            bucket = pending.setdefault(
                tier_name, {"period_start": None, "next_due": None, "entries": []}
            )
            entry = match_to_entry(m)
            entry["products"] = sorted(prod_names)
            existing = next(
                (e for e in bucket["entries"] if e["cve_id"] == cid), None
            )
            if existing is not None:
                # NVD re-emitted the same CVE inside the window - refresh.
                existing.update(entry)
            else:
                if bucket["period_start"] is None:
                    bucket["period_start"] = now.isoformat()
                    bucket["next_due"] = (
                        now + _period_delta(_bucket_period(period_map, tier_name))
                    ).isoformat()
                bucket["entries"].append(entry)

    delivery_error: DeliveryFailure | None = None

    # --- individual alerts (one cardsV2 per CVE) ---
    for m, is_update in individual_queue:
        try:
            send_alert(url, m, is_update, dry_run=dry_run)
        except NotifyError as e:
            log.error("webhook FAILED on %s: %s", m.cve.cve_id, e)
            recent.pop(m.cve.cve_id, None)
            try:
                save_recent(cfg.state_dir, recent, now)
            except OSError as save_err:
                log.warning("save_recent failed during rollback: %s", save_err)
            delivery_error = DeliveryFailure(f"webhook failed on {m.cve.cve_id}: {e}")
            break

        try:
            save_recent(cfg.state_dir, recent, now)
        except OSError as save_err:
            log.error(
                "state save FAILED after sending %s: %s", m.cve.cve_id, save_err
            )
            delivery_error = DeliveryFailure(
                f"state save failed after webhook on {m.cve.cve_id}: {save_err}"
            )
            break

        report.sent += 1
        if is_update:
            report.updated += 1

        _audit_one(cfg, m.cve, is_update, m.kev, m.epss, m, now, dry_run)

    # --- flush due pending digests (ONE cardsV2 per tier) ---
    if delivery_error is None:
        for tier_name, bucket in pending.items():
            entries = bucket.get("entries") or []
            if not entries:
                continue
            due = (
                datetime.fromisoformat(bucket["next_due"])
                if bucket.get("next_due")
                else None
            )
            if due is None or now < due:
                continue
            try:
                send_digest_alert(
                    url, tier_name, entries,
                    dry_run=dry_run,
                    accent_color=accent_map.get(tier_name),
                    category=label_map.get(tier_name),
                )
            except NotifyError as e:
                log.error(
                    "digest webhook FAILED for %s (%d CVEs): %s",
                    tier_name, len(entries), e,
                )
                # Entries stay pending; the next run retries the flush.
                delivery_error = DeliveryFailure(
                    f"digest webhook failed for {tier_name}: {e}"
                )
                break

            # Mark flushed CVEs in recent.json so they never re-alert.
            for e in entries:
                recent[e["cve_id"]] = {
                    "hash": hash_alert(
                        e["cve_id"],
                        e.get("cvss_score"),
                        bool(e.get("kev")),
                        e.get("epss"),
                        e.get("vuln_status", ""),
                    ),
                    "seen_at": now.isoformat(),
                }
            try:
                save_recent(cfg.state_dir, recent, now)
            except OSError as save_err:
                log.error(
                    "state save FAILED after digest for %s: %s",
                    tier_name, save_err,
                )
                delivery_error = DeliveryFailure(
                    f"state save failed after digest {tier_name}: {save_err}"
                )
                break

            report.batch_digests += 1
            report.batch_individual += len(entries)
            for e in entries:
                _audit_digest(cfg, tier_name, e, now, dry_run)

            bucket["entries"] = []
            bucket["period_start"] = now.isoformat()
            bucket["next_due"] = (
                now + _period_delta(_bucket_period(period_map, tier_name))
            ).isoformat()

    # Persist pending on BOTH paths: entries added this run must survive a
    # mid-run failure, and flushed buckets are pruned by save_pending.
    try:
        save_pending(cfg.state_dir, pending)
    except OSError as save_err:
        log.error("pending state save FAILED: %s", save_err)
        if delivery_error is None:
            delivery_error = DeliveryFailure(
                f"pending state save failed: {save_err}"
            )

    log.info(report.summary_line + f" dry_run={dry_run}")

    if delivery_error is not None:
        raise delivery_error

    if not dry_run:
        write_last_run(cfg.state_dir, now)

    return report
