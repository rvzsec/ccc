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

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ccc._logging import log
from ccc.config import Config, Product
from ccc.enrich import EnrichError, fetch_epss, fetch_kev
from ccc.matcher import Match, find_matches
from ccc.notifier import NotifyError, send_alert, send_batch_alert
from ccc.nvd import NvdClient, NvdError
from ccc.state import (
    audit_alert,
    check_and_mark,
    compute_window,
    load_recent,
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

    Already-sent CVEs are durable on disk; the failing CVE's hash is rolled
    back; next run retries it. last_run NOT advanced.
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

    if not cves:
        if not dry_run:
            write_last_run(cfg.state_dir, now)
        log.info("nothing in window; last_run advanced.")
        return report

    # 2. enrich
    try:
        kev_map = fetch_kev(cfg.state_dir)
    except EnrichError as e:
        raise EnrichFailure(f"KEV failure: {e}") from e
    epss_map = fetch_epss([c.cve_id for c in cves])

    # 3. match + gate
    matches = find_matches(cves, products, cfg, kev_map, epss_map)
    report.matched = len(matches)
    log.info("%d CVE(s) matched products and passed gate", len(matches))

    if not matches:
        if not dry_run:
            write_last_run(cfg.state_dir, now)
        return report

    # 4. dedup + alert
    recent = load_recent(cfg.state_dir)
    url = webhook_url if webhook_url is not None else str(cfg.google_chat_webhook)

    # Separate matches into individual-alert and batch-digest queues.
    # A CVE that matches both individual and batch products gets BOTH an
    # individual alert AND appears in batch digests. Dedup hash is shared
    # so rollback on batch failure only affects batch-ONLY CVEs.
    individual_queue: list[tuple[Match, bool]] = []  # (match, is_update)
    batch_groups: dict[str, list[tuple[Match, bool]]] = defaultdict(list)
    batch_only_ids: set[str] = set()  # CVEs with NO individual-mode products

    for m in matches:
        should_alert, is_update = check_and_mark(
            recent,
            m.cve.cve_id,
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

        batch_products = [p for p in m.products if p.alert_mode == "batch"]
        individual_products = [p for p in m.products if p.alert_mode == "individual"]

        if individual_products:
            individual_queue.append((m, is_update))
        if batch_products:
            for bp in batch_products:
                batch_groups[bp.name].append((m, is_update))
            if not individual_products:
                batch_only_ids.add(m.cve.cve_id)

    delivery_error: DeliveryFailure | None = None

    # --- individual alerts (existing flow, one cardsV2 per CVE) ---
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

    # --- batch digests (one cardsV2 per product) ---
    if delivery_error is None:
        for product_name, batch_entries in batch_groups.items():
            # Unpack matches from (match, is_update) tuples for the notifier.
            batch_matches = [m for m, _ in batch_entries]
            try:
                send_batch_alert(url, product_name, batch_matches, dry_run=dry_run)
            except NotifyError as e:
                log.error(
                    "batch webhook FAILED for %s (%d CVEs): %s",
                    product_name, len(batch_matches), e,
                )
                # Roll back batch-ONLY CVEs (individual CVEs already persisted).
                rolled = 0
                for bm in batch_matches:
                    if bm.cve.cve_id in batch_only_ids:
                        recent.pop(bm.cve.cve_id, None)
                        rolled += 1
                if rolled:
                    try:
                        save_recent(cfg.state_dir, recent, now)
                    except OSError as save_err:
                        log.warning(
                            "save_recent failed during batch rollback: %s", save_err
                        )
                delivery_error = DeliveryFailure(
                    f"batch webhook failed for {product_name}: {e}"
                )
                break

            # Persist after each successful batch to protect against mid-batch crash.
            try:
                save_recent(cfg.state_dir, recent, now)
            except OSError as save_err:
                log.error(
                    "state save FAILED after batch digest for %s: %s",
                    product_name, save_err,
                )
                delivery_error = DeliveryFailure(
                    f"state save failed after batch {product_name}: {save_err}"
                )
                break

            report.batch_digests += 1
            report.batch_individual += len(batch_matches)

            for bm, bm_is_update in batch_entries:
                _audit_one(cfg, bm.cve, bm_is_update, bm.kev, bm.epss, bm, now, dry_run)

    log.info(report.summary_line + f" dry_run={dry_run}")

    if delivery_error is not None:
        raise delivery_error

    if not dry_run:
        write_last_run(cfg.state_dir, now)

    return report
