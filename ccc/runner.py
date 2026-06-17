"""One poll cycle.

Pure orchestration: fetch -> enrich -> match -> dedup -> alert -> persist.
No `click`, no `sys.exit`, no stdout writes. Returns a `RunReport` or raises
a typed exception that `cli.py` translates into an exit code.

This is the seam between "what does ccc do" (here) and "what's the CLI
contract" (cli.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ccc._logging import log
from ccc.config import Config, Product
from ccc.enrich import EnrichError, fetch_epss, fetch_kev
from ccc.matcher import find_matches
from ccc.notifier import NotifyError, send_alert
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
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def summary_line(self) -> str:
        return (
            f"sent={self.sent} updated={self.updated} "
            f"suppressed={self.suppressed}"
        )


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
    delivery_error: DeliveryFailure | None = None

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
        # Hash is still updated above so we won't re-alert next run either.
        if is_update and not cfg.alert_on_update:
            report.suppressed += 1
            continue

        try:
            send_alert(url, m, is_update, dry_run=dry_run)
        except NotifyError as e:
            log.error("webhook FAILED on %s: %s", m.cve.cve_id, e)
            # Roll back this CVE's hash entry so next run retries it.
            recent.pop(m.cve.cve_id, None)
            # Persist the rollback before we exit so the next run sees it.
            try:
                save_recent(cfg.state_dir, recent, now)
            except OSError as save_err:
                log.warning("save_recent failed during rollback: %s", save_err)
            delivery_error = DeliveryFailure(f"webhook failed on {m.cve.cve_id}: {e}")
            break

        # CRITICAL: persist BEFORE audit so a crash mid-loop never replays a
        # successfully-sent alert. Order:
        #   1. webhook sent (durable on Google's side)
        #   2. save_recent (this CVE's hash is now on disk -> never re-alerted)
        #   3. audit_alert (best-effort log; failure is non-fatal)
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

        # Audit is best-effort. Disk-full here must not block last_run advance.
        try:
            audit_alert(
                cfg.state_dir,
                {
                    "ts": now.isoformat(timespec="seconds"),
                    "cve": m.cve.cve_id,
                    "is_update": is_update,
                    "kev": m.kev,
                    "epss": m.epss,
                    "cvss": m.cve.cvss_score,
                    "severity": m.cve.cvss_severity,
                    "products": [p.name for p in m.products],
                    "dry_run": dry_run,
                },
            )
        except OSError as audit_err:
            log.warning(
                "audit log write failed for %s: %s", m.cve.cve_id, audit_err
            )

    log.info(report.summary_line + f" dry_run={dry_run}")

    if delivery_error is not None:
        raise delivery_error

    if not dry_run:
        write_last_run(cfg.state_dir, now)

    return report
