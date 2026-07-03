"""C³ CLI entry point.

Subcommands:
  run            - one poll cycle (the cron/systemd entry)
  test-webhook   - send a fake card to verify Google Chat webhook
  version        - print version + brand

Exit codes:
  0  success (or another instance is running)
  1  config / usage error
  2  NVD API failure  (last_run NOT advanced - next run retries window)
  3  webhook failure  (last_run NOT advanced - next run retries window)
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from ccc import __brand__, __version__
from ccc._logging import configure as configure_logging
from ccc.config import AlertMode, Config, Product, build_product, load_config, load_raw_products
from ccc.notifier import NotifyError, send_test
from ccc.resolver import ResolveError, resolve_names
from ccc.lock import acquire_or_exit
from ccc.runner import RunnerError, run_once

DEFAULT_CONFIG = Path(
    os.environ.get("CCC_CONFIG", str(Path.home() / ".config/ccc/config.yaml"))
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name=f"ccc ({__brand__})")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable DEBUG-level logging on stderr.",
)
def main(verbose: bool) -> None:
    """C³ - Continuous CVE Coverage. Polls NVD for matches and alerts Google Chat."""
    configure_logging(verbose=verbose)


@main.command("version")
def version_cmd() -> None:
    """Print version."""
    click.echo(f"ccc ({__brand__}) {__version__}")


@main.command("run")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_CONFIG,
    show_default=True,
    help="Path to config.yaml.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print alerts to stdout. Send NOTHING. State is still updated.",
)
def run_cmd(config_path: Path, dry_run: bool) -> None:
    """One poll cycle. Designed to be called by cron / systemd timer."""
    cfg = _load_or_die(config_path)
    products = _load_products_or_die(cfg)

    # Acquire lock BEFORE any I/O. Released on process exit.
    lock = acquire_or_exit(cfg.state_dir / "ccc.lock")
    try:
        run_once(cfg, products, dry_run)
    except RunnerError as e:
        click.echo(f"ccc: {e}", err=True)
        sys.exit(e.exit_code)
    finally:
        lock.release()


@main.command("validate")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_CONFIG,
    show_default=True,
)
def validate_cmd(config_path: Path) -> None:
    """Validate config + products without running a poll.

    Loads config.yaml (catches misspelled keys, bad webhook, etc.) and
    resolves every product name to a CPE (catches typos, ambiguous names,
    NVD-unknown products). Cached resolutions are instant; uncached names
    hit NVD with 6s pacing. Exits 0 if everything's valid, 1 otherwise.
    """
    cfg = _load_or_die(config_path)
    products = _load_products_or_die(cfg)

    # Catch the obvious "operator never edited the example webhook" case.
    # Pydantic accepts the placeholder URL as syntactically valid; real
    # delivery later fails with HTTP 400 / API_KEY_INVALID.
    webhook = str(cfg.google_chat_webhook)
    placeholder_signals = ("AAAA", "key=...", "token=...", "X/messages")
    if any(s in webhook for s in placeholder_signals):
        click.echo("")
        click.echo(
            "ccc: WARN: google_chat_webhook looks like the example placeholder. "
            "Edit config/config.yaml and paste your real Incoming Webhook URL "
            "from your Chat space (Apps & integrations -> Webhooks).",
            err=True,
        )
        sys.exit(1)

    click.echo("")
    click.echo(f"ccc: validation OK. {len(products)} product(s) ready to monitor:")
    for p in products:
        click.echo(f"  - {p.name}  ->  {p.cpe}")
    click.echo("")
    click.echo("Config + webhook URL syntax also valid (webhook deliverability")
    click.echo("not tested here; use 'ccc test-webhook' for that).")


@main.command("test-webhook")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=DEFAULT_CONFIG,
    show_default=True,
)
@click.option("--dry-run", is_flag=True, default=False)
def test_webhook_cmd(config_path: Path, dry_run: bool) -> None:
    """Send a fake card to verify the webhook works."""
    cfg = _load_or_die(config_path)
    try:
        send_test(str(cfg.google_chat_webhook), dry_run=dry_run)
        click.echo("ccc: webhook test " + ("dry-run OK." if dry_run else "delivered."))
    except NotifyError as e:
        click.echo(f"ccc: webhook test FAILED: {e}", err=True)
        sys.exit(3)


# ---------- helpers ----------
# Orchestration moved to ccc/runner.py. cli.py only handles argparse,
# config loading, lock acquisition, and exit-code mapping.

def _load_or_die(path: Path) -> Config:
    try:
        return load_config(path)
    except FileNotFoundError:
        click.echo(f"ccc: config not found: {path}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ccc: config invalid ({path}): {e}", err=True)
        sys.exit(1)


def _load_products_or_die(cfg: Config) -> list[Product]:
    """Load products.yaml and resolve plain-name entries to CPEs.

    Each entry is either a plain string (auto-resolved via NVD CPE API
    + on-disk cache) or a full {name, cpe} dict (operator override).
    Resolution failure aborts startup with a helpful message.
    """
    path = cfg.products_file
    try:
        raw_entries = load_raw_products(path)
    except FileNotFoundError:
        click.echo(f"ccc: products file not found: {path}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"ccc: products invalid ({path}): {e}", err=True)
        sys.exit(1)

    # Split entries: plain strings need resolution, dicts pass through.
    plain_names: list[str] = []
    direct_entries: list[tuple[str, str, AlertMode]] = []  # (name, cpe, alert_mode)
    for entry in raw_entries:
        if isinstance(entry, str):
            plain_names.append(entry)
        else:
            direct_entries.append((
                entry["name"],
                entry["cpe"],
                entry.get("alert_mode", "individual"),
            ))

    # Resolve plain names via NVD + cache.
    resolutions = []
    if plain_names:
        try:
            resolutions = resolve_names(
                plain_names,
                state_dir=cfg.state_dir,
                nvd_api_key=cfg.nvd_api_key,
            )
        except ResolveError as e:
            click.echo(f"ccc: CPE resolution failed:\n{e}", err=True)
            sys.exit(1)

        # Show operator what resolved to what so they can sanity-check.
        for r in resolutions:
            tag = "[cached]" if r.source == "cache" else "[NVD]"
            click.echo(f"ccc: resolved {tag} {r.name!r} -> {r.cpe}")

    products: list[Product] = []
    for r in resolutions:
        try:
            products.append(build_product(r.name, r.cpe))
        except Exception as e:
            click.echo(
                f"ccc: resolved CPE for {r.name!r} failed validation: {e}",
                err=True,
            )
            sys.exit(1)
    for name, cpe, alert_mode in direct_entries:
        try:
            products.append(build_product(name, cpe, alert_mode))
        except Exception as e:
            click.echo(f"ccc: override CPE {cpe!r} invalid: {e}", err=True)
            sys.exit(1)

    if not products:
        click.echo("ccc: products list is empty", err=True)
        sys.exit(1)
    return products


if __name__ == "__main__":
    main()
