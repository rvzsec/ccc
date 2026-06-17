"""Send one realistic sample CVE alert card to verify the alert format.

Builds a Match against a real-world CVE (Log4Shell - CVE-2021-44228) with
KEV=True, high EPSS, and posts it via the same notifier.send_alert path used
by `ccc run`.

Run via:
  docker run --rm -v ./config-test:/config:ro ccc:local \
      python -m scripts.sample_alert
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make `ccc` importable when this script is executed as `python -m scripts.sample_alert`
sys.path.insert(0, "/app")

from ccc.config import Product, load_config
from ccc.matcher import Match
from ccc.notifier import NotifyError, send_alert
from ccc.nvd import CpeMatch, NvdCve


def build_sample_match() -> Match:
    cve = NvdCve(
        cve_id="CVE-2021-44228",
        published=datetime(2021, 12, 10, 10, 15, tzinfo=timezone.utc),
        last_modified=datetime(2024, 11, 21, 1, 22, tzinfo=timezone.utc),
        vuln_status="Modified",
        description=(
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases "
            "2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log "
            "messages, and parameters do not protect against attacker controlled "
            "LDAP and other JNDI related endpoints. An attacker who can control "
            "log messages or log message parameters can execute arbitrary code "
            "loaded from LDAP servers when message lookup substitution is enabled. "
            "From log4j 2.15.0, this behavior has been disabled by default."
        ),
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cpes=[
            CpeMatch(
                cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                vulnerable=True,
            )
        ],
        references=[
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://www.cisa.gov/news-events/alerts/2021/12/10/apache-releases-log4j-version-2150-address-critical-rce-vulnerability",
        ],
        cwes=["CWE-502", "CWE-20"],   # real CWEs NVD assigned to Log4Shell
    )
    product = Product(
        name="Apache Log4j",
        cpe="cpe:2.3:a:apache:log4j:*",
    )
    return Match(
        cve=cve,
        products=[product],
        epss=0.97565,  # real EPSS for Log4Shell, ~97.6th percentile
        kev=True,
        kev_name="Apache Log4j2 Remote Code Execution Vulnerability",  # real CISA-curated title
    )


def main() -> int:
    cfg_path = Path(os.environ.get("CCC_CONFIG", "/config/config.yaml"))
    cfg = load_config(cfg_path)
    match = build_sample_match()

    print("ccc: sending sample alert for CVE-2021-44228 (Log4Shell)")
    try:
        # is_update=False -> no [UPDATED] tag; this is what a fresh alert looks like.
        send_alert(str(cfg.google_chat_webhook), match, is_update=False, dry_run=False)
    except NotifyError as e:
        print(f"ccc: FAILED: {e}", file=sys.stderr)
        return 3
    print("ccc: sample alert delivered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
