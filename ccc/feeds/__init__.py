# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Custom feed sources for C³.

A feed source watches an Atom/RSS feed (e.g. a vendor release/advisory feed),
filters entries with operator-defined rules, optionally extracts CVE IDs and
enriches them with NVD/KEV/EPSS signal, and alerts Google Chat when a matching
entry appears or changes.

This package is a sibling of the NVD pipeline. It reuses the L1 flock, the
Google Chat transport + HTML-escaping discipline, and the categories system,
while adding its own fetch/parse/filter/notify.
"""
