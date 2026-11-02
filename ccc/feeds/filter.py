# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zyenra Security
"""Evaluate match rules and run extract specs against feed entries."""
from __future__ import annotations

import re

from ccc.feeds.config import ExtractRule, MatchCondition, MatchRule
from ccc.feeds.fetch import FeedEntry


def entry_matches(entry: FeedEntry, rule: MatchRule | None) -> bool:
    """True if the entry passes the rule. No rule = always true (alert-all).

    When both `all` and `any` are present, BOTH must hold.
    """
    if rule is None:
        return True
    if rule.all is not None and not all(_cond(entry, c) for c in rule.all):
        return False
    if rule.any is not None and not any(_cond(entry, c) for c in rule.any):
        return False
    return True


def _cond(entry: FeedEntry, c: MatchCondition) -> bool:
    value = entry.field_value(c.field)
    if c.contains is not None:
        low = value.lower()
        return any(term.lower() in low for term in c.contains)
    if c.regex is not None:
        return re.search(c.regex, value) is not None
    if c.equals is not None:
        return value == c.equals
    return False


def run_extracts(
    entry: FeedEntry, specs: dict[str, ExtractRule]
) -> dict[str, list[str]]:
    """Apply each extract spec, returning {name: [match, ...]} (de-duplicated,
    order-stable)."""
    out: dict[str, list[str]] = {}
    for name, spec in specs.items():
        value = entry.field_value(spec.from_)
        seen: list[str] = []
        # Use finditer + group(0) so the whole match is captured regardless of
        # whether the pattern contains capture groups.
        for m in re.finditer(spec.regex, value):
            token = m.group(0)
            if token and token not in seen:
                seen.append(token)
        out[name] = seen
    return out
