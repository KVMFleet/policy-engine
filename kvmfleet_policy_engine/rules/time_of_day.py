"""Allow only during configured weekly windows.

rule_data shape:
  {
    "tz": "Europe/Malta",           # IANA timezone name
    "allowed_windows": [
      {"days": ["mon", "tue", ...], "start": "09:00", "end": "17:00"},
      ...
    ],
    "target_tags": ["production"],  # optional; empty = all devices
    "target_actions": ["console.start"]  # optional; empty = all actions
  }

Outside any allowed window for the current weekday → rule fires.
Inside any window → rule does not fire.

Time math uses zoneinfo. If `tz` is missing or invalid, UTC is used.
"""
from __future__ import annotations

from datetime import UTC, datetime, time
from typing import Any
from zoneinfo import ZoneInfo

from kvmfleet_policy_engine.rules._filters import filters_match
from kvmfleet_policy_engine.types import EvalContext

_WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def apply(rule_data: dict[str, Any], context: EvalContext) -> str | None:
    if not filters_match(rule_data, context.action, context.device_tags):
        return None

    tz_name = rule_data.get("tz") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        # An invalid tz string falls back to UTC rather than crashing
        # the whole evaluation. The platform UI should still validate at
        # config-save time so this branch is defensive only.
        tz = ZoneInfo("UTC")

    base = context.now or datetime.now(UTC)
    if base.tzinfo is None:
        # Naive datetime — treat as UTC to avoid the
        # "local-time-of-the-process" trap.
        base = base.replace(tzinfo=UTC)
    now_local = base.astimezone(tz)

    weekday = _WEEKDAYS[now_local.weekday()]
    current = now_local.time()

    in_window = False
    for w in rule_data.get("allowed_windows") or []:
        if weekday not in (w.get("days") or []):
            continue
        try:
            start = _parse_hhmm(w["start"])
            end = _parse_hhmm(w["end"])
        except (KeyError, ValueError):
            continue
        if start <= current <= end:
            in_window = True
            break

    if in_window:
        return None

    target_tags = rule_data.get("target_tags") or []
    tag_clause = (
        f" (device tags: {', '.join(target_tags)})" if target_tags else ""
    )
    return (
        f"Outside allowed window for this device{tag_clause}. "
        f"Local time {now_local.strftime('%a %H:%M %Z')}."
    )


def _parse_hhmm(s: str) -> time:
    hh, mm = s.split(":")
    return time(hour=int(hh), minute=int(mm))
