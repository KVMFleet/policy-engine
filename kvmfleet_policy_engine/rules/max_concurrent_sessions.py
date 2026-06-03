"""Cap a user's simultaneous privileged sessions.

rule_data shape:
  {
    "max_sessions": 1,                           # int >= 1
    "target_tags": [...], "target_actions": [...]  # standard filters
  }

Fires when the user's current open-session count meets or exceeds
`max_sessions`. The session-about-to-be-created is NOT counted, so
`max_sessions=1` means "no second concurrent session" (i.e., must
close the existing one first).

`open_session_count is None` (caller didn't provide it): rule SKIPS.
`max_sessions <= 0` or non-integer: rule SKIPS.

Typical use case: SOC 2 / NIST 800-53 controls that require "one
privileged session at a time" per user.
"""
from __future__ import annotations

from typing import Any

from kvmfleet_policy_engine.rules._filters import filters_match
from kvmfleet_policy_engine.types import EvalContext


def apply(rule_data: dict[str, Any], context: EvalContext) -> str | None:
    if not filters_match(rule_data, context.action, context.device_tags):
        return None
    try:
        limit = int(rule_data.get("max_sessions", 0))
    except (TypeError, ValueError):
        return None
    if limit <= 0:
        return None
    if context.open_session_count is None:
        return None
    if context.open_session_count < limit:
        return None
    return (
        f"Concurrent-session limit reached "
        f"({context.open_session_count}/{limit}). "
        "Close one of your active sessions before starting another."
    )
