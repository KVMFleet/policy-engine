"""Require the user to have 2FA enabled.

rule_data shape:
  {
    "target_tags": [...], "target_actions": [...]  # standard filters
  }

Fires when filters match AND `context.user_totp_enabled` is False.

`user_totp_enabled is None` (caller didn't provide it): rule SKIPS.
If you need fail-closed-on-missing-context, the caller must enforce
that externally — the library's contract is "skip rules whose context
isn't provided" because that's the only sane default when the same
library powers multiple consumers with different data models.

Typical use case: SOC 2 / ISO 27001 customers mandate 2FA on sensitive
actions per-rule (rather than the heavier org-wide 2FA flag).
"""
from __future__ import annotations

from typing import Any

from kvmfleet_policy_engine.rules._filters import filters_match
from kvmfleet_policy_engine.types import EvalContext


def apply(rule_data: dict[str, Any], context: EvalContext) -> str | None:
    if not filters_match(rule_data, context.action, context.device_tags):
        return None
    if context.user_totp_enabled is None:
        # Caller did not provide the field — skip rather than fail-closed.
        # If the caller wanted fail-closed, they should validate at the
        # call site before invoking evaluate().
        return None
    if context.user_totp_enabled:
        return None  # 2FA on → rule does not fire
    return (
        "This action requires two-factor authentication. "
        "Enable 2FA in your account settings to proceed."
    )
