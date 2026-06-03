"""Require an active access grant for the target device.

rule_data shape:
  {
    "target_tags": [...], "target_actions": [...]  # standard filters
  }

Fires when filters match AND `context.has_active_grant` is False.

`has_active_grant is None` (caller didn't provide it): rule SKIPS.

This is the rule-driven equivalent of a per-device "JIT required" flag
— it lets you say "production console always requires approval"
without flipping every prod device's `jit_required` field individually.

The caller defines what "active access grant" means in its own model;
the library only needs a boolean.
"""
from __future__ import annotations

from typing import Any

from kvmfleet_policy_engine.rules._filters import filters_match
from kvmfleet_policy_engine.types import EvalContext


def apply(rule_data: dict[str, Any], context: EvalContext) -> str | None:
    if not filters_match(rule_data, context.action, context.device_tags):
        return None
    if context.has_active_grant is None:
        return None
    if context.has_active_grant:
        return None
    return (
        "Approval required for this action. Request access first via "
        "the Access requests page; once approved, retry."
    )
