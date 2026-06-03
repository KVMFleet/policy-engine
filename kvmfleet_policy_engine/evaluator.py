"""Walk a list of policies; return the most-restrictive outcome.

Order:
  1. First matching `block` rule wins → return deny.
  2. Otherwise, first matching `warn` rule wins → return warn.
  3. Otherwise → return allow.

Unknown `rule_type` values are silently skipped. This is the forward-
compatibility affordance for rolling out a new rule type while older
library versions are still in production.

Unknown `enforce_mode` values default to `"block"` (fail-closed) on the
grounds that mis-configured policies should err toward refusing access,
not granting it.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kvmfleet_policy_engine.rules import (
    approval_required,
    max_concurrent_sessions,
    require_mfa,
    time_of_day,
)
from kvmfleet_policy_engine.types import EvalContext, EvaluationResult, Policy

_RULE_DISPATCH: dict[str, Callable[[dict[str, Any], EvalContext], str | None]] = {
    "time_of_day": time_of_day.apply,
    "require_mfa": require_mfa.apply,
    "max_concurrent_sessions": max_concurrent_sessions.apply,
    "approval_required": approval_required.apply,
}

_ALLOW = EvaluationResult(decision="allow")


def evaluate(policies: list[Policy], context: EvalContext) -> EvaluationResult:
    """Pure-function evaluation. Caller loads `policies` however it
    wants (database, JSON file, in-memory list) and builds `context`
    from its own data model.

    Returns the first deny, otherwise the first warn, otherwise allow.
    """
    first_warn: EvaluationResult | None = None
    for p in policies:
        fn = _RULE_DISPATCH.get(p.rule_type)
        if fn is None:
            # Unknown rule type — skip silently. Forward-compatibility
            # affordance: a newer rule_type can land in the policy store
            # before every consumer has been upgraded.
            continue
        reason = fn(p.rule_data, context)
        if reason is None:
            continue
        # Rule fired. Resolve enforce_mode (block by default for any
        # unknown value — fail-closed).
        mode = p.enforce_mode if p.enforce_mode in ("block", "warn") else "block"
        if mode == "block":
            return EvaluationResult(
                decision="deny",
                reason=reason,
                policy_id=p.id,
                policy_name=p.name,
            )
        # warn mode — record the first warn but keep scanning for a block.
        if first_warn is None:
            first_warn = EvaluationResult(
                decision="warn",
                reason=reason,
                policy_id=p.id,
                policy_name=p.name,
            )

    return first_warn or _ALLOW
