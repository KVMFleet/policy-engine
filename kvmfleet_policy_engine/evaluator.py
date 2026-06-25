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

By the same principle, a rule that RAISES (unexpected input its own
graceful-skip handling didn't anticipate) is treated as a `block` →
`deny`, not silently skipped and not allowed to propagate. A restrictive
rule we cannot evaluate must fail closed: denying access is recoverable
(the admin notices and fixes the policy), silently granting it is a
breach. This makes the security property explicit in the engine rather
than relying on the caller turning an unhandled exception into a 500.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from kvmfleet_policy_engine.rules import (
    approval_required,
    ip_allowlist,
    max_concurrent_sessions,
    require_mfa,
    time_of_day,
)
from kvmfleet_policy_engine.types import EvalContext, EvaluationResult, Policy

log = logging.getLogger(__name__)

_RULE_DISPATCH: dict[str, Callable[[dict[str, Any], EvalContext], str | None]] = {
    "time_of_day": time_of_day.apply,
    "require_mfa": require_mfa.apply,
    "max_concurrent_sessions": max_concurrent_sessions.apply,
    "approval_required": approval_required.apply,
    "ip_allowlist": ip_allowlist.apply,
}

# Modes recognised by the evaluator. Anything else collapses to "block"
# (fail-closed). dry_run is a strict subset of warn — the rule is detected
# and reasoning surfaced but the result.decision is "observe" so callers
# treat it as informational.
_VALID_MODES = ("block", "warn", "dry_run")

_ALLOW = EvaluationResult(decision="allow")


def evaluate(policies: list[Policy], context: EvalContext) -> EvaluationResult:
    """Pure-function evaluation. Caller loads `policies` however it
    wants (database, JSON file, in-memory list) and builds `context`
    from its own data model.

    Returns the first deny; otherwise the first warn; otherwise the
    first observe (dry_run); otherwise allow.
    """
    first_warn: EvaluationResult | None = None
    first_observe: EvaluationResult | None = None
    for p in policies:
        fn = _RULE_DISPATCH.get(p.rule_type)
        if fn is None:
            # Unknown rule type — skip silently. Forward-compatibility
            # affordance: a newer rule_type can land in the policy store
            # before every consumer has been upgraded.
            continue
        # Resolve enforce_mode up front (block by default for any unknown
        # value — fail-closed) so we know how to handle a rule that raises.
        mode = p.enforce_mode if p.enforce_mode in _VALID_MODES else "block"
        try:
            reason = fn(p.rule_data, context)
        except Exception:
            log.exception(
                "policy rule %r (policy_id=%s, mode=%s) raised during "
                "evaluation", p.rule_type, p.id, mode,
            )
            if mode == "block":
                # A BLOCKING rule we cannot evaluate must fail closed: denying
                # is recoverable, silently granting is a breach.
                return EvaluationResult(
                    decision="deny",
                    reason=(
                        "This action is governed by a policy that could not be "
                        "evaluated. Access is denied (fail-closed). Contact an "
                        "administrator to review the policy configuration."
                    ),
                    policy_id=p.id,
                    policy_name=p.name,
                )
            # warn / dry_run never deny access by design, so a rule error here
            # cannot cause a breach — surface it as that mode's non-blocking
            # signal so the unreliable evaluation is still visible.
            reason = "policy rule could not be evaluated (see server logs)"
        if reason is None:
            continue
        if mode == "block":
            return EvaluationResult(
                decision="deny",
                reason=reason,
                policy_id=p.id,
                policy_name=p.name,
            )
        if mode == "warn":
            if first_warn is None:
                first_warn = EvaluationResult(
                    decision="warn",
                    reason=reason,
                    policy_id=p.id,
                    policy_name=p.name,
                )
            continue
        # dry_run — log the would-have-fired signal but don't block or warn.
        # Lets admins roll out a new rule, observe its fire-pattern for a
        # week, then promote to warn/block before any user is impacted.
        if first_observe is None:
            first_observe = EvaluationResult(
                decision="observe",
                reason=reason,
                policy_id=p.id,
                policy_name=p.name,
            )

    return first_warn or first_observe or _ALLOW
