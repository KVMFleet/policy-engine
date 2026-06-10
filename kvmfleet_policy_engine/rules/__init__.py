"""Per-rule-type evaluators. Each module exports `apply(policy, context)
→ str | None` where the return value is None when the rule does not
fire and a human-readable reason string when it does.

The dispatcher in evaluator.py routes to the right module by
`policy.rule_type`. Unknown types are silently skipped.
"""
from kvmfleet_policy_engine.rules import (
    approval_required,
    ip_allowlist,
    max_concurrent_sessions,
    require_mfa,
    time_of_day,
)

__all__ = [
    "approval_required",
    "ip_allowlist",
    "max_concurrent_sessions",
    "require_mfa",
    "time_of_day",
]
