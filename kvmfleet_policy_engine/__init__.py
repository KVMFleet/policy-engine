"""kvmfleet-policy-engine — small opinionated policy engine for access
control over hardware-shaped resources.

Four rule types:
  - time_of_day            — allow only during configured weekly windows
  - require_mfa            — require 2FA enabled on the requesting user
  - max_concurrent_sessions — cap simultaneous privileged sessions per user
  - approval_required      — require an active access grant for the device

Each rule has two enforcement modes:
  - "block"  — denies the action (caller raises 403)
  - "warn"   — allows but stamps an audit row (compliance signalling
               without breaking ops)

Pure functions. No I/O. No async. No database. The caller loads the
policies + context however it wants and passes them in.

Usage:

    from kvmfleet_policy_engine import EvalContext, Policy, evaluate

    policies = [Policy(
        id="...",
        name="No production access outside business hours",
        rule_type="time_of_day",
        rule_data={
            "tz": "Europe/Malta",
            "allowed_windows": [
                {"days": ["mon", "tue", "wed", "thu", "fri"],
                 "start": "09:00", "end": "17:00"}
            ],
            "target_tags": ["production"],
            "target_actions": ["console.start"],
        },
        enforce_mode="block",
    )]

    context = EvalContext(
        action="console.start",
        device_tags=["production"],
    )
    result = evaluate(policies, context)
    if result.denied:
        raise PermissionError(result.reason)

Powers the hosted access-governance platform at https://kvmfleet.io,
released under Apache 2.0 so anyone building tooling against
hardware-shaped resources can reuse the parts that matter.
"""
from kvmfleet_policy_engine.evaluator import evaluate
from kvmfleet_policy_engine.types import (
    EvalContext,
    EvaluationResult,
    Policy,
)

__version__ = "0.2.0"

__all__ = [
    "EvalContext",
    "EvaluationResult",
    "Policy",
    "__version__",
    "evaluate",
]
