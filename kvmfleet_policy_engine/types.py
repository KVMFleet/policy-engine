"""Shared types: Policy, EvalContext, EvaluationResult.

These are pure dataclasses — no DB coupling, no platform-specific fields.
The caller (typically a hosted control plane or an embedded tool) is
responsible for mapping its own models into these shapes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Policy:
    """One organisation-level policy rule.

    Attributes:
      id: opaque identifier (carried through to EvaluationResult.policy_id).
      name: human-readable label (carried through to result for UX).
      rule_type: one of `time_of_day`, `require_mfa`,
        `max_concurrent_sessions`, `approval_required`. Unknown rule
        types are silently skipped — this is the forward-compatibility
        affordance for rolling out a new rule type while older library
        versions are still running.
      rule_data: per-rule-type configuration. See `rules/*.py` for the
        expected shape per type. Common keys: `target_tags`,
        `target_actions` (filters; empty list = match every device /
        action).
      enforce_mode: `"block"` denies on match; `"warn"` allows but stamps
        a compliance-evaluation record. Unknown modes default to
        `"block"` (fail-closed).
    """
    id: str
    name: str
    rule_type: str
    rule_data: dict[str, Any]
    enforce_mode: str = "block"


@dataclass
class EvalContext:
    """Context for one evaluation.

    Required:
      action: what the user is about to do (e.g. `"console.start"`).
      device_tags: tags on the target device.

    Optional (provide when relevant — rules that need a field they
    don't get are silently skipped, NOT fail-closed-by-default):
      now: current time. Default `None` means `datetime.now(UTC)` at
        evaluation time. Pass an explicit datetime for testing /
        deterministic-replay.
      user_totp_enabled: whether the requesting user has 2FA active.
        Required for `require_mfa` rules.
      open_session_count: count of the user's currently-open privileged
        sessions across the fleet. Required for
        `max_concurrent_sessions` rules.
      has_active_grant: whether the requesting user has an active /
        non-expired access grant for the target device. Required for
        `approval_required` rules.
      request_ip: source IP of the request (caller-observed). Required
        for `ip_allowlist` rules.

    The rule-fires-when-context-missing-is-None semantics are
    documented per rule in `rules/*.py`. The default is "skip the
    rule" — if you want fail-closed for a specific rule, the caller
    must enforce it externally.
    """
    action: str
    device_tags: list[str] = field(default_factory=list)
    now: datetime | None = None
    user_totp_enabled: bool | None = None
    open_session_count: int | None = None
    has_active_grant: bool | None = None
    request_ip: str | None = None


@dataclass
class EvaluationResult:
    """Result of evaluating a context against a list of policies.

    Attributes:
      decision: `"allow"`, `"deny"`, `"warn"`, or `"observe"`.
      reason: human-readable explanation; empty when allow.
      policy_id: id of the policy that fired (None when allow).
      policy_name: name of the policy that fired (empty when allow).

    `"observe"` indicates a rule in `dry_run` enforce mode fired. The
    caller should not block, but should log the evaluation (an admin
    rolled the rule out as observe-only before promoting to warn/block).
    """
    decision: str
    reason: str = ""
    policy_id: str | None = None
    policy_name: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision != "deny"

    @property
    def denied(self) -> bool:
        return self.decision == "deny"

    @property
    def warned(self) -> bool:
        return self.decision == "warn"

    @property
    def observed(self) -> bool:
        return self.decision == "observe"
