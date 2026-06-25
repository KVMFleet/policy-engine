"""Tests for kvmfleet_policy_engine.evaluator + the four rule modules.

Pure functions; no fixtures needed beyond a tiny `make_policy` helper.
hypothesis covers the time_of_day edge cases (weekday + window
boundaries).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from kvmfleet_policy_engine import (
    EvalContext,
    EvaluationResult,
    Policy,
    evaluate,
)


def make_policy(
    rule_type: str,
    rule_data: dict[str, Any] | None = None,
    enforce_mode: str = "block",
    id_: str = "p-1",
    name: str = "test",
) -> Policy:
    return Policy(
        id=id_,
        name=name,
        rule_type=rule_type,
        rule_data=rule_data or {},
        enforce_mode=enforce_mode,
    )


# --- empty policy list / unknown rule type ------------------------------

def test_empty_policy_list_allows() -> None:
    ctx = EvalContext(action="console.start")
    assert evaluate([], ctx) == EvaluationResult(decision="allow")


def test_unknown_rule_type_is_silently_skipped() -> None:
    """Forward-compat: an older library version sees a newer rule_type
    and skips rather than crashing."""
    policies = [make_policy("not_yet_implemented_v2", {})]
    ctx = EvalContext(action="console.start")
    assert evaluate(policies, ctx).decision == "allow"


def test_unknown_enforce_mode_defaults_to_block_fail_closed() -> None:
    """A mis-configured policy with an unknown enforce_mode defaults to
    block — mis-configured policies should err toward refusing access."""
    policies = [
        make_policy("approval_required", {}, enforce_mode="typo_here"),
    ]
    ctx = EvalContext(action="console.start", has_active_grant=False)
    result = evaluate(policies, ctx)
    assert result.denied


# --- time_of_day --------------------------------------------------------

def test_time_of_day_inside_window_allows() -> None:
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
    })]
    # Monday at 12:00 UTC
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).decision == "allow"


def test_time_of_day_outside_window_denies() -> None:
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
    })]
    # Monday at 19:00 UTC
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 1, 19, 0, tzinfo=UTC),
    )
    result = evaluate(policies, ctx)
    assert result.denied
    assert "Outside allowed window" in result.reason


def test_time_of_day_wrong_weekday_denies() -> None:
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "00:00", "end": "23:59"}],
    })]
    # Tuesday — not in allowed days
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 2, 12, 0, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).denied


def test_time_of_day_target_tags_filter() -> None:
    """target_tags="all" means the rule only applies to devices with
    those tags. A device without them passes."""
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
        "target_tags": ["production"],
    })]
    # Outside window, but device is dev → rule does not fire
    ctx = EvalContext(
        action="console.start",
        device_tags=["dev"],
        now=datetime(2026, 6, 1, 19, 0, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).decision == "allow"


def test_time_of_day_target_actions_filter() -> None:
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
        "target_actions": ["console.start"],
    })]
    # Outside window, but action is power.cycle → rule does not fire
    ctx = EvalContext(
        action="power.cycle",
        now=datetime(2026, 6, 1, 19, 0, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).decision == "allow"


def test_time_of_day_invalid_tz_falls_back_to_utc() -> None:
    """An invalid tz string defaults to UTC rather than crashing — the
    platform UI is expected to validate at save time; this is defensive."""
    policies = [make_policy("time_of_day", {
        "tz": "Not/A/Real/Zone",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
    })]
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).decision == "allow"


def test_time_of_day_handles_naive_now_as_utc() -> None:
    """A caller that passes a tz-naive datetime gets UTC semantics
    rather than the local-time-of-the-process trap."""
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
    })]
    # 2026-06-01 was a Monday; 12:00 naive → treated as 12:00 UTC
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 1, 12, 0),  # tz-naive
    )
    assert evaluate(policies, ctx).decision == "allow"


@settings(max_examples=200)
@given(
    hour=st.integers(min_value=0, max_value=23),
    minute=st.integers(min_value=0, max_value=59),
)
def test_time_of_day_property_window_consistency(hour: int, minute: int) -> None:
    """Property: a 24-hour allowed window for every weekday should
    allow at any time. Catches off-by-one boundary errors that
    fixture-based tests miss."""
    policies = [make_policy("time_of_day", {
        "tz": "UTC",
        "allowed_windows": [
            {"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
             "start": "00:00", "end": "23:59"},
        ],
    })]
    ctx = EvalContext(
        action="console.start",
        now=datetime(2026, 6, 1, hour, minute, tzinfo=UTC),
    )
    assert evaluate(policies, ctx).decision == "allow"


# --- require_mfa --------------------------------------------------------

def test_require_mfa_user_with_2fa_allows() -> None:
    policies = [make_policy("require_mfa", {})]
    ctx = EvalContext(action="console.start", user_totp_enabled=True)
    assert evaluate(policies, ctx).decision == "allow"


def test_require_mfa_user_without_2fa_denies() -> None:
    policies = [make_policy("require_mfa", {})]
    ctx = EvalContext(action="console.start", user_totp_enabled=False)
    result = evaluate(policies, ctx)
    assert result.denied
    assert "two-factor" in result.reason.lower()


def test_require_mfa_skips_when_context_field_missing() -> None:
    """Library default: rule skips when caller didn't provide the field.
    Documented in the rule module docstring."""
    policies = [make_policy("require_mfa", {})]
    ctx = EvalContext(action="console.start")  # user_totp_enabled=None
    assert evaluate(policies, ctx).decision == "allow"


# --- max_concurrent_sessions --------------------------------------------

def test_max_concurrent_under_limit_allows() -> None:
    policies = [make_policy("max_concurrent_sessions", {"max_sessions": 3})]
    ctx = EvalContext(action="console.start", open_session_count=2)
    assert evaluate(policies, ctx).decision == "allow"


def test_max_concurrent_at_limit_denies() -> None:
    """The session-about-to-be-created is NOT counted, so an open_count
    equal to max_sessions means "would exceed if we let this one open"."""
    policies = [make_policy("max_concurrent_sessions", {"max_sessions": 1})]
    ctx = EvalContext(action="console.start", open_session_count=1)
    assert evaluate(policies, ctx).denied


def test_max_concurrent_skips_on_missing_field() -> None:
    policies = [make_policy("max_concurrent_sessions", {"max_sessions": 1})]
    ctx = EvalContext(action="console.start")  # open_session_count=None
    assert evaluate(policies, ctx).decision == "allow"


def test_max_concurrent_invalid_limit_skips() -> None:
    policies = [make_policy("max_concurrent_sessions", {"max_sessions": "not-a-number"})]
    ctx = EvalContext(action="console.start", open_session_count=100)
    assert evaluate(policies, ctx).decision == "allow"


# --- approval_required --------------------------------------------------

def test_approval_required_with_grant_allows() -> None:
    policies = [make_policy("approval_required", {})]
    ctx = EvalContext(action="console.start", has_active_grant=True)
    assert evaluate(policies, ctx).decision == "allow"


def test_approval_required_without_grant_denies() -> None:
    policies = [make_policy("approval_required", {})]
    ctx = EvalContext(action="console.start", has_active_grant=False)
    result = evaluate(policies, ctx)
    assert result.denied
    assert "Approval required" in result.reason


def test_approval_required_skips_on_missing_field() -> None:
    policies = [make_policy("approval_required", {})]
    ctx = EvalContext(action="console.start")  # has_active_grant=None
    assert evaluate(policies, ctx).decision == "allow"


# --- warn vs block + multi-rule ordering --------------------------------

def test_warn_does_not_short_circuit_subsequent_blocks() -> None:
    """A warn rule records the first warn but keeps scanning. If a later
    rule fires in block mode, the block takes priority over the warn."""
    policies = [
        make_policy("require_mfa", {}, enforce_mode="warn", id_="p-warn"),
        make_policy("approval_required", {}, enforce_mode="block", id_="p-block"),
    ]
    ctx = EvalContext(
        action="console.start",
        user_totp_enabled=False,    # would warn
        has_active_grant=False,     # would block
    )
    result = evaluate(policies, ctx)
    assert result.denied
    assert result.policy_id == "p-block"


def test_first_warn_wins_when_no_block() -> None:
    """When no block fires, the FIRST warn is returned (not the last)."""
    policies = [
        make_policy("require_mfa", {}, enforce_mode="warn", id_="p-first"),
        make_policy("approval_required", {}, enforce_mode="warn", id_="p-second"),
    ]
    ctx = EvalContext(
        action="console.start",
        user_totp_enabled=False,
        has_active_grant=False,
    )
    result = evaluate(policies, ctx)
    assert result.warned
    assert result.policy_id == "p-first"


def test_first_block_wins_when_multiple_blocks_fire() -> None:
    policies = [
        make_policy("require_mfa", {}, enforce_mode="block", id_="p-first-block"),
        make_policy("approval_required", {}, enforce_mode="block", id_="p-second-block"),
    ]
    ctx = EvalContext(
        action="console.start",
        user_totp_enabled=False,
        has_active_grant=False,
    )
    result = evaluate(policies, ctx)
    assert result.denied
    assert result.policy_id == "p-first-block"


# --- EvaluationResult helpers ------------------------------------------

@pytest.mark.parametrize(
    "decision,allowed,denied,warned",
    [
        ("allow", True, False, False),
        ("deny", False, True, False),
        ("warn", True, False, True),
    ],
)
def test_evaluation_result_helpers(
    decision: str, allowed: bool, denied: bool, warned: bool
) -> None:
    r = EvaluationResult(decision=decision)
    assert r.allowed is allowed
    assert r.denied is denied
    assert r.warned is warned


# --- fail-closed when a rule RAISES (security-critical) ------------------

def _boom(rule_data, context):  # type: ignore[no-untyped-def]
    raise RuntimeError("simulated rule bug / unexpected input")


def test_block_rule_that_raises_fails_closed_to_deny(monkeypatch) -> None:
    """A BLOCKING rule we cannot evaluate must DENY, not propagate, not allow.
    Denying is recoverable; silently granting on an unevaluable restrictive
    policy is a breach."""
    from kvmfleet_policy_engine import evaluator
    monkeypatch.setitem(evaluator._RULE_DISPATCH, "time_of_day", _boom)
    res = evaluate([make_policy("time_of_day", enforce_mode="block")],
                   EvalContext(action="console.start"))
    assert res.decision == "deny"
    assert res.policy_id == "p-1"


def test_warn_rule_that_raises_does_not_deny(monkeypatch) -> None:
    """warn never blocks access by design — a rule error there can't cause a
    breach, so it must NOT escalate to deny. It surfaces as a warn."""
    from kvmfleet_policy_engine import evaluator
    monkeypatch.setitem(evaluator._RULE_DISPATCH, "time_of_day", _boom)
    res = evaluate([make_policy("time_of_day", enforce_mode="warn")],
                   EvalContext(action="console.start"))
    assert res.decision == "warn"


def test_dry_run_rule_that_raises_never_impacts_access(monkeypatch) -> None:
    """observe/dry_run must never block — a rule error stays informational."""
    from kvmfleet_policy_engine import evaluator
    monkeypatch.setitem(evaluator._RULE_DISPATCH, "time_of_day", _boom)
    res = evaluate([make_policy("time_of_day", enforce_mode="dry_run")],
                   EvalContext(action="console.start"))
    assert res.decision == "observe"


def test_a_raising_rule_never_propagates(monkeypatch) -> None:
    """evaluate() must never let a rule exception escape to the caller —
    the security property must be the engine's, not the caller's 500 handler."""
    from kvmfleet_policy_engine import evaluator
    monkeypatch.setitem(evaluator._RULE_DISPATCH, "require_mfa", _boom)
    # Should not raise:
    res = evaluate([make_policy("require_mfa", enforce_mode="block")],
                   EvalContext(action="console.start"))
    assert res.decision == "deny"
