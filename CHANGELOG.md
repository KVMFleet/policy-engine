# Changelog

All notable changes to `kvmfleet-policy-engine` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [0.2.0] — 2026-06-10

### Added

- `ip_allowlist` rule type: blocks/warns when the source IP of the
  request is outside an admin-defined CIDR allowlist. Supports IPv4
  and IPv6 CIDRs. Skips on missing context (same contract as
  `require_mfa`).
- `EvalContext.request_ip: str | None` — caller-observed source IP,
  consumed by `ip_allowlist`. Optional; existing callers stay source
  compatible.
- `"observe"` decision + `dry_run` enforce mode: lets admins roll a
  rule out as observe-only (logged but non-blocking) before promoting
  to `warn`/`block`. `EvaluationResult.decision` extended to include
  `"observe"`; `result.observed` convenience flag.

### Notes

- Backward-compatible at the wire level for the four 0.1.0 rule types.
  Existing policy rows keep evaluating as before.
- `request_ip` defaults to `None`, so a 0.1.0 caller that doesn't
  pass it continues to work — `ip_allowlist` rules will simply skip
  if the IP is not provided.

## [0.1.0] — 2026-06-03

Initial public release. Extracted from the production KVM Fleet
platform code (in production since 2026-Q2) under Apache 2.0.

### Added

- `evaluate(policies, context) -> EvaluationResult` — pure-function
  evaluator. First `block` wins, then first `warn`, else `allow`.
- Four rule types: `time_of_day`, `require_mfa`,
  `max_concurrent_sessions`, `approval_required`.
- Shared `target_tags` / `target_actions` filter for all rule types.
- `Policy`, `EvalContext`, `EvaluationResult` dataclasses.
- 28 tests including hypothesis-based property tests for time_of_day
  boundary conditions.
- CI: ruff + mypy strict + pytest on Python 3.11 / 3.12.

### Notable contracts

- Unknown `rule_type` is silently skipped (forward-compat).
- Unknown `enforce_mode` defaults to `block` (fail-closed).
- Rules whose required context field is None are silently skipped.
  Callers needing fail-closed-on-missing must enforce externally.
- Naive `EvalContext.now` is treated as UTC, not local-time-of-process.
- Invalid `time_of_day.tz` falls back to UTC rather than crashing.
