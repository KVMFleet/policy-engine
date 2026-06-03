# Changelog

All notable changes to `kvmfleet-policy-engine` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

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
