# Changelog

All notable changes to `kvmfleet-policy-engine` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [SemVer](https://semver.org/).

## [0.2.1] — 2026-06-25

Security hardening (no API change).

### Changed

- **Fail-closed on an unevaluable rule.** A rule that raises during
  evaluation no longer propagates out of `evaluate()`. A `block`-mode rule
  that can't be evaluated now returns `deny` (a restrictive policy we can't
  confirm is satisfied must fail closed); `warn`/`dry_run` modes — which
  never deny by design — degrade to their non-blocking signal. Previously an
  exception propagated and the security outcome depended on the caller
  turning it into a denial. 4 new tests pin each mode's behaviour.

### Fixed

- Type annotation in `ip_allowlist` used the private `ipaddress._BaseNetwork`
  without type args (a mypy-strict failure under current mypy); switched to
  the public `IPv4Network | IPv6Network` union.

## [0.2.0] — 2026-06-10

Adds a fifth rule type and an observe-only enforcement mode, extracted
from the production platform's access-governance cascade.

### Added

- **`ip_allowlist` rule type** — fires when the request's source IP is
  outside the allow-listed CIDR ranges. Skips (rather than locking out)
  when the source IP is unset or the `cidrs` list is empty/malformed.
- **`dry_run` enforcement mode** — the rule is evaluated and its reasoning
  surfaced, but the result is `"observe"`: it neither blocks nor warns.
  Lets admins roll a new rule out in observe-only mode and watch its
  fire-pattern before promoting it to `warn`/`block`.
- **`EvalContext.request_ip`** — source IP of the request, consumed by the
  `ip_allowlist` rule (skip-on-missing, same contract as `require_mfa`).
- `EvaluationResult.observed` helper + `"observe"` decision value.

### Notable contracts

- Outcome order is now: first `block` → first `warn` → first `dry_run`
  (`observe`) → `allow`.

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
