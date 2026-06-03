# kvmfleet-policy-engine

Small, opinionated policy engine for access control over hardware-
shaped resources — BMCs, network gear, industrial control systems,
anything where the meaningful unit of policy is "this user, this
device, this action, this time."

Powers the hosted access-governance platform at
[kvmfleet.io](https://kvmfleet.io). Released under Apache 2.0.

## What this is

Four rule types, each with `block` and `warn` enforcement modes:

| Rule | Fires when |
|---|---|
| `time_of_day` | Current time is outside the configured weekly windows |
| `require_mfa` | The user does not have 2FA enabled |
| `max_concurrent_sessions` | The user already has ≥ N privileged sessions open |
| `approval_required` | The user has no active access grant for the device |

Each rule supports two common filters: `target_tags` (rule applies
only when device has all of these tags) and `target_actions` (rule
applies only to certain action names). Both default to "match every
device / action" when empty.

## What this is NOT

- Not a general-purpose policy engine. We deliberately stop at four
  rule types — the ones that 80% of access-governance setups for
  hardware actually need. If you need ABAC over arbitrary
  attributes, use [Cedar](https://www.cedarpolicy.com/) or
  [OPA](https://www.openpolicyagent.org/).
- Not a DSL. Rule configuration is JSON-shaped Python `dict`s —
  schema per rule type. Easier to write a UI against, harder to
  abuse, much easier to embed than Rego.
- Not async. The library is synchronous and pure. Wrap it in
  async if your caller is async.
- Not a database. Load policies + context however you want and
  pass them in.

## Install

```bash
pip install kvmfleet-policy-engine
```

Requires Python 3.11+. Zero runtime dependencies.

## Quick start

```python
from kvmfleet_policy_engine import EvalContext, Policy, evaluate

policies = [
    Policy(
        id="prod-business-hours",
        name="Prod access during business hours only",
        rule_type="time_of_day",
        rule_data={
            "tz": "Europe/Malta",
            "allowed_windows": [
                {"days": ["mon", "tue", "wed", "thu", "fri"],
                 "start": "09:00", "end": "17:00"},
            ],
            "target_tags": ["production"],
            "target_actions": ["console.start"],
        },
        enforce_mode="block",
    ),
    Policy(
        id="prod-needs-mfa",
        name="Prod console requires 2FA",
        rule_type="require_mfa",
        rule_data={"target_tags": ["production"]},
        enforce_mode="block",
    ),
]

context = EvalContext(
    action="console.start",
    device_tags=["production"],
    user_totp_enabled=True,
)

result = evaluate(policies, context)
if result.denied:
    raise PermissionError(result.reason)
```

## Rule details

### `time_of_day`

```python
rule_data = {
    "tz": "Europe/Malta",              # IANA timezone; invalid → UTC fallback
    "allowed_windows": [
        {"days": ["mon", "tue", ...],
         "start": "09:00", "end": "17:00"},
    ],
    "target_tags": ["production"],     # optional; default = all devices
    "target_actions": ["console.start"], # optional; default = all actions
}
```

Outside any allowed window for the current weekday → rule fires.
Pass `EvalContext.now` for deterministic testing; defaults to
`datetime.now(UTC)`.

### `require_mfa`

```python
rule_data = {
    "target_tags": [...], "target_actions": [...]
}
```

Provide `EvalContext.user_totp_enabled`. Rule fires when False.
Rule **skips** (returns allow) when the field is None — the library's
contract is "skip rules whose context isn't provided." If you need
fail-closed-on-missing-context for a specific rule, enforce it at
the call site.

### `max_concurrent_sessions`

```python
rule_data = {
    "max_sessions": 1,                 # int >= 1
    "target_tags": [...], "target_actions": [...]
}
```

Provide `EvalContext.open_session_count`. The session-about-to-be-
created is NOT counted, so `max_sessions=1` means "no second
concurrent session." Rule skips when the count is None or the
limit is ≤ 0.

### `approval_required`

```python
rule_data = {
    "target_tags": [...], "target_actions": [...]
}
```

Provide `EvalContext.has_active_grant`. Rule fires when False. The
caller defines what "active grant" means in its own data model —
the library only needs a boolean.

## Outcome semantics

`evaluate()` walks the policy list in order:

1. **First matching `block` rule wins.** Return `deny`.
2. **Otherwise, first matching `warn` rule wins.** Return `warn`.
3. **Otherwise**, return `allow`.

Unknown `rule_type` values are silently skipped — forward-compat for
rolling out a new rule type while older library versions are still
running. Unknown `enforce_mode` values default to `block` (fail-closed).

## Why does this exist

We needed access governance for BMCs and built this. Most of the
existing policy engines are either too heavyweight (OPA + Rego is a
lot for "should this console session start at 3 AM?") or too generic
(Cedar's ABAC is brilliant but doesn't have first-class concepts for
"weekly time window" or "concurrent session count").

By being narrow + opinionated, we ship a policy engine you can
embed in a Friday and stop thinking about. If your needs grow
beyond the four rule types, you'll outgrow us — and you should,
because that's a sign your access model has gotten richer.

Open-sourcing because:

- The protocol / rule-evaluation logic isn't where our value lives.
  Our value is the hosted operational surface: audit chain, EU-
  resident retention, support SLA.
- Open code means hostile reviewers can verify the time-zone
  handling, the warn-vs-block ordering, the rule-fire defaults.
  That trust transfer matters more to us than gatekeeping.

This is one of a series of OSS extractions from the KVM Fleet
platform:

- [agent](https://github.com/KVMFleet/agent) — device-side agent
  (Apache 2.0)
- [audit-verify](https://github.com/KVMFleet/audit-verify) — OSS
  audit-chain verifier (BSL 1.1)
- [bmc-adapters](https://github.com/KVMFleet/bmc-adapters) — multi-
  vendor BMC Redfish client (Apache 2.0)
- [mcp](https://github.com/KVMFleet/mcp) — read-only MCP server for
  AI assistants (MIT)

See [BUSINESS.md §N](https://github.com/kvmfleet) for the doctrine.

## Contributing

Bug reports and patches welcome. PRs that add new rule types must
make a case for why the existing four don't cover the use case. We'd
rather stay opinionated and small.

See [docs/contributing.md](docs/contributing.md) for the local dev
setup.

## License

Apache 2.0 — see [LICENSE](LICENSE). Copyright 2026 KVM Fleet.
