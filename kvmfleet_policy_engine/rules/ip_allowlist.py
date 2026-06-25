"""Block / warn when the request source IP is outside an allowlist.

rule_data shape:
  {
    "cidrs": ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.5/32"],
    "target_tags": [...], "target_actions": [...]  # standard filters
  }

Fires when filters match AND `context.request_ip` is set AND the IP is
NOT inside any of the allow-listed CIDRs.

`request_ip is None` (caller didn't provide it): rule SKIPS — same
contract as `require_mfa`. If you want fail-closed when the caller
hasn't supplied the IP, enforce it at the call site (or set a default
that won't match any sane allowlist, e.g. "0.0.0.0/32").

`cidrs` is empty or malformed: rule SKIPS. A misconfigured allowlist
shouldn't lock everyone out — admins set this from the policies UI and
a typo would otherwise turn into an outage.

Common use case: SOC 2 / ISO 27001 customers need to demonstrate "only
corporate IP ranges can reach the management plane." This rule is the
procurement-checklist answer.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from kvmfleet_policy_engine.rules._filters import filters_match
from kvmfleet_policy_engine.types import EvalContext


def apply(rule_data: dict[str, Any], context: EvalContext) -> str | None:
    if not filters_match(rule_data, context.action, context.device_tags):
        return None
    if context.request_ip is None:
        return None

    cidrs_raw = rule_data.get("cidrs") or []
    if not isinstance(cidrs_raw, list) or not cidrs_raw:
        return None

    try:
        addr = ipaddress.ip_address(context.request_ip)
    except ValueError:
        # Malformed IP from caller — skip rather than error. The hot path
        # shouldn't crash because of a bad request-IP string.
        return None

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs_raw:
        try:
            networks.append(ipaddress.ip_network(c, strict=False))
        except (ValueError, TypeError):
            # Skip malformed entries. We could log here but the library is
            # I/O-free; the caller wrapping us can log on its side.
            continue

    if not networks:
        return None  # nothing to compare against

    for net in networks:
        if addr in net:
            return None  # allowed

    return (
        f"Access from {context.request_ip} is outside the allowed source-IP "
        "ranges for this action. Connect from a corporate / VPN IP and retry."
    )
