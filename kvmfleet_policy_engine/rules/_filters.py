"""Shared target_tags / target_actions filter used by every rule type."""
from __future__ import annotations

from typing import Any


def filters_match(rule_data: dict[str, Any], action: str, device_tags: list[str]) -> bool:
    """Return True if the rule's `target_tags` and `target_actions`
    filters match the current action + device. Empty list (or missing)
    means "match everything" for that filter.

    Semantics:
      target_actions: action must be in the list (any-match).
      target_tags: device must have ALL of these tags (all-match).
    """
    target_actions = rule_data.get("target_actions") or []
    if target_actions and action not in target_actions:
        return False
    target_tags = rule_data.get("target_tags") or []
    if target_tags:
        device_tag_set = set(device_tags)
        if not all(t in device_tag_set for t in target_tags):
            return False
    return True
