"""Turns a raw finding into the flat bag of *signals* that rule predicates read.

The scoring engine never looks at a raw finding directly. It looks at signals:
the union of

  1. the ``context`` dict P1 supplied (the observed facts), and
  2. values P2 derives itself (name heuristics, port classification, aliases).

Deriving as much as possible here means P1 does not have to answer a question
like "does this bucket name suggest financial data?" -- P2 can infer it from the
resource name it already sends. Every derived key is namespaced in
``DERIVED_KEYS`` so a collision with a P1-supplied context key is detectable
rather than silently shadowing real evidence.
"""

from __future__ import annotations

from typing import Any, Mapping

from .rules import INACTIVE_USER_HINTS, SENSITIVE_NAME_HINTS, SENSITIVE_PORTS

#: Keys this module computes itself. `context` must not use these names.
DERIVED_KEYS: frozenset[str] = frozenset(
    {
        "rule_id",
        "name",
        "resource_name",
        "resource_type",
        "region",
        "name_lower",
        "sensitive_data_likely",
        "user_likely_inactive",
        "sensitive_ports_found",
        "first_sensitive_port",
        "first_sensitive_service",
        "port_services",
        # convenience aliases so factor templates can read naturally
        "days",
        "user_count",
    }
)

#: Context keys ``derive_signals`` reads directly.
#:
#: A rule declaring one of these is not dead even when no factor names it in
#: ``requires``: the key is consumed here and resurfaces as a derived signal
#: (`exposed_ports` -> `sensitive_ports_found`, `unused_days` -> `days`,
#: `attached_user_count` -> `user_count`). ``test_rule_table.py`` unions this set
#: with the factors' ``requires`` to decide whether a declared key is live.
CONTEXT_KEYS_CONSUMED: frozenset[str] = frozenset(
    {
        "exposed_ports",
        "unused_days",
        "attached_user_count",
    }
)


def _matches_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack for n in needles)


def derive_signals(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Build the scoring signal bag for one raw finding.

    Missing context keys are simply absent rather than an error -- rules are
    expected to ship incrementally, and ``Factor.applies`` predicates already
    treat absent keys as False via ``s.get(...)``.
    """
    context = dict(raw.get("context") or {})
    resource = raw.get("resource") or {}

    collisions = DERIVED_KEYS & context.keys()
    if collisions:
        raise ValueError(
            f"context for finding {raw.get('finding_id')!r} uses reserved key(s): "
            f"{sorted(collisions)}. These are derived by P2; rename the context key."
        )

    name = str(resource.get("name") or "")
    name_lower = name.lower()

    exposed_ports = [int(p) for p in (context.get("exposed_ports") or []) if p is not None]
    sensitive_ports_found = sorted(p for p in exposed_ports if p in SENSITIVE_PORTS)
    port_services = {str(p): SENSITIVE_PORTS[p] for p in exposed_ports if p in SENSITIVE_PORTS}

    signals: dict[str, Any] = {
        **context,
        "rule_id": raw.get("rule_id", ""),
        "name": name,
        "resource_name": name,
        "resource_type": str(resource.get("type") or ""),
        "region": str(resource.get("region") or ""),
        "name_lower": name_lower,
        "sensitive_data_likely": _matches_any(name_lower, SENSITIVE_NAME_HINTS),
        "user_likely_inactive": _matches_any(name_lower, INACTIVE_USER_HINTS),
        "sensitive_ports_found": sensitive_ports_found,
        "first_sensitive_port": sensitive_ports_found[0] if sensitive_ports_found else None,
        "first_sensitive_service": (
            SENSITIVE_PORTS[sensitive_ports_found[0]] if sensitive_ports_found else None
        ),
        "port_services": port_services,
        # Aliases used by factor description templates. `days` falls back to the
        # rule's own 90-day threshold: the factor only fires at >= 90 days, so
        # stating the threshold is accurate even when P1 reported no exact count,
        # and it avoids rendering "over 0 days".
        "days": context.get("unused_days", 90),
        "user_count": context.get("attached_user_count", 0),
    }
    return signals
