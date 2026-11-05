"""
MITRE ATT&CK mapping driven by a human-editable YAML rules file.

The rules file (backend/rules/mitre_rules.yaml by default) is a list of rules.
Each rule names ONE technique and lists match conditions. A rule fires when
ANY of its conditions matches (they are OR-ed). Conditions:

    rule_ids:   exact match against the alert's rule ID (Wazuh rule.id, Splunk signature_id)
    rule_names: case-insensitive substring of the alert's rule name
    keywords:   case-insensitive substring of rule name + description
    categories: case-insensitive match against a token of the alert's category
                (Wazuh rule.groups, Splunk category/eventtype)
    regex:      Python regular expressions against rule name + description

An alert may match several rules; all matched techniques are kept (deduplicated)
in rules-file order, so put the most specific rules FIRST - the first match is
shown as the alert's primary technique. Alerts that match nothing get the
"Unmapped" label instead of being dropped.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

UNMAPPED = {"technique_id": "Unmapped", "technique_name": "Unmapped", "tactic": "Unmapped", "rule": None}

CONDITION_KEYS = ("rule_ids", "rule_names", "keywords", "categories", "regex")


class RulesError(ValueError):
    """Raised when the rules file is missing or malformed."""


class MitreMapper:
    def __init__(self, rules: list[dict]):
        self.rules = [self._compile(rule, i) for i, rule in enumerate(rules, start=1)]

    @classmethod
    def from_file(cls, path: str | Path) -> "MitreMapper":
        path = Path(path)
        if not path.exists():
            raise RulesError(f"MITRE rules file not found: {path}")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            raise RulesError(f"MITRE rules file is not valid YAML: {e}") from None
        rules = doc.get("rules") if isinstance(doc, dict) else None
        if not isinstance(rules, list):
            raise RulesError("MITRE rules file must contain a top-level 'rules:' list.")
        return cls(rules)

    @staticmethod
    def _compile(rule: dict, index: int) -> dict:
        """Validate one rule and pre-process its conditions for fast matching."""
        if not isinstance(rule, dict):
            raise RulesError(f"Rule #{index} must be a mapping.")
        label = rule.get("name", f"#{index}")
        for key in ("technique_id", "technique_name", "tactic"):
            if not rule.get(key):
                raise RulesError(f"Rule {label!r} is missing required key '{key}'.")
        match = rule.get("match") or {}
        if not isinstance(match, dict) or not any(match.get(k) for k in CONDITION_KEYS):
            raise RulesError(
                f"Rule {label!r} needs a 'match:' block with at least one of {', '.join(CONDITION_KEYS)}."
            )
        unknown = set(match) - set(CONDITION_KEYS)
        if unknown:
            raise RulesError(f"Rule {label!r} has unknown match keys: {', '.join(sorted(unknown))}.")

        def lowered(key):
            return [str(v).lower() for v in match.get(key) or []]

        try:
            patterns = [re.compile(p, re.IGNORECASE) for p in match.get("regex") or []]
        except re.error as e:
            raise RulesError(f"Rule {label!r} has an invalid regex: {e}") from None

        return {
            "name": label,
            "technique_id": str(rule["technique_id"]),
            "technique_name": str(rule["technique_name"]),
            "tactic": str(rule["tactic"]),
            "rule_ids": {str(v) for v in match.get("rule_ids") or []},
            "rule_names": lowered("rule_names"),
            "keywords": lowered("keywords"),
            "categories": set(lowered("categories")),
            "regex": patterns,
        }

    @staticmethod
    def _matches(rule: dict, alert: dict) -> bool:
        rule_name = alert.get("rule_name", "").lower()
        text = f"{rule_name} {alert.get('description', '')}".lower()
        categories = {c.strip().lower() for c in re.split(r"[,;|]", alert.get("category", "")) if c.strip()}

        return (
            alert.get("rule_id", "") in rule["rule_ids"]
            or any(n in rule_name for n in rule["rule_names"])
            or any(k in text for k in rule["keywords"])
            or bool(categories & rule["categories"])
            or any(p.search(text) for p in rule["regex"])
        )

    def map_alert(self, alert: dict) -> list[dict]:
        """Return the list of matched techniques (never empty: falls back to UNMAPPED)."""
        found, seen = [], set()
        for rule in self.rules:
            if rule["technique_id"] in seen or not self._matches(rule, alert):
                continue
            seen.add(rule["technique_id"])
            found.append({
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"],
                "rule": rule["name"],
            })
        return found or [dict(UNMAPPED)]

    def summary(self) -> list[dict]:
        """Rules as plain dicts for the /api/rules endpoint."""
        return [
            {"name": r["name"], "technique_id": r["technique_id"],
             "technique_name": r["technique_name"], "tactic": r["tactic"]}
            for r in self.rules
        ]
