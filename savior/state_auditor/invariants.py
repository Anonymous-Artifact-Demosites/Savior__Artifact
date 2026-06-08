"""Rule-based invariant evaluation for SAVIOR tasks (Section 5.2.3).

Loads task definitions from configs/invariants.yaml and provides a minimal
rule engine that evaluates structured conditions against observations JSON.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import yaml


_loaded_configs: dict | None = None


def _configs_path() -> Path:
    """Return the path to configs/invariants.yaml, supporting both layouts."""
    base = Path(__file__).resolve()
    # Bundled layout: savior/state_auditor/invariants.py -> savior/configs/
    bundled = base.parents[1] / "configs" / "invariants.yaml"
    if bundled.exists():
        return bundled
    # Alternate layout: repo/savior/state_auditor/invariants.py -> repo/configs/
    return base.parents[2] / "configs" / "invariants.yaml"


def _load_configs() -> dict:
    """Load and cache the invariants YAML. Returns the 'tasks' dict."""
    global _loaded_configs
    if _loaded_configs is None:
        with open(_configs_path(), "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        _loaded_configs = raw.get("tasks", {})
    return _loaded_configs


def reload_configs() -> None:
    """Force re-read of invariants.yaml (useful after tests modify the file)."""
    global _loaded_configs
    _loaded_configs = None


def get_task_config(task_id: str) -> dict:
    """Return the task config for *task_id*, enriched with runtime helpers.

    Adds ``statuses`` (alias for ``status_values``) and ``llm_status_pattern``
    so that verdict_parser and auditor can work without knowing the YAML schema.
    """
    configs = _load_configs()
    normalized = task_id.upper()
    if normalized not in configs:
        raise KeyError(f"Invariants for {task_id} are not defined in invariants.yaml")
    config = deepcopy(configs[normalized])

    # Backward-compat: expose status_values also as 'statuses'
    status_values = config.get("status_values", [])
    config["statuses"] = status_values

    # Generate regex pattern for fallback STATUS extraction
    if "llm_status_pattern" not in config and status_values:
        alternatives = "|".join(status_values)
        config["llm_status_pattern"] = rf"STATUS:\s*({alternatives})"

    return config


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _get_nested_value(payload: dict | None, dotted_path: str):
    """Walk a dotted path (e.g. ``task_specific.field``) into a nested dict."""
    current = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _evaluate_leaf(condition: dict, observations: dict | None):
    """Evaluate a leaf condition. Returns True, False, or None.

    None means the observation field is missing and the condition is
    indeterminate, distinct from a field that is explicitly False.
    """
    value = _get_nested_value(observations, condition["field"])
    if value is None:
        return None

    expected = condition.get("value")
    op = condition.get("operator")

    # LLM outputs may encode primitive JSON values as strings.
    if isinstance(expected, bool) and isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes"):
            value = True
        elif normalized in ("false", "0", "no"):
            value = False

    if isinstance(expected, (int, float)) and not isinstance(expected, bool) and isinstance(value, str):
        try:
            value = type(expected)(value.strip())
        except (ValueError, TypeError):
            pass

    if op == "eq":
        return value == expected
    if op == "neq":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "gt":
        return value > expected
    if op == "lt":
        return value < expected
    raise ValueError(f"Unsupported operator: {op}")


def _evaluate_condition(condition: dict, observations: dict | None):
    """Recursively evaluate a condition tree with three-valued logic."""
    ctype = condition.get("type")
    if ctype == "leaf":
        return _evaluate_leaf(condition, observations)
    if ctype == "all_of":
        results = [_evaluate_condition(c, observations) for c in condition.get("conditions", [])]
        if any(result is False for result in results):
            return False
        if any(result is None for result in results):
            return None
        return True
    if ctype == "any_of":
        results = [_evaluate_condition(c, observations) for c in condition.get("conditions", [])]
        if any(result is True for result in results):
            return True
        if any(result is None for result in results):
            return None
        return False
    if ctype == "not":
        inner = _evaluate_condition(condition["condition"], observations)
        if inner is None:
            return None
        return not inner
    raise ValueError(f"Unsupported condition type: {ctype}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _evaluate_verdict_rules(verdict_rules: list, invariant_results: dict, observations: dict) -> dict | None:
    """Walk a verdict_rule list top-to-bottom, return first determinate match."""
    for rule in verdict_rules:
        if rule.get("default"):
            if any(result is None for result in invariant_results.values()):
                return None
            return {"status": rule["status"], "reason": rule.get("reason", "")}

        condition = rule.get("condition", {})

        # Invariant-reference rule
        if "invariant" in condition:
            inv_id = condition["invariant"]
            expected_violated = condition.get("violated", True)
            actual_violated = invariant_results.get(inv_id)
            if actual_violated is None:
                continue
            if actual_violated == expected_violated:
                return {"status": rule["status"], "reason": rule.get("reason", "")}
            continue

        # Field-based rule
        if "type" in condition:
            eval_result = _evaluate_condition(condition, observations)
            if eval_result is None:
                continue
            if eval_result:
                return {"status": rule["status"], "reason": rule.get("reason", "")}
            continue

    return None


def evaluate_invariants(task_id: str, observations: dict | None) -> dict | None:
    """Evaluate rule-based invariants and return a verdict dict, or None.

    Implements the SAVIOR invariant rule engine.
    verdict_rule is a list evaluated top-to-bottom; first match wins.

    For T3_T4 (dual-status tasks), returns a dict with both status_t3 and
    status_t4 keys instead of a single status key.
    """
    if observations is None:
        return None

    config = get_task_config(task_id)

    # Pre-evaluate each invariant's check condition
    invariant_results: dict[str, bool] = {}
    for inv in config.get("invariants", []):
        invariant_results[inv["id"]] = _evaluate_condition(inv["check"], observations)

    # T3_T4 special case: dual verdict rules
    if "verdict_rule_t3" in config and "verdict_rule_t4" in config:
        t3 = _evaluate_verdict_rules(config["verdict_rule_t3"], invariant_results, observations)
        t4 = _evaluate_verdict_rules(config["verdict_rule_t4"], invariant_results, observations)
        return {
            "status_t3": t3["status"] if t3 else None,
            "reason_t3": t3["reason"] if t3 else "",
            "status_t4": t4["status"] if t4 else None,
            "reason_t4": t4["reason"] if t4 else "",
        }

    # Standard single verdict_rule
    return _evaluate_verdict_rules(config.get("verdict_rule", []), invariant_results, observations)
