"""Bounded, data-only standards language. No Python expressions are executed."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field

import regex

from standards_catalog import SENSITIVE, sanitized, schema_fields
from security import session_secret

MISSING = object()
OPERATORS = ("eq", "ne", "gt", "gte", "lt", "lte", "matches", "in", "contains", "exists", "absent")


class EvaluationError(ValueError):
    pass


def path_value(value, path):
    if not path:
        return value
    key, *tail = path
    if key == "*":
        if not isinstance(value, (dict, list)):
            return MISSING
        children = value.values() if isinstance(value, dict) else value
        return [path_value(child, tail) for child in children]
    if isinstance(value, dict):
        return path_value(value[key], tail) if key in value else MISSING
    if isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
        return path_value(value[key], tail)
    return MISSING


def validate_path(path):
    if not isinstance(path, list) or len(path) > 20 or any(
        type(p) not in (str, int) or isinstance(p, str) and len(p) > 250 or isinstance(p, int) and p < 0 for p in path
    ):
        raise ValueError("A field path must be a list of keys, indexes, or * (up to 20 parts)")


def compile_pattern(pattern):
    if not isinstance(pattern, str) or len(pattern) > 2000:
        raise ValueError("Regex patterns must contain at most 2,000 characters")
    try:
        return regex.compile(pattern, regex.VERSION0)
    except regex.error as exc:
        raise ValueError(f"Invalid regex: {exc}") from exc


def semantic_hash(policy):
    semantic = {key: policy.get(key) for key in ("target", "when", "requirement")}
    if policy.get("_source_semantics"):
        semantic["sources"] = policy["_source_semantics"]
    return hashlib.sha256(json.dumps(semantic, sort_keys=True, allow_nan=False).encode()).hexdigest()


def validate_policy(policy, sources, specialist_validator=None):
    if not isinstance(policy, dict) or len(json.dumps(policy, allow_nan=False)) > 128000:
        raise ValueError("Policy must be an object smaller than 128 KB")
    if not isinstance(policy.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}", policy["id"]):
        raise ValueError("Policy ID must contain 1–80 letters, numbers, underscores, or hyphens")
    if not isinstance(policy.get("name"), str) or not 1 <= len(policy["name"].strip()) <= 200:
        raise ValueError("Enter a policy name of 1–200 characters")
    if policy.get("severity", "warning") not in ("info", "warning", "error"):
        raise ValueError("Severity must be info, warning, or error")
    if type(policy.get("enabled", True)) is not bool:
        raise ValueError("Enabled must be true or false")
    if not isinstance(policy.get("requirement"), dict):
        raise ValueError("A requirement is required")
    if policy["requirement"].get("kind") != "specialist" and not re.fullmatch(r"custom_[A-Za-z0-9_-]{1,73}", policy["id"]):
        raise ValueError("Custom policy IDs must start with custom_")
    validate_selector(policy.get("target", {}))
    source_ids = {s["id"] for s in sources}
    source_map = {s["id"]: s for s in sources}
    nodes = 0

    def known_types(expr):
        if expr.get("kind") == "capture":
            return {"string"}
        if expr.get("kind") == "count":
            return {"number", "integer"}
        if expr.get("kind") == "literal":
            value = expr.get("value")
            return {"null" if value is None else "boolean" if type(value) is bool else "number" if type(value) in (int, float) else
                    "array" if isinstance(value, list) else "object" if isinstance(value, dict) else "string"}
        if expr.get("kind") != "field" or expr.get("source") not in source_map:
            return set()
        source = source_map[expr["source"]]
        actual_path = expr["path"]
        for f in schema_fields(source["operation"], source.get("record_path"), collection=source["scope"] != "device"):
            if len(f["path"]) == len(actual_path) and all(a == b or a == "*" for a, b in zip(f["path"], actual_path)):
                types = set()
                for t in f["types"]:
                    types.update(t if isinstance(t, list) else [t])
                return types - {"unknown", "null"}
        return set()  # Observed-only fields are validated against their actual live type.

    def operand(value, depth):
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 250:
            raise ValueError("Policy expressions are limited to 250 nodes and 16 levels")
        if not isinstance(value, dict):
            raise ValueError("Operands must be literal, field, count, or capture objects")
        kind = value.get("kind")
        if kind == "literal":
            if "value" not in value:
                raise ValueError("Literal value is required")
            return
        if kind == "field":
            if not isinstance(value.get("source"), str) or value["source"] not in source_ids | {"$item", "$target"}:
                raise ValueError("Choose a registered field source")
            validate_path(value.get("path"))
            if value.get("on", "current") not in ("current", "root"):
                raise ValueError("Field context must be current or root")
        elif kind in ("count", "capture"):
            operand(value.get("value"), depth + 1)
            if kind == "capture":
                compiled = compile_pattern(value.get("pattern"))
                if type(value.get("group")) not in (str, int):
                    raise ValueError("A capture group must be a name or number")
                if value.get("group") not in compiled.groupindex and value.get("group") not in range(compiled.groups + 1):
                    raise ValueError("Choose a group present in the capture pattern")
            if value.get("where") is not None:
                condition(value["where"], depth + 1)
        else:
            raise ValueError("Unknown operand kind")

    def condition(node, depth=0):
        nonlocal nodes
        nodes += 1
        if not isinstance(node, dict) or depth > 16 or nodes > 250:
            raise ValueError("Invalid condition or expression limit exceeded")
        kind = node.get("kind")
        if kind in ("all", "any"):
            if not isinstance(node.get("children"), list) or not node["children"]:
                raise ValueError("All / Any groups require at least one condition")
            for child in node["children"]:
                condition(child, depth + 1)
        elif kind == "not":
            condition(node.get("child"), depth + 1)
        elif kind == "compare":
            op = node.get("op")
            if op not in OPERATORS:
                raise ValueError("Unknown comparison operator")
            operand(node.get("left"), depth + 1)
            if op not in ("exists", "absent"):
                operand(node.get("right"), depth + 1)
            if op == "matches":
                if node["right"].get("kind") != "literal":
                    raise ValueError("A regex pattern must be a literal")
                compile_pattern(node["right"].get("value"))
            # Catch unambiguous type errors before activation; live types are checked too.
            if op in ("gt", "gte", "lt", "lte") and node.get("right", {}).get("kind") == "literal":
                v = node["right"].get("value")
                if type(v) not in (int, float):
                    raise ValueError("Numeric comparisons require a numeric value")
            if op == "in" and node.get("right", {}).get("kind") == "literal" and not isinstance(node["right"].get("value"), list):
                raise ValueError("Membership requires a list")
            if op not in ("exists", "absent", "contains") and node.get("left", {}).get("kind") == "field" and "*" in node["left"].get("path", []):
                raise ValueError("Wildcard fields require an explicit collection quantifier or count")
            types = known_types(node["left"])
            if op == "matches" and types and "string" not in types:
                raise ValueError("Regex requires a string field")
            if op in ("gt", "gte", "lt", "lte") and types and not types & {"number", "integer"}:
                raise ValueError("Numeric comparisons require a numeric field or count")
            if op in ("eq", "ne", "in", "matches") and types and types <= {"array", "object"}:
                raise ValueError("Collection fields require an explicit quantifier or count")
        elif kind == "collection":
            operand(node.get("value"), depth + 1)
            if node.get("quantifier") not in ("every", "any", "none"):
                raise ValueError("Choose every, any, or none; use a count operand for counts")
            condition(node.get("requirement"), depth + 1)
        elif kind == "related":
            validate_selector(node.get("selector", {}))
            if node.get("scope", "site") not in ("site", "organization"):
                raise ValueError("Relationship scope must be site or organization")
            if node.get("quantifier") not in ("every", "any", "none", "one"):
                raise ValueError("Choose an explicit relationship quantifier")
            operand(node.get("left"), depth + 1)
            operand(node.get("right"), depth + 1)
            condition(node.get("requirement"), depth + 1)
        elif kind == "unique":
            operand(node.get("value"), depth + 1)
            validate_selector(node.get("selector", {}))
        elif kind == "specialist":
            if not specialist_validator:
                raise ValueError("Specialist blocks are unavailable")
            specialist_validator(node, policy)
        else:
            raise ValueError("Unknown requirement kind")

    if policy.get("when") is not None:
        condition(policy["when"])
    condition(policy.get("requirement"))
    return policy


def validate_selector(selector):
    if not isinstance(selector, dict) or selector.get("kind", "device") not in ("device", "site", "organization"):
        raise ValueError("Choose a device, site, or organization target")
    for key in ("org_ids", "site_ids", "device_types", "models"):
        if key in selector and (not isinstance(selector[key], list) or any(not isinstance(x, str) or len(x) > 200 for x in selector[key])):
            raise ValueError(f"{key} must be a list of names or identifiers")
    if any(t not in ("ap", "switch", "gateway") for t in selector.get("device_types", [])):
        raise ValueError("Device types must be ap, switch, or gateway")


def selected(target, selector):
    if target["kind"] != selector.get("kind", "device"):
        return False
    for key, field_name in (("org_ids", "org_id"), ("site_ids", "site_id"), ("device_types", "type"), ("models", "model")):
        if selector.get(key) and target.get(field_name) not in selector[key]:
            return False
    return True


@dataclass
class Snapshot:
    targets: list = field(default_factory=list)
    records: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    complete_orgs: set = field(default_factory=set)
    collected_at: str = ""
    _indexes: dict = field(default_factory=dict)

    def resolve(self, source_id, target):
        source = self.sources[source_id]
        relevant = lambda x: x.get("org_id") == target.get("org_id") and (
            not x.get("site_id") or x.get("site_id") == target.get("site_id")) and (
            not x.get("type") or x.get("type") == target.get("type")) and (
            not x.get("device_id") or x.get("device_id") == target.get("id"))
        if any(e["source"] == source_id and relevant(e) for e in self.errors):
            raise EvaluationError(f"{source['name']}: collection is incomplete")
        if source_id not in self._indexes:
            by_scope = {}
            for record in self.records.get(source_id, []):
                key = (record.get("org_id"), record.get("site_id"), record.get("device_id"))
                by_scope.setdefault(key, []).append(record["value"])
                if record.get("mac"):
                    mac_key = (record.get("org_id"), record.get("site_id"), "mac:" + normalize_mac(record["mac"]))
                    by_scope.setdefault(mac_key, []).append(record["value"])
            self._indexes[source_id] = by_scope
        index = self._indexes[source_id]
        keys = [(target.get("org_id"), target.get("site_id"), None), (target.get("org_id"), None, None)]
        if source["scope"] == "device":
            if target["kind"] != "device":
                raise EvaluationError("Device fields need a device target or an explicit related-device rule")
            keys = [(target.get("org_id"), site, identity) for site in (target.get("site_id"), None)
                    for identity in (target.get("id"), "mac:" + normalize_mac(target.get("mac", "")))]
        values = next((index[key] for key in keys if key in index), [])
        if not values:
            return MISSING
        if len(values) > 1:
            raise EvaluationError("Source mapping is ambiguous; use a unique identity or a collection source")
        return values[0]


def normalize_mac(value):
    return re.sub(r"[^a-f0-9]", "", str(value).lower())


class Evaluator:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.steps = 0
        self.deadline = time.monotonic() + 20
        self.evidence = []
        self.missing_count = 0
        self.unique_indexes = {}

    def tick(self):
        self.steps += 1
        if self.steps > 500000 or time.monotonic() > self.deadline:
            raise EvaluationError("Policy evaluation limit exceeded")

    def value(self, node, target, root, item=MISSING):
        self.tick()
        kind = node["kind"]
        if kind == "literal":
            return node["value"]
        if kind == "field":
            source = node["source"]
            obj = root if node.get("on") == "root" else target
            raw = item if source == "$item" else obj if source == "$target" else self.snapshot.resolve(source, obj)
            result = path_value(raw, node["path"])
            if len(self.evidence) < 40:
                sensitive = any(SENSITIVE.search(str(p)) for p in node["path"])
                evidence = {"source": source, "path": node["path"], "present": result is not MISSING,
                            "value": "[redacted]" if sensitive else safe_value(result)}
                if result is not MISSING:
                    # Complete evidence stays value-specific even when the display is
                    # redacted or truncated. A keyed digest avoids exposing secret hashes.
                    raw = json.dumps(_canonical_evidence(result), sort_keys=True, allow_nan=False).encode()
                    evidence["value_digest"] = hmac.new(session_secret().encode(), raw, hashlib.sha256).hexdigest()
                self.evidence.append(evidence)
            return result
        value = self.value(node["value"], target, root, item)
        if value is MISSING:
            return MISSING
        if kind == "count":
            if not isinstance(value, (list, dict)):
                raise EvaluationError("Count requires an array or dictionary")
            values = value.values() if isinstance(value, dict) else value
            return sum(1 for child in values if node.get("where") is None or self.condition(node["where"], target, root, child))
        if kind == "capture":
            if not isinstance(value, str):
                raise EvaluationError("Regex capture requires a string")
            match = pattern_match(node["pattern"], value)
            return match.group(node["group"]) if match else MISSING
        raise EvaluationError("Unknown operand")

    def peers(self, node, target):
        if node.get("scope", "organization") == "organization" and target["org_id"] not in self.snapshot.complete_orgs:
            raise EvaluationError("Organization data is incomplete")
        return [p for p in self.snapshot.targets if p.get("org_id") == target["org_id"]
                and (node.get("scope", "organization") != "site" or p.get("site_id") == target.get("site_id"))
                and selected(p, node.get("selector", {"kind": "device"}))]

    def condition(self, node, target, root=None, item=MISSING):
        self.tick()
        root = root or target
        kind = node["kind"]
        if kind in ("all", "any"):
            values, errors = [], []
            for child in node["children"]:
                try:
                    values.append(self.condition(child, target, root, item))
                except EvaluationError as exc:
                    errors.append(exc)
            if kind == "all" and False in values:
                return False
            if errors:
                raise errors[0]
            return all(values) if kind == "all" else any(values)
        if kind == "not":
            missing_before = self.missing_count
            value = self.condition(node["child"], target, root, item)
            return self.missing_count == missing_before and not value
        if kind == "compare":
            left = self.value(node["left"], target, root, item)
            op = node["op"]
            if op in ("exists", "absent"):
                return (left is not MISSING) == (op == "exists")
            right = self.value(node["right"], target, root, item)
            if left is MISSING or right is MISSING:
                self.missing_count += 1
                return False
            if isinstance(left, (dict, list)) and op not in ("contains",):
                raise EvaluationError("Choose an explicit collection quantifier or count")
            if op in ("gt", "gte", "lt", "lte"):
                if any(type(x) not in (int, float) or not math.isfinite(x) for x in (left, right)):
                    raise EvaluationError("Numeric comparison received a non-numeric value")
                return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]
            if op == "matches":
                if not isinstance(left, str):
                    raise EvaluationError("Regex requires a string field")
                return bool(pattern_match(right, left))
            if op == "in":
                if not isinstance(right, list):
                    raise EvaluationError("Membership requires a list")
                return any(type(left) is type(v) and left == v for v in right)
            if op == "contains":
                if not isinstance(left, (str, list, dict)) or isinstance(left, str) and not isinstance(right, str):
                    raise EvaluationError("Contains requires compatible strings or a collection")
                return right in left
            if left is not None and right is not None and type(left) is not type(right) and not (type(left) in (int, float) and type(right) in (int, float)):
                raise EvaluationError("Equality requires compatible field types")
            return (left == right) if op == "eq" else (left != right)
        if kind == "collection":
            value = self.value(node["value"], target, root, item)
            if value is MISSING:
                self.missing_count += 1
                return False
            if not isinstance(value, (dict, list)):
                raise EvaluationError("Collection rule requires an array or dictionary")
            values = list(value.values()) if isinstance(value, dict) else value
            return self.quantify(node["quantifier"], values, lambda child: self.condition(node["requirement"], target, root, child))
        if kind == "related":
            left = self.value(node["left"], target, root, item)
            if left is MISSING:
                self.missing_count += 1
                return False
            matches = []
            for peer in self.peers({"scope": node.get("scope", "site"), "selector": node.get("selector", {})}, target):
                right = self.value(node["right"], peer, root)
                if right is not MISSING and type(right) is type(left) and right == left:
                    matches.append(peer)
            if node["quantifier"] == "one" and len(matches) > 1:
                raise EvaluationError("Relationship matched more than one device")
            if len(self.evidence) < 40:
                self.evidence.append({"related_targets": [{"id": p["id"], "site_id": p.get("site_id"), "name": p.get("name")} for p in matches[:30]]})
            return self.quantify(node["quantifier"], matches, lambda peer: self.condition(node["requirement"], peer, root))
        if kind == "unique":
            value = self.value(node["value"], target, root, item)
            if value is MISSING:
                self.missing_count += 1
                return False
            if isinstance(value, (dict, list)):
                raise EvaluationError("Uniqueness requires a scalar field")
            cache_key = (json.dumps(node, sort_keys=True), target["org_id"])
            if cache_key not in self.unique_indexes:
                index = {}
                for peer in self.peers(node, target):
                    observed = self.value(node["value"], peer, peer)
                    if observed is not MISSING:
                        index.setdefault(json.dumps(observed, sort_keys=True), []).append(peer)
                self.unique_indexes[cache_key] = index
            peers = self.unique_indexes[cache_key].get(json.dumps(value, sort_keys=True), [])
            others = [p for p in peers if (p["kind"], p.get("site_id"), p["id"]) != (target["kind"], target.get("site_id"), target["id"])]
            if others and len(self.evidence) < 40:
                self.evidence.append({"duplicates": [{"id": p["id"], "site_id": p.get("site_id"), "name": p.get("name")} for p in others[:30]]})
            return not others
        raise EvaluationError("Specialist blocks must be evaluated through the specialist adapter")

    @staticmethod
    def quantify(mode, values, evaluate):
        results, errors = [], []
        for value in values:
            try:
                results.append(evaluate(value))
            except EvaluationError as exc:
                errors.append(exc)
        if mode in ("every", "one") and False in results:
            return False
        if mode == "none" and True in results:
            return False
        if errors:
            raise errors[0]
        if mode in ("every", "one"):
            return bool(values) and all(results)
        return any(results) if mode == "any" else not any(results)


def pattern_match(pattern, value):
    if len(value) > 65536:
        raise EvaluationError("Regex input exceeds 65,536 characters")
    try:
        return compile_pattern(pattern).fullmatch(value, timeout=0.025)
    except TimeoutError as exc:
        raise EvaluationError("Regex evaluation exceeded 25 milliseconds") from exc


def safe_value(value):
    if value is MISSING:
        return None
    if isinstance(value, list):
        return [safe_value(v) for v in value[:30]]
    return sanitized(value)


def _canonical_evidence(value):
    if value is MISSING:
        return {"missing": True}
    if isinstance(value, list):
        return [_canonical_evidence(v) for v in value]
    if isinstance(value, dict):
        return {k: _canonical_evidence(v) for k, v in value.items()}
    return value


def required_sources(policies):
    found = set()
    def walk(value):
        if isinstance(value, dict):
            if value.get("kind") == "field" and not value.get("source", "").startswith("$"):
                found.add(value["source"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(policies)
    return found


def needs_organization(policies):
    def walk(value):
        if isinstance(value, dict):
            return value.get("kind") == "unique" or value.get("kind") == "related" and value.get("scope") == "organization" or any(walk(v) for v in value.values())
        return isinstance(value, list) and any(walk(v) for v in value)
    return walk(policies)


def evaluate_policy(policy, snapshot, selected_sites=None):
    evaluator = Evaluator(snapshot)
    results = []
    for target in snapshot.targets:
        if selected_sites is not None and target["kind"] != "organization" and target.get("site_id") not in selected_sites:
            continue
        if not selected(target, policy.get("target", {})):
            continue
        evaluator.evidence = []
        try:
            if policy.get("when") is not None and not evaluator.condition(policy["when"], target):
                status, message = "excluded", "Applicability conditions did not match"
            else:
                passed = evaluator.condition(policy["requirement"], target)
                status, message = ("pass", "Requirement satisfied") if passed else ("fail", "Requirement not satisfied")
        except (EvaluationError, TypeError, ValueError, KeyError) as exc:
            status, message = "unevaluated", str(exc)
        results.append({"target": {k: v for k, v in target.items() if k != "raw"}, "status": status,
                        "message": message, "evidence": list(evaluator.evidence)})
    return results
