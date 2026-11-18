"""Bridge the editable catalog to existing audits and value-specific exceptions."""
from __future__ import annotations

import copy

import audit_exceptions as exceptions
import compliance as c
import standards_store as store
from standards_catalog import sanitized
from standards_collector import Collector
from standards_engine import Evaluator, EvaluationError, evaluate_policy, needs_organization, required_sources, selected, semantic_hash
from standards_specialists import OPTIONS, instantiate


class FieldPolicyCheck(c.ComplianceCheck):
    def __init__(self, policy):
        self.policy = policy
        self.id, self.name = policy["id"], policy["name"]
        self.description, self.severity = policy.get("description", ""), policy.get("severity", "warning")
        self.evaluations = []

    def run(self, context):
        findings = []
        for result in self.evaluations:
            target = result["target"]
            if target.get("site_id") != context.site_id and not (target["kind"] == "organization" and context.site_id == self.first_site):
                continue
            if result["status"] != "fail":
                continue
            device_id = target["id"] if target["kind"] == "device" else None
            details = {"policy_id": self.id, "policy_hash": semantic_hash(self.policy), "evidence": result["evidence"],
                       "expected": sanitized(self.policy["requirement"]), "scope": target["kind"], "org_id": target.get("org_id")}
            finding = c.Finding(site_id=context.site_id, site_name=context.site_name,
                                device_id=device_id, device_name=target.get("name") if device_id else None,
                                message=f"{self.name}: {result['message']}", severity=self.severity, details=details)
            finding.exception_candidate = exceptions.candidate_for(context, self.id, device_id,
                "policy." + self.id, result["evidence"], {"policy_hash": semantic_hash(self.policy)}, context.mist_base_url)
            findings.append(finding)
        return findings


def _specialist_run(check, context):
    policy = check.policy
    target = {"kind": "site", "id": context.site_id, "site_id": context.site_id, "org_id": context.site.get("org_id") or context.setting.get("org_id"), "name": context.site_name}
    status, message, findings = "pass", "Requirement satisfied", []
    if not selected(target, policy.get("target", {"kind": "site"})):
        status, message = "excluded", "Target selector did not match"
    else:
        try:
            if policy.get("when") and not Evaluator(check.snapshot).condition(policy["when"], target):
                status, message = "excluded", "Applicability conditions did not match"
            elif check.id == "switch_cable_test" and check.passive:
                status, message = "unevaluated", "Active diagnostics require an explicitly requested active audit"
            else:
                token = OPTIONS.set(policy["requirement"]["parameters"])
                try:
                    findings = check.original_run(context)
                finally:
                    OPTIONS.reset(token)
                status = "fail" if findings else "pass"
                # Preserve legacy findings but never certify incomplete collection.
                if not findings and (context.unavailable_sources or context.unavailable_device_ids):
                    status, message = "unevaluated", "Required site/device evidence is incomplete"
                if not findings and getattr(check, "source_errors", None):
                    status, message = "unevaluated", "; ".join(check.source_errors[-10:])
                if check.id == "firmware_management" and not check.allowed_switch_versions and not check.allowed_ap_versions:
                    status, message = "unevaluated", "No approved firmware versions are available"
        except (EvaluationError, TimeoutError, ValueError, c.requests.RequestException) as exc:
            status, message = "unevaluated", str(exc)
    check.evaluations.append({"target": target, "status": status, "message": message, "evidence": []})
    return findings


class CatalogRunner(c.SiteAuditRunner):
    def __init__(self, checks, document, *, include_active_checks=False):
        super().__init__(checks)
        self.document = document
        self.include_active_checks = include_active_checks

    def run(self, contexts, *, exception_records=None, origin=""):
        if not contexts:
            return super().run(contexts, exception_records=exception_records, origin=origin)
        generic = [check for check in self.checks if isinstance(check, FieldPolicyCheck)]
        policies = [check.policy for check in self.checks]
        needed = required_sources(policies)
        snapshot = None
        if generic or needed:
            needed.add("device_config")
            snapshot = Collector(origin or contexts[0].mist_base_url, contexts[0].mist_headers).collect(
                [s for s in self.document["sources"] if s["id"] in needed], contexts,
                full_organization=needs_organization(policies))
        for check in self.checks:
            check.evaluations = []
            if isinstance(check, FieldPolicyCheck):
                check.evaluations = evaluate_policy(check.policy, snapshot, {ctx.site_id for ctx in contexts})
                # Target-population errors must be visible even when no records could be read.
                for error in snapshot.errors:
                    if error["source"] == "device_config" and (not error.get("site_id") or error.get("site_id") in {ctx.site_id for ctx in contexts}):
                        check.evaluations.append({"target": {"kind": "site", "site_id": error.get("site_id"), "id": error.get("site_id"), "org_id": error.get("org_id")},
                                                  "status": "unevaluated", "message": error["error"], "evidence": []})
                check.first_site = contexts[0].site_id
            else:
                check.snapshot = snapshot
                check.passive = not self.include_active_checks
        result = super().run(contexts, exception_records=exception_records, origin=origin)
        for check, payload in zip(self.checks, result["checks"]):
            evaluations = check.evaluations
            coverage = {status: sum(r["status"] == status for r in evaluations)
                        for status in ("pass", "fail", "excluded", "unevaluated")}
            payload.update(scope=check.policy.get("target", {}).get("kind", "device"),
                           policy_revision=check.policy["revision"], policy_hash=semantic_hash(check.policy),
                           evaluations=evaluations, coverage=coverage)
            unknown_sites = {r["target"].get("site_id") for r in evaluations if r["status"] in ("unevaluated", "excluded")}
            payload["passing_sites"] = len({r["target"].get("site_id") for r in evaluations if r["status"] == "pass"}
                                           - unknown_sites - set(payload["failing_sites"]))
            payload["organization_findings"] = [f for f in payload["findings"] if f.get("details", {}).get("scope") == "organization"]
            if not isinstance(check, FieldPolicyCheck):
                for action in payload.get("actions", []) + [a for f in payload["findings"] for a in f.get("actions", [])]:
                    action.setdefault("metadata", {}).update(standard_policy_id=check.id, standard_policy_hash=semantic_hash(check.policy))
        result["evaluation_coverage"] = {status: sum(ch["coverage"][status] for ch in result["checks"])
                                         for status in ("pass", "fail", "excluded", "unevaluated")}
        result["collection_errors"] = snapshot.errors if snapshot else []
        result["collected_at"] = snapshot.collected_at if snapshot else None
        result["standards_revision"] = self.document["revision"]
        return result


def build_runner(check_ids=None, *, refresh_standards=True, include_active_checks=False, document=None):
    document = document or store.load()
    checks = []
    for policy in document["policies"]:
        if not policy.get("enabled", True) or check_ids is not None and policy["id"] not in check_ids:
            continue
        if policy["requirement"]["kind"] == "specialist":
            if policy["requirement"]["check"] == "switch_cable_test" and not include_active_checks:
                continue
            check = instantiate(policy, refresh_standards)
            check.original_run = check.run
            check.run = lambda context, check=check: _specialist_run(check, context)
        else:
            policy = copy.deepcopy(policy)
            policy["_source_semantics"] = [{k: v for k, v in s.items() if k not in ("name", "revision")}
                                           for s in document["sources"] if s["id"] in required_sources(policy)]
            check = FieldPolicyCheck(policy)
        checks.append(check)
    return CatalogRunner(checks, document, include_active_checks=include_active_checks)
