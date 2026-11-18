"""Extract a reviewable passive catalog from an official Mist OpenAPI export.

Usage: python scripts/build_standards_catalog.py downloaded-mist-openapi.json
The export URL, original SHA-256 and version are retained with the generated data.
No network request is performed by this build step.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def extract(raw):
    spec = json.loads(raw.decode("utf-8", errors="replace"))
    refs, operations = {}, []

    def resolve(ref):
        result = spec
        for key in ref.removeprefix("#/").split("/"):
            result = result[key.replace("~1", "/").replace("~0", "~")]
        return result

    def compact(value):
        if isinstance(value, list):
            return [compact(v) for v in value]
        if not isinstance(value, dict):
            return value
        return {k: compact(v) for k, v in value.items() if k not in {"example", "examples", "x-examples", "xml", "externalDocs"}}

    def collect(value):
        if isinstance(value, dict):
            ref = value.get("$ref")
            if ref and ref not in refs:
                refs[ref] = compact(resolve(ref))
                collect(resolve(ref))
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    for path, item in spec["paths"].items():
        op = item.get("get")
        if not op or not path.startswith(("/api/v1/sites/", "/api/v1/orgs/")):
            continue
        schema = op.get("responses", {}).get("200", {}).get("content", {}).get("application/json", {}).get("schema")
        parameters = [compact(resolve(p["$ref"]) if "$ref" in p else p)
                      for p in item.get("parameters", []) + op.get("parameters", [])]
        reason = None
        if not schema:
            reason = "This endpoint does not describe a JSON response."
        if re.search(r"/(?:psks?|secrets?|credentials?|apitokens?|admins?|webhooks?|config_cmd|export|synthetic_test)(?:/|$)", path):
            reason = "This endpoint is not available as a passive standards source."
        if any(p.get("in") not in ("path", "query") for p in parameters):
            reason = "Unsupported parameter location."
        if schema and not reason:
            collect(schema)
        operations.append({"id": op["operationId"], "path": path.removeprefix("/api/v1"),
                           "name": op.get("summary", op["operationId"]), "description": op.get("description", "")[:500],
                           "parameters": parameters, "schema": compact(schema or {}), "supported": not reason, "reason": reason})
    return {"version": spec["info"]["version"],
            "source": "https://www.juniper.net/documentation/us/en/software/mist/api/static/exports/mist-api-openapi31json.json",
            "sha256": hashlib.sha256(raw).hexdigest(), "operations": operations, "refs": refs}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "backend/mist_standards_catalog.json")
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.input.read_bytes()), ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
