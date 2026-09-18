#!/usr/bin/env bash
# Verifies the vendored AuthScope OpenAPI document against the OPE capability
# manifest and the contract lock. This is the Task 1 hard gate: it must exit
# non-zero (red) until an immutable compatible AuthScope release satisfies
# every required operation. Usage: scripts/verify-contract.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT" <<'PY'
import json, re, sys, hashlib
import yaml

root = sys.argv[1]
lock = json.load(open(f"{root}/contracts/authscope.lock.json"))
manifest = json.load(open(f"{root}/contracts/ope-required-capabilities.json"))
spec_path = f"{root}/contracts/authscope-v1.yaml"

raw = open(spec_path, "rb").read()
digest = hashlib.sha256(raw).hexdigest()
errors, warnings = [], []

if digest != lock["openapi_sha256"]:
    errors.append(
        f"vendored OpenAPI digest mismatch: got {digest}, lock wants {lock['openapi_sha256']}"
    )

doc = yaml.safe_load(raw.decode("utf-8"))
paths = doc.get("paths", {}) or {}
schemas = set(((doc.get("components", {}) or {}).get("schemas", {}) or {}).keys())
sec_schemes = set(((doc.get("components", {}) or {}).get("securitySchemes", {}) or {}).keys())
sec_text = json.dumps(doc.get("components", {}).get("securitySchemes", {})).lower()
has_workload_scheme = any(k in sec_text for k in ("mtls", "mutualtls", "workload", "clientcert", "x509"))

def norm(p):
    return re.sub(r"\{[^}]+\}", "{x}", p)

indexed = {(norm(p), m.lower()): p for p, item in paths.items() for m in (item or {}) if m in ("get","post","put","patch","delete","head","options")}

for op in manifest["required_operations"]:
    cap, method, path = op["capability"], op["method"].lower(), op["path"]
    if (norm(path), method) not in indexed:
        errors.append(f"missing {op['method']} {path}  [{cap}]")
    for schema_key in ("request_schema", "response_schema"):
        name = op.get(schema_key, "")
        if name and name not in schemas:
            close = sorted(s for s in schemas if name.lower() in s.lower() or s.lower() in name.lower())
            hint = f" (closest: {', '.join(close[:3])})" if close else ""
            warnings.append(f"schema {name} not found for {op['method']} {path} [{cap}]{hint}")
    rp = op.get("reconcile_path", "")
    if rp:
        rp_method, rp_path = rp.split(" ", 1)
        if (norm(rp_path), rp_method.lower()) not in indexed:
            errors.append(f"missing reconcile {rp} for {op['method']} {path} [{cap}]")
    if op.get("security_scheme") == "workload_identity_mtls" and not has_workload_scheme:
        errors.append(
            f"no workload-identity/mTLS security scheme for {op['method']} {path} [{cap}]; "
            f"vendored schemes: {sorted(sec_schemes)}"
        )

version, kind = lock.get("core_version", ""), lock.get("core_version_kind", "")
if kind != "release":
    errors.append(
        f"core version {version!r} is kind {kind!r}, not an immutable release; "
        "Task 2 has no authorized start condition"
    )

print("contract-ready: " + ("RED" if errors else "GREEN"))
for e in errors:
    print(f"ERROR: {e}")
for w in warnings:
    print(f"WARN: {w}")
sys.exit(1 if errors else 0)
PY
