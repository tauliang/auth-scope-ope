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

# The signing-key pin file is trusted implicitly, so the lock pins its exact
# bytes and this gate re-verifies structure: format tag, root fingerprint,
# and a root entry whose fingerprint matches.
pin_path = f"{root}/contracts/authscope-signing-keys.json"
try:
    pin_raw = open(pin_path, "rb").read()
except OSError as e:
    errors.append(f"signing-key pin file missing: {e}")
else:
    pin_digest = hashlib.sha256(pin_raw).hexdigest()
    if pin_digest != lock.get("signing_keys_sha256", ""):
        errors.append(
            f"signing-key pin digest mismatch: got {pin_digest}, "
            f"lock wants {lock.get('signing_keys_sha256', '')!r}"
        )
    try:
        pin = json.loads(pin_raw.decode("utf-8"))
    except ValueError as e:
        errors.append(f"signing-key pin file is not JSON: {e}")
        pin = None
    if pin is not None:
        if pin.get("format") != "authscope-signing-keys/v1":
            errors.append(f"signing-key pin format {pin.get('format')!r} is not authscope-signing-keys/v1")
        fp = pin.get("signing_root_fingerprint", "")
        if not (isinstance(fp, str) and fp.startswith("sha256:") and len(fp) == len("sha256:") + 64):
            errors.append("signing-key pin has no well-formed signing_root_fingerprint")
        roots = [k for k in (pin.get("keys") or []) if isinstance(k, dict) and k.get("root")]
        if len(roots) != 1:
            errors.append(f"signing-key pin has {len(roots)} root entries, want exactly 1")
        elif fp:
            import base64 as _b64
            try:
                raw_pub = _b64.urlsafe_b64decode(roots[0].get("public_key", "") + "==")
                calc = "sha256:" + hashlib.sha256(raw_pub).hexdigest()
            except Exception:
                calc = ""
            if calc != fp:
                errors.append("signing-key pin root entry does not match signing_root_fingerprint")

print("contract-ready: " + ("RED" if errors else "GREEN"))
for e in errors:
    print(f"ERROR: {e}")
for w in warnings:
    print(f"WARN: {w}")
sys.exit(1 if errors else 0)
PY
