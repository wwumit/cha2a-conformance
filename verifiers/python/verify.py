#!/usr/bin/env python3
"""did:cha2a conformance 参考验证器（Python，第一批）

覆盖：§3.1 did-syntax / §3.3 normalization / §4.5 outbound-sig / §5.2 discovery
用法：python3 verify.py <fixtures_dir> [--manifest MANIFEST.sha256]
输出：每向量 PASS/FAIL + 汇总；全过 exit 0
"""
import json, os, re, sys, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# ---- §3.1 ABNF：did:cha2a: type : id [#fragment] ----
TYPE_RE = re.compile(r"^[a-z][a-z_]*$")                    # ALPHA-LOWER *(ALPHA-LOWER/_)
ID_CHAR = r"A-Za-z0-9._~-"                                  # unreserved
ID_RE = re.compile(rf"^[{ID_CHAR}]+(:[{ID_CHAR}]+)*$")      # 1*(unreserved / ":")

def check_did_syntax(did):
    if not isinstance(did, str) or not did.startswith("did:cha2a:"):
        return False, "method 前缀"
    rest = did[len("did:cha2a:"):]
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        if not re.match(rf"^[{ID_CHAR}]+$", frag):
            return False, "fragment"
    parts = rest.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False, "缺 type:id"
    t, rid = parts
    if not TYPE_RE.match(t):
        return False, "type 非法"
    if not ID_RE.match(rid):
        return False, "id 非法"
    return True, ""

# ---- §3.3 规范化（第一批：方法名+类型小写；完整规则后续扩展，如实标注） ----
def normalize_did(did):
    if not check_did_syntax(did)[0]:
        return did
    method, rest = did.split(":", 2)[:2], did.split(":", 2)[2]
    t, rid = rest.split(":", 1)
    return f"did:{method[1].lower()}:{t.lower()}:{rid}"

# ---- §4.5 Ed25519 验签 ----
def verify_ed25519(pk_hex, msg, sig_hex):
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        pk.verify(bytes.fromhex(sig_hex), msg.encode())
        return True
    except (InvalidSignature, ValueError):
        return False

# ---- §5.2 discovery 结构 ----
def check_discovery(doc):
    if not isinstance(doc, dict):
        return False, "非对象"
    for field in ("registryDid", "supportedMethods", "publicKeys"):
        if not doc.get(field):
            return False, f"缺 {field}"
    if not isinstance(doc.get("publicKeys"), list) or not doc["publicKeys"]:
        return False, "publicKeys 非空列表"
    return True, ""

# ---- 逐向量判定 ----

# ---- §4.6 L0-L4 判定（按规范：contentIdentity/author/publisher/verifiedBy） ----
PREDICATE_SUBJECT = {
    "identity-anchor": ["agent"], "owner-binding": ["agent"],
    "number-binding": ["agent"], "delegation": ["agent"],
    "number-range-grant": ["org"],
}

def compute_level(metadata, verified_by, registered_verifiers, revoked):
    if revoked:
        return 0
    lv = 0
    if metadata.get("contentIdentity") or metadata.get("contentHash"):
        lv = 1
    if lv >= 1 and metadata.get("author"):
        lv = 2
    if lv >= 2 and metadata.get("publisher"):
        lv = 3
    if lv >= 3:
        # L4：≥2 独立 verifier（distinct DID）且都在 registeredVerifiers + 有 evidenceRef
        entries = [v for v in (verified_by or [])
                   if v.get("verifier") in registered_verifiers and v.get("evidenceRef")]
        distinct = {v["verifier"] for v in entries}
        if len(distinct) >= 2:
            lv = 4
    return lv

def check_evidence(subject, ev):
    if not ev.get("predicateType") or not ev.get("verifier") or not ev.get("result"):
        return False, "缺必填字段"
    if not ev.get("evidenceRef"):
        return False, "缺 evidenceRef"
    pt = ev["predicateType"].rstrip("/").split("/")[-2]  # URL .../predicate/<name>/v1
    subj_type = subject.split(":")[2] if len(subject.split(":")) > 2 else ""
    allowed = PREDICATE_SUBJECT.get(pt, [])
    if allowed and subj_type not in allowed:
        return False, f"predicate {pt} 不允许 subject {subj_type}"
    return True, ""


# ---- §4.1-4.4 CRUD + §5 DID 文档 ----
def check_did_doc(doc):
    if not isinstance(doc, dict): return False, "非对象"
    if not doc.get("id"): return False, "缺 id"
    ctx = doc.get("@context", [])
    if not any("w3.org/ns/did/v1" in str(c) for c in (ctx if isinstance(ctx, list) else [ctx])):
        return False, "缺 @context did/v1"
    vm = doc.get("verificationMethod")
    if not isinstance(vm, list) or not vm: return False, "缺 verificationMethod"
    for m in vm:
        if m.get("type") != "Ed25519VerificationKey2020":
            return False, "密钥类型非 Ed25519"
        if not m.get("controller") or not m.get("publicKeyMultibase"):
            return False, "controller/publicKeyMultibase 缺失"
    return True, ""

def eval_crud(fx):
    kind, inp = fx.get("fixtureType"), fx.get("input", {})
    exp = fx.get("expected", {}).get("verdict")
    reg = fx.get("verifierState", {}).get("registeredResources", [])
    if kind == "create":
        ok = True
        t, rid = inp.get("type", ""), inp.get("id", "")
        if not t or not rid: ok = False
        elif f"did:cha2a:{t}:{rid}" in reg: ok = False      # 重复
        # 类型合法性：对照 §3.2 类型表（12 类）
        valid_types = {"registry","authority","publisher","agent","skill","package",
                       "org","provider","verifier","mcp_server","ai_tool","llm"}
        if t not in valid_types: ok = False
        # id ABNF
        if not check_did_syntax(f"did:cha2a:{t}:{rid}"): ok = False
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"expect={exp}"
    if kind == "resolve":
        did = inp.get("did", "")
        if not check_did_syntax(did):
            return ("PASS" if "REJECT" == exp else "FAIL"), "REJECT", "syntax"
        if inp.get("deactivated"):
            return ("PASS" if "REJECT" == exp else "FAIL"), "REJECT", "deactivated"
        ok = did in reg
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"registered={ok}"
    if kind == "update":
        did = inp.get("did", "")
        ok = did in reg
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"registered={ok}"
    if kind == "did-doc":
        ok, detail = check_did_doc(inp.get("document"))
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"{detail} expect={exp}"
    return None

def eval_fixture(fx):
    kind, inp, exp = fx.get("fixtureType"), fx.get("input", {}), fx.get("expected", {}).get("verdict")
    _crud = eval_crud(fx)
    if _crud:
        return _crud
    if kind == "did-syntax":
        ok, _ = check_did_syntax(inp.get("did"))
    elif kind == "normalization":
        ok, _ = check_did_syntax(inp.get("did"))
        if ok:
            norm = normalize_did(inp["did"])
            ok = norm == inp.get("expectNormalized")
    elif kind == "outbound-sig":
        ok = verify_ed25519(inp.get("publicKeyHex", ""), inp.get("message", ""), inp.get("signatureHex", ""))
    elif kind == "discovery":
        ok, _ = check_discovery(inp.get("document"))
    elif kind == "level":
        lv = compute_level(inp.get("metadata", {}), inp.get("verifiedBy", []),
                           fx.get("verifierState", {}).get("registeredVerifiers", []),
                           bool(inp.get("revoked")))
        exp_level = fx.get("expected", {}).get("level")
        ok = lv == exp_level
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if ok else "FAIL"), verdict, f"level={lv} expect={exp_level}"
    elif kind == "evidence":
        ok, detail = check_evidence(inp.get("subject", ""), inp)
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"{detail} expect={exp}"
    elif kind == "revocation":
        ok = bool(inp.get("revoked"))
        verdict = "ACCEPT" if ok else "REJECT"
        return ("PASS" if verdict == exp else "FAIL"), verdict, f"revoked={inp.get('revoked')}"
    else:
        return "SKIP", "", "未知 fixtureType"
    verdict = "ACCEPT" if ok else "REJECT"
    match = verdict == exp
    return "PASS" if match else "FAIL", verdict, f"expect={exp}"

def check_manifest(fix_dir, manifest_path):
    if not manifest_path or not os.path.exists(manifest_path):
        print("  [warn] MANIFEST.sha256 不存在（未校验字节钉住）")
        return
    bad = 0
    with open(manifest_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sha, path = line.split()
            full = os.path.join(fix_dir, os.path.basename(path))
            if os.path.exists(full):
                got = hashlib.sha256(open(full, "rb").read()).hexdigest()
                if got != sha:
                    print(f"  [FAIL] MANIFEST 不匹配: {path}")
                    bad += 1
    if bad:
        sys.exit(2)

def main():
    fix_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "fixtures")
    manifest = None
    if "--manifest" in sys.argv:
        manifest = sys.argv[sys.argv.index("--manifest") + 1]
    files = sorted(f for f in os.listdir(fix_dir) if f.endswith(".json"))
    if not files:
        print("无 fixtures"); sys.exit(1)
    check_manifest(fix_dir, manifest)
    passed = failed = skipped = 0
    for fn in files:
        fx = json.load(open(os.path.join(fix_dir, fn)))
        status, verdict, detail = eval_fixture(fx)
        if status == "SKIP":
            skipped += 1
            print(f"[SKIP] {fn} ({detail})")
        elif status == "PASS":
            passed += 1
            print(f"[PASS] {fn} -> {verdict}")
        else:
            failed += 1
            print(f"[FAIL] {fn} -> {verdict} ({detail})")
    print(f"\n汇总: {passed} PASS / {failed} FAIL / {skipped} SKIP（共 {len(files)}）")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
