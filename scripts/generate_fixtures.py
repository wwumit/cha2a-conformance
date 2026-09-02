#!/usr/bin/env python3
"""确定性 conformance fixture 生成器（byte-pin：重生成必须字节一致）

生成 conformance/fixtures/*.json：
- §3.1 ABNF 语法向量（valid/invalid）
- §3.3 规范化向量
- §4.5 出站签名向量（X-DID + X-DID-Sig，Ed25519）
- §5.2 discovery 向量
输入：conformance/vectors/*.json（TEST-ONLY 密钥）
输出：conformance/fixtures/ + 更新 MANIFEST.sha256（由调用方生成）
用法：python3 scripts/generate_fixtures.py
"""
import json, os, re, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")
VEC = os.path.join(ROOT, "vectors")
SPEC_REF = "https://github.com/wwumit/did-method-cha2a/blob/main/did-method-cha2a.md"

# ---- 确定性材料 ----
TEST_MSGS = {
    "sig1": "cha2a conformance outbound call 001",
    "sig2": "cha2a conformance outbound call 002",
}

def load_vec(role):
    with open(os.path.join(VEC, f"{role}.json")) as f:
        return json.load(f)

def fixture(name, ftype, section, input_, expected, verifier_state, desc):
    """构造 fixture（对齐 opena2a 格式）"""
    return {
        "$schema": "https://cha2a.org/schemas/fixture-v1.json",
        "name": f"cha2a/{name}",
        "description": desc,
        "fixtureType": ftype,
        "spec": [{"id": "did:cha2a", "ref": SPEC_REF, "section": section}],
        "verifierState": verifier_state,
        "input": input_,
        "expected": expected,
    }

def sign_hex(role, msg):
    vec = load_vec(role)
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vec["privateKeyHex"]))
    return sk.sign(msg.encode()).hex()

def did_syntax_fixtures():
    out = []
    registry_vec = load_vec("registry")
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"]}
    valid_types = ["registry", "authority", "publisher", "agent", "skill",
                   "package", "org", "provider", "verifier", "mcp_server", "ai_tool", "llm"]
    for t in valid_types:
        did = f"did:cha2a:{t}:conformance_valid_{t.replace('-','_')}"
        out.append(fixture(f"did-syntax-valid-{t}", "did-syntax", "§3.1",
                           {"did": did}, {"verdict": "ACCEPT"}, vs,
                           f"合法 {t} DID，ABNF 通过"))
    # 非法：大写方法名 / 空 id / 空格 / 非法字符
    out.append(fixture("did-syntax-invalid-uppercase-method", "did-syntax", "§3.1",
                       {"did": "did:CHA2A:agent:x"}, {"verdict": "REJECT"}, vs, "方法名必须小写"))
    out.append(fixture("did-syntax-invalid-empty-id", "did-syntax", "§3.1",
                       {"did": "did:cha2a:agent:"}, {"verdict": "REJECT"}, vs, "resource-id 非空"))
    out.append(fixture("did-syntax-invalid-space", "did-syntax", "§3.1",
                       {"did": "did:cha2a:agent:a b"}, {"verdict": "REJECT"}, vs, "含空格非法"))
    out.append(fixture("did-syntax-fragment", "did-syntax", "§3.1",
                       {"did": "did:cha2a:agent:x#key-1"}, {"verdict": "ACCEPT"}, vs, "fragment 合法"))
    # normalization：规范未定义完整 normalization 章节（§3.3 为服务挂载；仅 §2 前缀小写表述）
    # 待规范补全 normalization 语义（参考 opena2a §3.3：prefix/type 大小写敏感、resource-id 保留）后加入
    return out

def outbound_sig_fixtures():
    """§4.5 出站签名：X-DID + X-DID-Sig（真实 Ed25519）"""
    out = []
    agent = load_vec("agent-a")
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"]}
    # 有效：agent-a 私钥签名
    m1 = TEST_MSGS["sig1"]
    s1 = sign_hex("agent-a", m1)
    out.append(fixture("outbound-sig-valid", "outbound-sig", "§4.5",
                       {"did": agent["keyId"], "message": m1, "signatureHex": s1,
                        "publicKeyHex": agent["publicKeyHex"]},
                       {"verdict": "ACCEPT"}, vs, "agent-a 真实签名，验签通过"))
    # 篡改：消息改了，签名不变
    out.append(fixture("outbound-sig-tampered-message", "outbound-sig", "§4.5",
                       {"did": agent["keyId"], "message": m1 + " tampered", "signatureHex": s1,
                        "publicKeyHex": agent["publicKeyHex"]},
                       {"verdict": "REJECT"}, vs, "篡改消息，签名不匹配"))
    # 伪造：另一把密钥的签名
    s_forged = sign_hex("agent-b", m1)
    out.append(fixture("outbound-sig-forged-key", "outbound-sig", "§4.5",
                       {"did": agent["keyId"], "message": m1, "signatureHex": s_forged,
                        "publicKeyHex": agent["publicKeyHex"]},
                       {"verdict": "REJECT"}, vs, "伪造密钥签名，验签失败"))
    return out

def discovery_fixtures():
    """§5.2 /.well-known/cha2a discovery 文档结构"""
    out = []
    reg = load_vec("registry")
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"]}
    valid_doc = {
        "registryDid": "did:cha2a:registry:compliancehub.cn",
        "version": "1.0",
        "supportedMethods": ["did:cha2a"],
        "capabilities": ["trust-proof", "trust-lookup", "revocation", "deactivation", "evidence", "phone"],
        "publicKeys": [{"algorithm": "Ed25519", "status": "signing",
                        "publicKeyHex": reg["publicKeyHex"],
                        "keyId": reg["keyId"]}],
    }
    out.append(fixture("discovery-valid", "discovery", "§5.2",
                       {"document": valid_doc}, {"verdict": "ACCEPT"}, vs, "discovery 文档结构完整"))
    missing = {k: v for k, v in valid_doc.items() if k != "publicKeys"}
    out.append(fixture("discovery-missing-publickeys", "discovery", "§5.2",
                       {"document": missing}, {"verdict": "REJECT"}, vs, "缺 publicKeys 非法"))
    return out


def level_fixtures():
    """§4.6 L0-L4 判定（按规范：contentIdentity→L1 +author→L2 +publisher→L3 +≥2独立已注册verifier→L4）
    简化标注：disclosure consistency 场景未模拟（L4 额外条件）；撤销 fail-closed 单列"""
    out = []
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"],
          "registeredVerifiers": ["did:cha2a:verifier:verifier_a",
                                  "did:cha2a:verifier:verifier_b"]}
    def L(name, metadata, verifiedBy, exp_level, desc, revoked=False):
        out.append(fixture(name, "level", "§4.6",
                           {"metadata": metadata, "verifiedBy": verifiedBy, "revoked": revoked},
                           {"verdict": "ACCEPT", "level": exp_level}, vs, desc))
    # L0-L4
    L("level-l0-no-declaration", {}, [], 0, "无声明 → L0")
    L("level-l1-content-identity", {"contentIdentity": "sha256:abc123"}, [], 1,
      "content fingerprint → L1")
    L("level-l2-author", {"contentIdentity": "sha256:abc123",
                          "author": "did:cha2a:authority:example.com"}, [], 2,
      "L1 + author → L2")
    L("level-l3-publisher", {"contentIdentity": "sha256:abc123",
                             "author": "did:cha2a:authority:example.com",
                             "publisher": "did:cha2a:publisher:market"}, [], 3,
      "L2 + publisher attestation → L3")
    # L4：两条独立已注册 verifier
    vb2 = [{"verifier": "did:cha2a:verifier:verifier_a", "method": "audit",
            "result": "passed", "at": "2026-08-30T00:00:00Z",
            "evidenceRef": "https://evidence.example.com/ev1"},
           {"verifier": "did:cha2a:verifier:verifier_b", "method": "audit",
            "result": "passed", "at": "2026-08-30T00:00:00Z",
            "evidenceRef": "https://evidence.example.com/ev2"}]
    L("level-l4-two-verifiers",
      {"contentIdentity": "sha256:abc123", "author": "did:cha2a:authority:example.com",
       "publisher": "did:cha2a:publisher:market"}, vb2, 4,
      "L3 + 2 独立已注册 verifier → L4")
    # 同一 verifier 不构成独立 → 非 L4
    vb_same = [dict(vb2[0]), dict(vb2[0])]
    vb_same[1]["evidenceRef"] = "https://evidence.example.com/ev2"
    L("level-l4-same-verifier",
      {"contentIdentity": "sha256:abc123", "author": "did:cha2a:authority:example.com",
       "publisher": "did:cha2a:publisher:market"}, vb_same, 3,
      "同一 verifier 两次不构成独立 → 非 L4（L3）")
    # 未注册 verifier → 非 L4（硬要求）
    vb_unreg = [dict(vb2[0]), {"verifier": "did:cha2a:verifier:not_registered",
                               "method": "audit", "result": "passed",
                               "at": "2026-08-30T00:00:00Z",
                               "evidenceRef": "https://evidence.example.com/ev3"}]
    L("level-l4-unregistered-verifier",
      {"contentIdentity": "sha256:abc123", "author": "did:cha2a:authority:example.com",
       "publisher": "did:cha2a:publisher:market"}, vb_unreg, 3,
      "verifier 未注册不满足硬要求 → 非 L4（L3）")
    # 撤销 fail-closed
    L("revocation-fail-closed",
      {"contentIdentity": "sha256:abc123", "author": "did:cha2a:authority:example.com",
       "publisher": "did:cha2a:publisher:market"}, vb2, 0,
      "撤销后 fail-closed → L0", revoked=True)
    return out


def evidence_fixtures():
    """§4.6 evidence schema：字段完整 + predicate-subject 白名单 + evidenceRef 要求"""
    out = []
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"]}
    base = {"predicateType": "https://cha2a.org/predicate/identity-anchor/v1",
            "verifier": "did:cha2a:verifier:verifier_a", "result": "passed",
            "checkedAt": "2026-08-30T00:00:00Z",
            "evidenceRef": "https://evidence.example.com/ev"}
    out.append(fixture("evidence-valid", "evidence", "§4.6",
                       {"subject": "did:cha2a:agent:x", **base},
                       {"verdict": "ACCEPT"}, vs, "字段完整 ACCEPT"))
    # predicate-subject 不匹配：number-range-grant → agent 主体（白名单：→org）
    out.append(fixture("evidence-invalid-predicate-subject", "evidence", "§4.6",
                       {"subject": "did:cha2a:agent:x",
                        "predicateType": "https://cha2a.org/predicate/number-range-grant/v1",
                        "verifier": "did:cha2a:verifier:verifier_a", "result": "passed",
                        "checkedAt": "2026-08-30T00:00:00Z",
                        "evidenceRef": "https://evidence.example.com/ev"},
                       {"verdict": "REJECT"}, vs, "predicate 与 subject 类型不匹配 REJECT"))
    # 缺 evidenceRef（必填）
    no_ref = {k: v for k, v in base.items() if k != "evidenceRef"}
    out.append(fixture("evidence-missing-evidenceRef", "evidence", "§4.6",
                       {"subject": "did:cha2a:agent:x", **no_ref},
                       {"verdict": "REJECT"}, vs, "缺 evidenceRef REJECT"))
    return out


def crud_fixtures():
    """§4.1 Create / §4.2 Read / §4.3 Update / §4.4 Deactivate + §5 DID 文档结构"""
    out = []
    registered = ["did:cha2a:agent:known_agent", "did:cha2a:skill:known_skill",
                  "did:cha2a:org:known_org"]
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"],
          "registeredResources": registered}
    # §4.1 Create：代表类型 valid + 非法类型 + 重复
    for t, rid in [("agent", "new_agent"), ("skill", "new_skill"), ("org", "new_org"),
                   ("provider", "new_provider"), ("verifier", "new_verifier")]:
        out.append(fixture(f"create-valid-{t}", "create", "§4.1",
                           {"type": t, "id": rid,
                            "metadata": {"name": f"new {t}", "author": "did:cha2a:authority:example.com"}},
                           {"verdict": "ACCEPT"}, vs, f"{t} 合法注册"))
    out.append(fixture("create-invalid-type", "create", "§4.1",
                       {"type": "not_a_type", "id": "x", "metadata": {}},
                       {"verdict": "REJECT"}, vs, "未注册类型 REJECT"))
    out.append(fixture("create-duplicate", "create", "§4.1",
                       {"type": "agent", "id": "known_agent", "metadata": {}},
                       {"verdict": "REJECT"}, vs, "重复注册（已存在）REJECT"))
    # §4.2 Read：known/unknown/syntax-invalid/deactivated
    out.append(fixture("resolve-known", "resolve", "§4.2",
                       {"did": "did:cha2a:agent:known_agent"},
                       {"verdict": "ACCEPT"}, vs, "已注册解析 ACCEPT"))
    out.append(fixture("resolve-unknown", "resolve", "§4.2",
                       {"did": "did:cha2a:agent:nobody"},
                       {"verdict": "REJECT"}, vs, "未注册 → 404 REJECT"))
    out.append(fixture("resolve-syntax-invalid", "resolve", "§4.2",
                       {"did": "did:cha2a:agent:has space"},
                       {"verdict": "REJECT"}, vs, "违反 §3.1 → 400 REJECT"))
    out.append(fixture("resolve-deactivated", "resolve", "§4.4",
                       {"did": "did:cha2a:agent:known_agent", "deactivated": True},
                       {"verdict": "REJECT"}, vs, "deactivated → 不解析 REJECT"))
    # §4.3 Update
    out.append(fixture("update-known", "update", "§4.3",
                       {"did": "did:cha2a:agent:known_agent", "metadata": {"name": "updated"}},
                       {"verdict": "ACCEPT"}, vs, "更新已注册 ACCEPT"))
    out.append(fixture("update-unknown", "update", "§4.3",
                       {"did": "did:cha2a:agent:nobody", "metadata": {}},
                       {"verdict": "REJECT"}, vs, "更新未注册 REJECT"))
    return out


def did_doc_fixtures():
    """§5 DID Document 结构"""
    out = []
    vs = {"trustedRegistries": ["did:cha2a:registry:compliancehub.cn"]}
    valid_doc = {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": "did:cha2a:skill:known_skill",
        "verificationMethod": [{
            "id": "did:cha2a:skill:known_skill#registry-key",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:cha2a:registry:compliancehub.cn",
            "publicKeyMultibase": "z6Mk1234567890abcdef"}],
        "authentication": ["did:cha2a:skill:known_skill#registry-key"],
        "assertionMethod": ["did:cha2a:skill:known_skill#registry-key"],
        "service": [{"id": "did:cha2a:skill:known_skill#trust-lookup",
                     "type": "TrustLookup",
                     "serviceEndpoint": "https://registry.example.com/api/v1/trust/query"}],
    }
    out.append(fixture("did-doc-valid", "did-doc", "§5",
                       {"document": valid_doc}, {"verdict": "ACCEPT"}, vs, "DID 文档结构完整"))
    missing = {k: v for k, v in valid_doc.items() if k != "verificationMethod"}
    out.append(fixture("did-doc-missing-verificationMethod", "did-doc", "§5",
                       {"document": missing}, {"verdict": "REJECT"}, vs, "缺 verificationMethod REJECT"))
    wrong_key = dict(valid_doc)
    wrong_key["verificationMethod"] = [{"id": "x#key", "type": "RSAVerificationKey2018",
                                        "controller": "did:cha2a:registry:compliancehub.cn"}]
    out.append(fixture("did-doc-wrong-key-type", "did-doc", "§5",
                       {"document": wrong_key}, {"verdict": "REJECT"}, vs, "密钥类型非 Ed25519 REJECT"))
    return out

def main():
    os.makedirs(FIX, exist_ok=True)
    all_fx = (did_syntax_fixtures() + outbound_sig_fixtures() + discovery_fixtures()
              + level_fixtures() + evidence_fixtures()
              + crud_fixtures() + did_doc_fixtures())
    for fx in all_fx:
        path = os.path.join(FIX, fx["name"].split("/")[1] + ".json")
        with open(path, "w") as f:
            json.dump(fx, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"✓ {os.path.basename(path)}")
    print(f"共 {len(all_fx)} 个 fixture（第一批：语法/规范化/出站签名/discovery）")

if __name__ == "__main__":
    main()
