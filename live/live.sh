#!/bin/bash
# did:cha2a live-endpoint conformance（只读探测，考官/考生分离）
#
# 对象：运行中真实实现（旧站 compliancehub.cn 生产 / 新站火山）
# 模式：readonly（默认，只读探测——生产安全）；full（新站可含测试资源写操作）
# 断言依据：规范 §4.2 Read / §4.6 信任 / §5.2 discovery / §3.3 号段授权机制
# 用法：bash live.sh [--host URL] [--mode readonly|full] [--label 名称]
# 纪律：只读为主；不污染生产；写操作仅 full 且只对新站测试资源

HOST="${HOST:-https://compliancehub.cn}"
MODE="${MODE:-readonly}"
LABEL="${LABEL:-legacy-production}"
PASS=0; FAIL=0

check() {  # check <名称> <条件(0=通过)>
  if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "[PASS] $1";
  else FAIL=$((FAIL+1)); echo "[FAIL] $1"; fi
}

echo "=== live conformance: $LABEL ($HOST, mode=$MODE) ==="

# ---- §5.2 discovery：/.well-known/cha2a 结构 ----
R=$(curl -s -m 8 -w "\n%{http_code}" "$HOST/.well-known/cha2a")
BODY=$(echo "$R" | sed '$d'); CODE=$(echo "$R" | tail -1)
check "discovery HTTP 200" "$([ "$CODE" = "200" ] && echo 0 || echo 1)"
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok_pk = bool(d.get('publicKeys')) and any(k.get('algorithm')=='Ed25519' and k.get('status')=='signing' for k in d.get('publicKeys',[]))
ok_sm = 'did:cha2a' in (d.get('supportedMethods') or [])
print('  publicKeys(Ed25519 signing):', ok_pk, '| supportedMethods 含 did:cha2a:', ok_sm)
exit(0 if (ok_pk and ok_sm) else 1)" 2>/dev/null
check "discovery publicKeys+supportedMethods" $?

# ---- §4.2 Read：解析已知 DID → DID 文档 ----
R=$(curl -s -m 8 -w "\n%{http_code}" "$HOST/api/v1/did/did:cha2a:agent:volcano-demo")
BODY=$(echo "$R" | sed '$d'); CODE=$(echo "$R" | tail -1)
check "resolve-known HTTP 200" "$([ "$CODE" = "200" ] && echo 0 || echo 1)"
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok_id = d.get('id')=='did:cha2a:agent:volcano-demo'
vm = d.get('verificationMethod') or []
ok_vm = any(m.get('type')=='Ed25519VerificationKey2020' and m.get('publicKeyMultibase','').startswith('z') for m in vm)
print('  id 匹配:', ok_id, '| verificationMethod Ed25519+multibase:', ok_vm)
exit(0 if (ok_id and ok_vm) else 1)" 2>/dev/null
check "resolve DID 文档结构" $?

# ---- §4.2 Read：未知 DID → 404 ----
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$HOST/api/v1/did/did:cha2a:agent:live_conformance_nonexist")
check "resolve-unknown → 404" "$([ "$CODE" = "404" ] && echo 0 || echo 1)"

# ---- §4.2 Read：语法违规 → 400 ----
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$HOST/api/v1/did/did:cha2a:agent:bad%20space")
check "resolve-syntax-invalid → 400" "$([ "$CODE" = "400" ] && echo 0 || echo 1)"

# ---- §4.6 信任查询：registered + level 字段 ----
R=$(curl -s -m 8 "$HOST/api/v1/trust/query?did=did:cha2a:agent:volcano-demo")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = d.get('registered') and 'level' in d and 'revoked' in d and 'active' in d
print('  registered:', d.get('registered'), '| level:', d.get('level'), '| revoked:', d.get('revoked'))
exit(0 if ok else 1)" 2>/dev/null
check "trust-query 结构（registered/level/revoked/active）" $?

# ---- §4.6 evidence/query 结构 ----
R=$(curl -s -m 8 "$HOST/api/v1/evidence/query?did=did:cha2a:agent:volcano-demo")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = 'subject' in d and 'count' in d and 'credentials' in d
print('  subject/count/credentials 字段齐全:', ok)
exit(0 if ok else 1)" 2>/dev/null
check "evidence-query 结构" $?

# ---- §4.6 撤销列表 ----
R=$(curl -s -m 8 "$HOST/api/v1/trust/revocations")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = 'revocations' in d and isinstance(d.get('revocations'), list)
print('  revocations 列表:', ok)
exit(0 if ok else 1)" 2>/dev/null
check "trust-revocations 结构" $?

# ---- §3.3 号段授权机制（grant 记录可公开核验，非真实运营声称） ----
R=$(curl -s -m 8 "$HOST/api/v1/number-ranges?grantee=did%3Acha2a%3Aorg%3Acompliancehub.cn")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ranges = d.get('ranges') or []
ok = d.get('ok') and any(r.get('range','').startswith('+86') for r in ranges)
print('  grant 记录（+86 号段）:', ok, '| 注：机制可核验，非真实运营号段')
exit(0 if ok else 1)" 2>/dev/null
check "number-ranges 号段授权机制可核验" $?

echo ""
echo "=== live 汇总: $PASS PASS / $FAIL FAIL (label=$LABEL, mode=$MODE) ==="
exit $([ "$FAIL" = "0" ] && echo 0 || echo 1)
