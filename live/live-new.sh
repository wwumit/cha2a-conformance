#!/bin/bash
# did:cha2a live conformance —— 新站（OpenAN + cha2a 扩展，只读）
# 断言按规范条款；新站未实现的规范点如实 FAIL 记录（B 项规范-实现缺口）
# 用法：bash live-new.sh [--host URL]
HOST="${HOST:-http://127.0.0.1:5000}"
BASE="$HOST/rest/v1/registry-center"
PASS=0; FAIL=0
check() { if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "[PASS] $1";
  else FAIL=$((FAIL+1)); echo "[FAIL] $1"; fi }

echo "=== live conformance: new-registry ($HOST, readonly) ==="

# §5.2 discovery：新站是否实现 /.well-known/cha2a
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$HOST/.well-known/cha2a")
check "discovery /.well-known/cha2a（规范要求，新站实现状态）" "$([ "$CODE" = "200" ] && echo 0 || echo 1)"

# §4.2 Read：did_ext 解析
R=$(curl -s -m 8 -w "\n%{http_code}" "$BASE/did/did:cha2a:agent:sig-live")
BODY=$(echo "$R" | sed '$d'); CODE=$(echo "$R" | tail -1)
check "resolve-known HTTP 200" "$([ "$CODE" = "200" ] && echo 0 || echo 1)"
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok_id = d.get('id')=='did:cha2a:agent:sig-live'
print('  id 匹配:', ok_id)
exit(0 if ok_id else 1)" 2>/dev/null
check "resolve DID 文档 id" $?

# §4.2 Read：未知 DID → 404
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$BASE/did/did:cha2a:agent:live_nonexist")
check "resolve-unknown → 404" "$([ "$CODE" = "404" ] && echo 0 || echo 1)"

# §4.6 信任查询
R=$(curl -s -m 8 "$BASE/trust/did:cha2a:agent:sig-live")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = d.get('registered') and 'level' in d and 'revoked' in d
print('  registered:', d.get('registered'), '| level:', d.get('level'))
exit(0 if ok else 1)" 2>/dev/null
check "trust 查询结构" $?

# §4.6 evidence/query
R=$(curl -s -m 8 "$BASE/evidence/query?did=did:cha2a:agent:sig-live")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = 'subject' in d and 'count' in d and 'credentials' in d
print('  evidence 结构:', ok)
exit(0 if ok else 1)" 2>/dev/null
check "evidence-query 结构" $?

# §4.6 撤销列表
R=$(curl -s -m 8 "$BASE/trust/revocations")
echo "$R" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok = 'revocations' in d and isinstance(d.get('revocations'), list)
print('  revocations 列表:', ok)
exit(0 if ok else 1)" 2>/dev/null
check "trust-revocations 结构" $?

# §3.3 号段授权机制：新站实现状态
CODE=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "$BASE/number-ranges")
check "number-ranges 端点（规范要求，新站实现状态）" "$([ "$CODE" != "404" ] && echo 0 || echo 1)"

echo ""
echo "=== live 汇总: $PASS PASS / $FAIL FAIL (label=new-registry, readonly) ==="
exit $([ "$FAIL" = "0" ] && echo 0 || echo 1)
