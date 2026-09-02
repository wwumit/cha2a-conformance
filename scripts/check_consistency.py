#!/usr/bin/env python3
"""conformance 防漂移检查（CI 用；"声称=实有"机器化）

检查：
  1. conformance.json 合法 JSON 且必填键齐全
  2. fixtureCount == fixtures/*.json 实有数
  3. README.md 声称的向量计数 == 实有数（覆盖矩阵合计 + "N fixtures" 行）
  4. MANIFEST.sha256 条目数 == fixtures + vectors 实有数（内容哈希由 verify --manifest 校验）
任一不符 → exit 1
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")
FAILS = []

def fail(msg):
    FAILS.append(msg)
    print("FAIL:", msg)

# 1. conformance.json
try:
    with open(os.path.join(ROOT, "conformance.json"), encoding="utf-8") as f:
        conf = json.load(f)
    for k in ("suite", "spec", "fixtureManifest", "verifiers", "fixtureCount", "negativeVectorRatio"):
        if k not in conf:
            fail(f"conformance.json 缺必填键 {k}")
except Exception as e:
    fail(f"conformance.json 解析失败: {e}")
    conf = {}

# 2. fixtureCount == 实有
n = len([x for x in os.listdir(FIX) if x.endswith(".json")])
if conf.get("fixtureCount") != n:
    fail(f"conformance.json fixtureCount={conf.get('fixtureCount')} != fixtures 实有 {n}")

# 3. README 声称计数
readme_path = os.path.join(ROOT, "README.md")
readme = open(readme_path, encoding="utf-8").read()
m = re.search(r"\*\*(\d+)\s+fixtures", readme)
if m and int(m.group(1)) != n:
    fail(f"README 声称 {m.group(1)} fixtures != 实有 {n}")
rows = re.findall(r"\|\s*§[^|\n]+\|\s*(\d+)\s*\|", readme)
if rows and sum(int(r) for r in rows) != n:
    fail(f"README 覆盖矩阵合计 {sum(int(r) for r in rows)} != 实有 {n}（逐行 {rows}）")

# 4. MANIFEST 条目数
vec_n = len([x for x in os.listdir(os.path.join(ROOT, "vectors")) if x.endswith(".json")])
try:
    with open(os.path.join(ROOT, "MANIFEST.sha256"), encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    if len(lines) != n + vec_n:
        fail(f"MANIFEST 条目 {len(lines)} != fixtures {n} + vectors {vec_n}")
except Exception as e:
    fail(f"MANIFEST.sha256 读取失败: {e}")

if FAILS:
    print(f"\n✗ {len(FAILS)} 项不一致（声称≠实有）")
    sys.exit(1)
print(f"✓ OK：{n} fixtures，conformance.json / README 计数 / MANIFEST 条目 全部一致")
