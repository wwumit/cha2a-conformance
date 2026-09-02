#!/usr/bin/env python3
"""规范 → 向量覆盖反向检查（2.3）：规范含 MUST/SHOULD 的条款区块必须可映射到
conformance 向量，或在 notCovered 显式声明理由——不允许"规范有要求但既无向量也无声明"。

规则：
  1. 解析规范标题区块（## N / ### N.M / #### N.M.K），统计每块 MUST/SHOULD 行数
  2. 覆盖集 = fixtures spec.section（去 § 前缀）∪ conformance.json notCovered 的 specSection 编号
  3. 含 MUST/SHOULD 的区块编号 ∉ 覆盖集 → 缺失（红）
  4. 区块语义被向量/声明以"近似编号"覆盖的不算（如 §3.1 不覆盖 §3.1.1）——精确匹配
任一缺失 → exit 1

用法：python3 scripts/check_spec_coverage.py [--local PATH]（默认拉远程 spec-v0.2）
"""
import json, os, re, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_REPO = "https://raw.githubusercontent.com/wwumit/did-method-cha2a"
SPEC_BRANCH = "spec-v0.2"
SPEC_FILE = "did-method-cha2a.md"

HEADING_RE = re.compile(r"^(#{2,4})\s+([0-9]+(?:\.[0-9]+)*)\.?\s+\S")
MUST_SHOULD_RE = re.compile(r"\b(MUST|SHOULD)\b")

def fetch_spec():
    url = f"{SPEC_REPO}/{SPEC_BRANCH}/{SPEC_FILE}"
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        print(f"✗ 无法拉取规范 {url}: {e}")
        sys.exit(1)

def parse_spec_blocks(text):
    """返回 [(编号, 标题, MUST/SHOULD 行数)]，按规范层次"""
    blocks = []
    cur = None
    for line in text.split("\n"):
        m = HEADING_RE.match(line)
        if m:
            if cur:
                blocks.append(cur)
            cur = {"num": m.group(2), "must": 0}
        if cur and MUST_SHOULD_RE.search(line):
            cur["must"] += 1
    if cur:
        blocks.append(cur)
    return blocks

def coverage_sets():
    """覆盖集：fixtures spec.section ∪ notCovered 编号"""
    covered = set()
    import glob
    for f in glob.glob(os.path.join(ROOT, "fixtures", "*.json")):
        d = json.load(open(f, encoding="utf-8"))
        for s in d.get("spec", []):
            sec = (s.get("section") or "").lstrip("§").strip()
            if sec:
                covered.add(sec)
    with open(os.path.join(ROOT, "conformance.json"), encoding="utf-8") as f:
        conf = json.load(f)
    for nc in conf.get("notCovered", []):
        m = re.match(r"§?([0-9][0-9.]*)", nc.get("specSection", ""))
        if m:
            covered.add(m.group(1))
    return covered

def main():
    if "--local" in sys.argv:
        path = sys.argv[sys.argv.index("--local") + 1]
        text = open(path, encoding="utf-8").read()
    else:
        text = fetch_spec()
    blocks = parse_spec_blocks(text)
    covered = coverage_sets()

    missing = []
    for b in blocks:
        if b["must"] > 0 and b["num"] not in covered:
            missing.append(b)

    print(f"规范 MUST/SHOULD 区块: {len([b for b in blocks if b['must']>0])} 个")
    print(f"覆盖集: {len(covered)} 个（fixtures + notCovered）")
    if not missing:
        print("\n✓ 反向覆盖检查通过：全部 MUST/SHOULD 区块均有向量或 notCovered 声明")
        return 0
    print("\n✗ 以下含 MUST/SHOULD 的区块既无向量覆盖也无 notCovered 声明：")
    for b in missing:
        print(f"  §{b['num']}  ({b['must']} 条 MUST/SHOULD)")
    sys.exit(1)

if __name__ == "__main__":
    main()
