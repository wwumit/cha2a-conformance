#!/usr/bin/env python3
"""Cross-implementation parity gate（对齐 opena2a atp-conformance）

跑 Python + Node 两个参考验证器，断言对每个 fixture：
  1. 两实现 verdict（ACCEPT/REJECT）一致
  2. 无验证器跳过对方看到的 fixture
  3. 两验证器自身 PASS/FAIL 与 pinned expected 一致（各自验证器已自检）
任一分歧 → exit 1

用法：python3 scripts/parity.py [--manifest MANIFEST.sha256]
"""
import json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures")

VERIFIERS = {
    "python": ["python3", os.path.join(ROOT, "verifiers", "python", "verify.py")],
    "node": ["node", os.path.join(ROOT, "verifiers", "node", "verify.mjs")],
}
LINE_RE = re.compile(r"^\[(PASS|FAIL|SKIP)\] (.+?) -> (ACCEPT|REJECT)")

def run_verifier(name):
    manifest = os.path.join(ROOT, "MANIFEST.sha256")
    r = subprocess.run(VERIFIERS[name] + [FIX, "--manifest", manifest],
                       capture_output=True, text=True)
    verdicts = {}
    for line in r.stdout.splitlines():
        m = LINE_RE.match(line)
        if m:
            verdicts[m.group(2)] = m.group(3)
    return verdicts, r.returncode

def main():
    results = {}
    rcs = {}
    for name in VERIFIERS:
        verdicts, rc = run_verifier(name)
        results[name] = verdicts
        rcs[name] = rc
        print(f"{name}: {len(verdicts)} fixtures, exit={rc}")

    names = list(VERIFIERS.keys())

    # 断言①：验证器自身必须成功（rc=0）——崩溃/缺依赖/路径错 → 门禁失败
    for name, rc in rcs.items():
        if rc != 0:
            print(f"\n✗ 门禁失败：{name} 验证器退出码 {rc} != 0（崩溃/缺依赖/路径错）")
            sys.exit(1)

    a, b = results[names[0]], results[names[1]]

    # 断言②：verdicts 不能为空——防止"什么都没验"被报告成"全部通过"（假绿潜伏缺陷）
    for name, v in results.items():
        if not v:
            print(f"\n✗ 门禁失败：{name} 验证器 0 个 verdict——什么都没验，不算通过")
            sys.exit(1)

    # 断言③：两实现判卷集合相等 且 == fixtures 实有数（无验证器跳过对方看到的 fixture）
    n_fix = len([f for f in os.listdir(FIX) if f.endswith(".json")])
    if set(a) != set(b):
        print(f"\n✗ 门禁失败：两实现判卷集合不一致（仅 {names[0]}={len(set(a)-set(b))}，"
              f"仅 {names[1]}={len(set(b)-set(a))}）")
        sys.exit(1)
    if len(a) != n_fix:
        print(f"\n✗ 门禁失败：判卷数 {len(a)} != fixtures 实有 {n_fix}")
        sys.exit(1)

    diverged = 0
    for fx in sorted(a):
        va, vb = a[fx], b[fx]
        if va != vb:
            diverged += 1
            print(f"[DIVERGE] {fx}: {names[0]}={va} vs {names[1]}={vb}")
    if diverged:
        print(f"\n✗ parity 失败：{diverged} 个 fixture 两实现判卷不一致")
        sys.exit(1)
    print(f"\n✓ parity 通过：{names[0]} 与 {names[1]} 对 {len(a)} 个 fixture"
          f"（实有 {n_fix}）判卷全部一致")

if __name__ == "__main__":
    main()
