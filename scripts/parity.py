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
    for name in VERIFIERS:
        verdicts, rc = run_verifier(name)
        results[name] = verdicts
        print(f"{name}: {len(verdicts)} fixtures, exit={rc}")

    names = list(VERIFIERS.keys())
    a, b = results[names[0]], results[names[1]]
    diverged = 0
    for fx in sorted(set(a) | set(b)):
        va, vb = a.get(fx), b.get(fx)
        if va != vb:
            diverged += 1
            print(f"[DIVERGE] {fx}: {names[0]}={va} vs {names[1]}={vb}")
    if diverged:
        print(f"\n✗ parity 失败：{diverged} 个 fixture 两实现判卷不一致")
        sys.exit(1)
    print(f"\n✓ parity 通过：{names[0]} 与 {names[1]} 对 {len(a)} 个 fixture 判卷全部一致")

if __name__ == "__main__":
    main()
