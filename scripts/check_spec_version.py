#!/usr/bin/env python3
"""跨仓版本一致性门禁：规范仓库头部版本 == conformance.json spec.version

规范与 conformance 分属两仓（did-method-cha2a / cha2a-conformance），版本各说各话
会导致"conformance 验证的不是这份规范"。本脚本拉取规范 main 分支（conformance spec.ref
指向 blob/main；历史曾指向 spec-v0.2，已随 P0-2 ref 迁移更新），
解析头部 **Version:** 字段，与 conformance.json 的 spec.version 比对（仅比版本号数字）。

用法：
  python3 scripts/check_spec_version.py                 # 拉取远程 main 比对
  python3 scripts/check_spec_version.py --local PATH    # 用本地规范文件比对（调试）
任一不一致 → exit 1
"""
import json, os, re, subprocess, sys, tempfile, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_REPO = "https://raw.githubusercontent.com/wwumit/did-method-cha2a"
SPEC_BRANCH = "main"
SPEC_FILE = "did-method-cha2a.md"

VERSION_RE = re.compile(r"\*\*Version:\*\*\s*([0-9]+\.[0-9]+)")
CONF_VERSION_RE = re.compile(r"v?([0-9]+\.[0-9]+)")

def fetch_spec_text():
    url = f"{SPEC_REPO}/{SPEC_BRANCH}/{SPEC_FILE}"
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.read().decode("utf-8")
    except Exception as e:
        print(f"✗ 无法拉取规范 {url}: {e}")
        sys.exit(1)

def spec_version(text):
    m = VERSION_RE.search(text)
    if not m:
        print(f"✗ 规范头部未找到 **Version:** 字段")
        sys.exit(1)
    return m.group(1)

def conf_version():
    with open(os.path.join(ROOT, "conformance.json"), encoding="utf-8") as f:
        conf = json.load(f)
    sv = conf.get("spec", {}).get("version", "")
    m = CONF_VERSION_RE.search(sv)
    if not m:
        print(f"✗ conformance.json spec.version 无法解析版本号: {sv!r}")
        sys.exit(1)
    return m.group(1)

def main():
    if "--local" in sys.argv:
        path = sys.argv[sys.argv.index("--local") + 1]
        with open(path, encoding="utf-8") as f:
            text = f.read()
        src = f"local {path}"
    else:
        text = fetch_spec_text()
        src = f"{SPEC_REPO}/{SPEC_BRANCH}/{SPEC_FILE}"

    sv = spec_version(text)
    cv = conf_version()
    print(f"规范（{src}）头部版本: {sv}")
    print(f"conformance.json spec.version: {cv}")
    if sv != cv:
        print(f"\n✗ 跨仓版本不一致：规范 {sv} != conformance {cv}——conformance 验证的不是这份规范")
        sys.exit(1)
    print(f"\n✓ 跨仓版本一致：{sv}")
    return 0

if __name__ == "__main__":
    main()
