#!/usr/bin/env python3
"""Parity gate for the Registry/Passport/Agent Card profile suite."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CASES = json.loads((ROOT / "vectors.json").read_text(encoding="utf-8"))


def run(command):
    completed = subprocess.run(
        command,
        cwd=ROOT.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    results = {}
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "name" in value:
            results[value["name"]] = {
                "verdict": value["verdict"],
                "result": value["result"],
                "pass": value["pass"],
            }
    return results, completed.returncode


def main():
    python_results, python_rc = run(
        [
            sys.executable,
            "registry-agent-card/verify.py",
            "registry-agent-card",
            "--manifest",
            "registry-agent-card/MANIFEST.sha256",
        ]
    )
    node_results, node_rc = run(
        [
            "node",
            "registry-agent-card/verify.mjs",
            "registry-agent-card",
            "--manifest",
            "registry-agent-card/MANIFEST.sha256",
        ]
    )
    if python_rc or node_rc:
        print("FAIL verifier exit code")
        return 1
    expected_names = {item["name"] for item in CASES}
    if set(python_results) != expected_names or set(node_results) != expected_names:
        print("FAIL result set mismatch")
        return 1
    for name in sorted(expected_names):
        if python_results[name] != node_results[name]:
            print("FAIL diverge " + name)
            return 1
        if not python_results[name]["pass"]:
            print("FAIL expected " + name)
            return 1
    print("PASS registry-agent-card parity " + str(len(CASES)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
