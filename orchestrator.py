#!/usr/bin/env python3
"""
orchestrator.py -- ties the three stages into one autonomous loop.

    Find              Fix                    Prove
  fuzz + scan  ->  reduce + LLM patch  ->  replay + regress (+ optional ESBMC)
       ^                                          |
       +---------- feedback on failure -----------+   (up to MAX_ATTEMPTS)

Run:
    cd autopatch
    python3 orchestrator.py
"""
import json
import os
import shutil
import sys

sys.path.insert(0, "fuzzer")
sys.path.insert(0, "analyzer")
sys.path.insert(0, "patcher")
sys.path.insert(0, "verifier")
sys.path.insert(0, "proof")

from fuzz import fuzz                      # noqa: E402
from static_scan import scan_file           # noqa: E402
from llm_patch import generate_patch, apply_patch  # noqa: E402
from verify import verify                   # noqa: E402
from esbmc_check import prove_no_overflow, esbmc_available  # noqa: E402

TARGET_DIR = "vuln_target"
SRC = os.path.join(TARGET_DIR, "buggy.c")
BIN = os.path.join(TARGET_DIR, "buggy")
MAX_ATTEMPTS = 3


def stage_build():
    print("== Stage 0: Build baseline ==")
    os.system(f"cd {TARGET_DIR} && make >/dev/null 2>&1")
    assert os.path.exists(BIN), "baseline build failed"
    print(f"  baseline binary ready: {BIN}\n")


def stage_find():
    print("== Stage 1: Find (fuzz + static analysis) ==")
    crash = fuzz(BIN, iterations=20000, out_path="crash.json")
    if not crash:
        print("  No crash found -- nothing to patch. Exiting.")
        sys.exit(0)
    print(f"  Fuzzer crash: signal {crash['signal']}, payload length {crash['payload_len']}")

    findings = scan_file(SRC)
    if not findings:
        print("  Static scan found no known-dangerous pattern; cannot auto-localise. Exiting.")
        sys.exit(0)
    finding = findings[0]
    print(f"  Static scan localised: {finding['rule']} in `{finding['function']}` "
          f"(line {finding['line']})\n")
    return crash, finding


def stage_fix_and_prove(crash, finding):
    print("== Stage 2+3: Fix (reduce+LLM/rule patch) -> Prove (replay+regress+ESBMC) ==")
    prior_failure = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"  -- attempt {attempt}/{MAX_ATTEMPTS} --")
        patched_src, start, end, method = generate_patch(finding, prior_failure)
        print(f"     patch method: {method} (lines {start}-{end})")

        patched_file = os.path.join(TARGET_DIR, "buggy_patched.c")
        patched_bin = os.path.join(TARGET_DIR, "buggy_patched")
        apply_patch(SRC, patched_file, start, end, patched_src)

        result = verify(patched_file, patched_bin, crash["payload_raw"])
        print(f"     verification: {result}")

        if result["passed"]:
            if esbmc_available():
                proof = prove_no_overflow(patched_file, finding["function"])
                print(f"     formal proof (ESBMC): {proof}")
            else:
                print("     formal proof (ESBMC): skipped -- esbmc not installed in this environment")

            print("\n  PATCH ACCEPTED.")
            print(f"  Diff-worthy function:\n{patched_src}")
            return True

        prior_failure = f"stage={result['stage']} detail={result['detail']}"

    print("\n  All attempts exhausted -- patch NOT accepted. Escalate to a human reviewer.")
    return False


if __name__ == "__main__":
    stage_build()
    crash, finding = stage_find()
    stage_fix_and_prove(crash, finding)
