#!/usr/bin/env python3
"""
esbmc_check.py -- Stage 3b: Prove (formal, optional)

Wraps ESBMC (Efficient SMT-Based Bounded Model Checker) to formally check
memory-safety properties (buffer overflow, null deref, overflow) on a
single function, given a bound on input size -- this is the "mathematical
proof" tier described in the Manchester/UAE paper: instead of an LLM
guessing whether a bug exists, ESBMC either proves the property holds
(within the bound) or produces a concrete counterexample.

This is OPTIONAL in the pipeline: it only runs for bug classes ESBMC
handles well (buffer overflow, integer overflow, null pointer, division by
zero) and is skipped gracefully if the `esbmc` binary isn't installed --
the empirical verifier (verifier/verify.py) is the pipeline's mandatory
gate; this is the upgrade path when a stronger guarantee is wanted.

Install (not run automatically in this prototype):
  wget the release tarball from https://github.com/esbmc/esbmc/releases
  and put `esbmc` on PATH.
"""
import shutil
import subprocess
import sys


def esbmc_available() -> bool:
    return shutil.which("esbmc") is not None


def prove_no_overflow(src_path: str, function: str, unwind: int = 8, timeout: int = 60) -> dict:
    if not esbmc_available():
        return {"ran": False, "reason": "esbmc not installed -- skipping formal proof tier"}

    proc = subprocess.run(
        ["esbmc", src_path,
         "--function", function,
         "--unwind", str(unwind),
         "--overflow-check",
         "--bounds-check",
         "--no-unwinding-assertions"],
        capture_output=True, text=True, timeout=timeout,
    )
    out = proc.stdout + proc.stderr
    if "VERIFICATION SUCCESSFUL" in out:
        return {"ran": True, "proved": True, "detail": "ESBMC proved no violation within the unwind bound"}
    if "VERIFICATION FAILED" in out:
        return {"ran": True, "proved": False, "detail": out[-1000:]}
    return {"ran": True, "proved": None, "detail": out[-1000:]}


if __name__ == "__main__":
    src, fn = sys.argv[1], sys.argv[2]
    print(prove_no_overflow(src, fn))
