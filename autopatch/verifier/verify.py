#!/usr/bin/env python3
"""
verify.py -- Stage 3: Verify & Prove

Nothing is accepted on the model's word. A patch only passes if ALL of:
  1. It compiles cleanly.
  2. Replaying the exact crashing input from the fuzzer no longer crashes.
  3. A small regression suite of KNOWN-GOOD inputs still produces the
     expected (unchanged) output -- i.e. the fix didn't break behavior.

If ESBMC is installed, a 4th, optional step formally proves the specific
memory-safety property (see proof/esbmc_check.py) rather than just testing
it -- this is the "mathematical proof" tier from the Manchester/UAE paper,
used for bug classes where a bounded model checker can give a real proof
instead of empirical evidence.
"""
import subprocess
import sys


REGRESSION_SUITE = [
    ("hello world", "Parsed packet: hello world\n"),
    ("test123", "Parsed packet: test123\n"),
    ("", "Parsed packet: \n"),
    ("A" * 40, f"Parsed packet: {'A' * 40}\n"),  # still under 64 bytes, must still work
]


def compile_patched(src_path: str, bin_path: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["gcc", "-g", "-O0", "-fno-stack-protector", "-D_FORTIFY_SOURCE=0", "-Wall",
         "-o", bin_path, src_path],
        capture_output=True, text=True,
    )
    return proc.returncode == 0, proc.stderr


def replay_crash(bin_path: str, crashing_payload: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run([bin_path], input=(crashing_payload + "\n").encode(),
                               capture_output=True, timeout=3)
    except subprocess.TimeoutExpired:
        return False, "timed out replaying crash input"
    if proc.returncode < 0:
        return False, f"STILL CRASHES with signal {-proc.returncode}"
    return True, "no longer crashes"


def run_regressions(bin_path: str) -> tuple[bool, str]:
    for payload, expected in REGRESSION_SUITE:
        proc = subprocess.run([bin_path], input=(payload + "\n").encode(),
                               capture_output=True, timeout=3)
        got = proc.stdout.decode(errors="replace")
        if got != expected:
            return False, f"regression failed for input {payload!r}: expected {expected!r}, got {got!r}"
    return True, f"all {len(REGRESSION_SUITE)} regression cases passed"


def verify(src_path: str, bin_path: str, crashing_payload: str) -> dict:
    ok, err = compile_patched(src_path, bin_path)
    if not ok:
        return {"passed": False, "stage": "compile", "detail": err}

    ok, detail = replay_crash(bin_path, crashing_payload)
    if not ok:
        return {"passed": False, "stage": "crash_replay", "detail": detail}

    ok, detail = run_regressions(bin_path)
    if not ok:
        return {"passed": False, "stage": "regression", "detail": detail}

    return {"passed": True, "stage": "all", "detail": "compiled, crash resolved, regressions green"}


if __name__ == "__main__":
    src, binp, payload = sys.argv[1], sys.argv[2], sys.argv[3]
    print(verify(src, binp, payload))
