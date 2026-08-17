#!/usr/bin/env python3
"""
fuzz.py -- Stage 1a: Find (dynamic)

A deliberately small mutation-based fuzzer, standing in for AFL++/libFuzzer
in the prototype. It feeds random/mutated strings to the target binary's
stdin and watches the exit status. A negative return code from
subprocess (on POSIX) means the child died from a signal -- e.g. -11 is
SIGSEGV -- which is our crash oracle.

Real system: swap this module for AFL++ (afl-fuzz) or libFuzzer/atheris,
keeping the same "give me a crashing input + stderr" contract so the rest
of the pipeline (analyzer -> patcher -> verifier) doesn't need to change.
"""
import os
import random
import string
import subprocess
import sys
import json

SEED_CORPUS = ["hello", "test123", "A" * 8, "packet:ping"]


def mutate(s: str) -> str:
    choice = random.random()
    if choice < 0.4:
        # length explosion -- the classic overflow trigger
        return s + random.choice(string.ascii_letters) * random.randint(50, 500)
    elif choice < 0.7:
        # random bytes
        return "".join(random.choice(string.printable) for _ in range(random.randint(1, 300)))
    else:
        # bit-flip-ish mutation on a seed
        chars = list(s)
        if chars:
            idx = random.randrange(len(chars))
            chars[idx] = random.choice(string.printable)
        return "".join(chars)


def run_once(binary_path: str, payload: str, timeout=2):
    try:
        proc = subprocess.run(
            [binary_path],
            input=(payload + "\n").encode(errors="replace"),
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT", b"", b""


def fuzz(binary_path: str, iterations: int = 20000, out_path: str = "crash.json"):
    corpus = list(SEED_CORPUS)
    for i in range(iterations):
        seed = random.choice(corpus)
        payload = mutate(seed)
        rc, out, err = run_once(binary_path, payload)

        if rc == "TIMEOUT":
            continue
        if isinstance(rc, int) and rc < 0:
            result = {
                "iteration": i,
                "signal": -rc,
                "payload_len": len(payload),
                "payload_repr": repr(payload)[:200],
                "payload_raw": payload,
                "stderr": err.decode(errors="replace")[-500:],
            }
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[fuzz] CRASH found at iteration {i}: signal {-rc} "
                  f"(payload length {len(payload)})", file=sys.stderr)
            print(f"[fuzz] Saved crashing input to {out_path}")
            return result

        # feed interesting (longer) mutations back into corpus to grow coverage
        if len(payload) > 20 and random.random() < 0.05:
            corpus.append(payload)

    print(f"[fuzz] No crash found in {iterations} iterations.")
    return None


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else "../vuln_target/buggy"
    iters = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
    fuzz(binary, iters)
