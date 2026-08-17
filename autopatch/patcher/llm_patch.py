#!/usr/bin/env python3
"""
llm_patch.py -- Stage 2: Reduce & Patch

Given a static-analysis finding, this module:
  1. Reduces context: pulls out ONLY the vulnerable function (+2 lines of
     margin), instead of dumping the whole file at the model -- the
     "Context Reduce" idea from the Snyk/ETH Zurich paper.
  2. Asks an LLM (Claude, via the Messages API) for the smallest patch that
     closes the flaw without changing behavior for valid input.
  3. Falls back to a small library of rule-based CWE patches if no
     ANTHROPIC_API_KEY is set, so the end-to-end loop still runs offline
     for a demo / CI environment.
  4. Supports a feedback loop: if verification fails, the failure reason is
     appended to the next prompt so the model can retry.
"""
import os
import re
import sys
import json
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analyzer"))
from static_scan import extract_function_source  # noqa: E402

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = os.environ.get("PATCH_MODEL", "claude-sonnet-5")

SYSTEM_PROMPT = """You are a security patch generator. You will be given:
- A CWE finding (rule + line)
- The exact vulnerable C function (already trimmed to the relevant code)

Return ONLY the full corrected function body (same signature), with the
minimal change needed to eliminate the flaw. Do not change unrelated
behavior. Do not add comments explaining the fix. Do not wrap in markdown
fences. Return raw C code only."""

# --- Rule-based fallback patches, keyed by CWE rule substring -------------
RULE_PATCHES = {
    "strcpy": lambda func_src, buf_name="buffer", buf_size="sizeof({buf})": (
        re.sub(
            r"strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*;",
            lambda m: f"strncpy({m.group(1)}, {m.group(2)}, sizeof({m.group(1)}) - 1); "
                      f"{m.group(1)}[sizeof({m.group(1)}) - 1] = '\\0';",
            func_src,
        )
    ),
}


def call_claude(system, user, api_key):
    body = json.dumps({
        "model": MODEL,
        "max_tokens": 1024,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode()
    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(text_blocks).strip()


def generate_patch(finding: dict, prior_failure: str | None = None):
    """Returns (patched_function_source, start_line, end_line, method)."""
    func_src, start, end = extract_function_source(finding["file"], finding["function"])

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        user_msg = (
            f"Finding: {finding['rule']} at line {finding['line']}.\n\n"
            f"Vulnerable function:\n```c\n{func_src}\n```\n"
        )
        if prior_failure:
            user_msg += f"\nA previous patch attempt failed verification:\n{prior_failure}\nPlease fix and try again."
        try:
            patched = call_claude(SYSTEM_PROMPT, user_msg, api_key)
            patched = re.sub(r"^```[a-z]*\n?|```$", "", patched.strip(), flags=re.M)
            return patched, start, end, "llm"
        except Exception as e:
            print(f"[patch] LLM call failed ({e}), falling back to rule-based patch.", file=sys.stderr)

    # --- fallback path ---
    for key, fn in RULE_PATCHES.items():
        if key in finding["rule"].lower():
            return fn(func_src), start, end, "rule-based-fallback"

    raise RuntimeError(f"No LLM key and no rule-based patch available for: {finding['rule']}")


def apply_patch(file_path: str, out_path: str, start: int, end: int, new_func_src: str):
    with open(file_path) as f:
        lines = f.readlines()
    new_lines = lines[: start - 1] + [new_func_src if new_func_src.endswith("\n") else new_func_src + "\n"] + lines[end:]
    with open(out_path, "w") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    finding = json.loads(sys.argv[1])
    src, start, end, method = generate_patch(finding)
    print(f"# method={method} lines={start}-{end}\n{src}")
