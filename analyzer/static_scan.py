#!/usr/bin/env python3
"""
static_scan.py -- Stage 1b: Find (static)

Scans C source for known-dangerous, unbounded functions (strcpy, gets,
sprintf, strcat, memcpy-with-unchecked-len, ...) and reports the exact
function + line each hit is inside. This gives Stage 2 (Reduce & Patch)
the "which function, which line" localisation it needs to trim context.

Real system: replace/augment with `cppcheck --enable=warning,portability
--xml` or clang static analyzer / Semgrep rules, keeping the same
{file, function, line, rule, snippet} record shape.
"""
import json
import re
import sys

DANGEROUS_PATTERNS = [
    (r"\bstrcpy\s*\(", "CWE-120: strcpy() has no bounds check"),
    (r"\bstrcat\s*\(", "CWE-120: strcat() has no bounds check"),
    (r"\bsprintf\s*\(", "CWE-134: sprintf() has no bounds check"),
    (r"\bgets\s*\(", "CWE-242: gets() is inherently unsafe"),
]

FUNC_DEF_RE = re.compile(r"^\s*[\w\*\s]+\b(\w+)\s*\([^;{]*\)\s*\{")


def scan_file(path: str):
    with open(path) as f:
        lines = f.readlines()

    findings = []
    current_func = None
    func_start = 0

    for i, line in enumerate(lines, start=1):
        m = FUNC_DEF_RE.match(line)
        if m:
            current_func = m.group(1)
            func_start = i

        for pattern, rule in DANGEROUS_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "file": path,
                    "function": current_func or "<unknown>",
                    "func_start_line": func_start,
                    "line": i,
                    "rule": rule,
                    "snippet": line.strip(),
                })

    return findings


def extract_function_source(path: str, func_name: str, context_lines: int = 2):
    """Stage 2 helper: pull out just the vulnerable function (+ small margin)
    instead of dumping the whole file to the LLM -- this is the
    'Context Reduce' step from the Snyk/ETH Zurich finding."""
    with open(path) as f:
        lines = f.readlines()

    start = None
    depth = 0
    end = None
    for i, line in enumerate(lines):
        if start is None:
            m = FUNC_DEF_RE.match(line)
            if m and m.group(1) == func_name:
                start = i
                depth = line.count("{") - line.count("}")
                continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                end = i
                break

    if start is None:
        return None

    lo = max(0, start - context_lines)
    hi = min(len(lines), (end or start) + 1 + context_lines)
    return "".join(lines[lo:hi]), lo + 1, hi


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "../vuln_target/buggy.c"
    findings = scan_file(path)
    print(json.dumps(findings, indent=2))
