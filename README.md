# AutoPatch — Autonomous Find → Fix → Prove Pipeline

A working prototype of the pipeline described in your project: it fuzzes a
target program, localises the bug with static analysis, asks an LLM for a
minimal patch using a *reduced* (trimmed) context, then refuses to accept
the patch until it survives crash-replay, regression tests, and (optionally)
a formal bounded-model-checker proof.

## Quick start

```bash
cd autopatch
python3 orchestrator.py
```

Runs against the intentionally-buggy `vuln_target/buggy.c` (a CWE-120
`strcpy` stack overflow). Expected output: fuzzer finds a crash in
milliseconds, static scan localises it to `parse_input`, a patch is
generated and verified, and the accepted patched function is printed.

To use the **real LLM** instead of the rule-based fallback:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 orchestrator.py
```
Without a key set, the pipeline still runs completely — it falls back to a
small rule-based patch library so the demo works offline / in CI.

## Architecture 

```
 ┌─────────────┐     ┌────────────────┐     ┌──────────────────┐
 │   FIND       │ --> │  REDUCE+PATCH  │ --> │  VERIFY & PROVE   │
 │ fuzz.py      │     │  llm_patch.py  │     │  verify.py         │
 │ static_scan  │     │                │     │  esbmc_check.py    │
 └─────────────┘     └────────────────┘     └──────────────────┘
        ^                                              |
        └───────────── feedback on failure ────────────┘
```

| Stage | File | Real-world tool it stands in for |
|---|---|---|
| Fuzz | `fuzzer/fuzz.py` | AFL++ / libFuzzer / atheris |
| Static scan | `analyzer/static_scan.py` | cppcheck / clang static analyzer / Semgrep |
| Context reduce + patch | `patcher/llm_patch.py` | Claude API (Messages endpoint), trimmed-context prompting |
| Empirical verify | `verifier/verify.py` | crash replay + regression/unit test suite |
| Formal proof (optional) | `proof/esbmc_check.py` | ESBMC bounded model checker |
| Orchestration | `orchestrator.py` | retry loop with failure feedback |

## Recommended tech stack for the full (competition-scale) system

**Target/analysis layer**
- C/C++ targets: AFL++ (coverage-guided fuzzing), cppcheck + clang-tidy (static analysis), ESBMC (bounded model checking, formal proofs)
- Python/JVM targets (if in scope): Atheris / Jazzer as fuzzer equivalents, Bandit/Semgrep for static rules

**Patch generation**
- Claude API (`claude-sonnet-5` or similar) via the Messages endpoint
- Prompt engineering: system prompt constrains output to raw code, minimal diff; context-reduction step (function + N lines) before every call — this is the one change the Snyk/ETH Zurich paper found mattered most
- Structured retry: verifier failure reason fed back into the next prompt (already implemented in `llm_patch.py`)

**Verification/proof**
- Recompilation + regression harness (as built here)
- Crash replay against the exact fuzzer-discovered input (the deterministic "did we actually fix it" check)
- ESBMC for memory-safety/overflow properties where a bound is tractable
- (Stretch) differential testing: run same inputs against original+patched binaries under sanitizers (ASan/UBSan) for extra confidence

**Orchestration & dashboard**
- Backend: Python (FastAPI) service wrapping the four stages as a job queue (Celery/RQ + Redis) so fuzzing/patching can run asynchronously
- Frontend/dashboard: React + a simple REST API, showing: bugs found, patches attempted, pass/fail per stage, time-to-fix
- Storage: SQLite/Postgres for run history — this is what makes "we detect ≥90% of known bugs" a measurable, demoable number rather than an anecdote
- CI hook: GitHub Actions workflow that runs the pipeline on PRs against a small corpus of intentionally-vulnerable sample programs (Juliet Test Suite / OWASP Benchmark are good sources for these)

**Evaluation corpus (for your demo + metrics slide)**
- NIST Juliet Test Suite (labelled CWE examples, exactly the "known bugs" you can score detection-rate against)
- A handful of real historical CVEs in small open-source C utilities, for a "before/after" narrative slide

## Extending this prototype

1. **More bug classes**: add patterns to `DANGEROUS_PATTERNS` in
   `static_scan.py` and matching entries in `RULE_PATCHES` in
   `llm_patch.py` (or just rely on the LLM path once you have an API key).
2. **Real fuzzer**: swap `fuzzer/fuzz.py`'s `fuzz()` for a wrapper that
   shells out to `afl-fuzz`, parses its crash corpus directory, and returns
   the same `{signal, payload_raw, ...}` shape.
3. **ESBMC**: install from https://github.com/esbmc/esbmc/releases and put
   `esbmc` on PATH — `proof/esbmc_check.py` will pick it up automatically
   (it currently no-ops gracefully when absent, which is why the demo run
   above shows `skipped`).
4. **Multiple targets**: parametrise `TARGET_DIR`/`SRC` in
   `orchestrator.py` and loop over a directory of vulnerable programs to
   get an aggregate detection-rate metric for your results slide.
