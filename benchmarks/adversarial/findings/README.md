# cycle_71/adversary/04 — Findings triage (fnv1a-pure)

**Target commit:** `0715056` (qa: cycle_71 QA_REPORT — VERDICT: SHIP) on `wt/cycle_71-build`
**Source audit:** commit `4bc46d2` on `wt/cycle_71-adversary-01` (`benchmarks/adversarial/VULN_AUDIT.md`)
**Fuzz run:** commit `61da90d` on `wt/cycle_71-adversary-03` (`benchmarks/adversarial/runs/corpus_run_summary.json`)
**Date:** 2026-09-13
**Triager:** @default (repo-factory adversary chain, slot 04)

---

## 1. Inputs to triage

This card consumes the artefacts from the upstream slots:

| Slot | Commit | Artefact | Verdict |
|------|--------|----------|---------|
| 01 audit | `4bc46d2` | `VULN_AUDIT.md` (12 surfaces, 5 findings: F-01..F-05) | PROCEED_TO_FUZZING |
| 02 harnesses | `6c2e815` | 4 stdlib fuzzing harnesses in `benchmarks/adversarial/harnesses/` | All built, runnable |
| 03 corpus + run | `61da90d` | 344-input seed corpus + 1,350,036 total iters across 4 harnesses | 0 crashes, 0 hangs, 0 timeouts |

The fuzz run is **clean** — no reproducible crash, hang, or OOM. All findings
below originate from the slot-01 audit (manual). Each finding has been
re-derived deterministically with a 1-line repro; the `triage.py` script
captures the live outcome into `findings.jsonl`.

## 2. Triage methodology

1. **Re-derive each audit finding** from `VULN_AUDIT.md §F-01..§F-05` by running
   the documented repro and capturing the actual return value / exception type.
2. **Pin canonical hashes** at the top of `triage.py` so that any future drift
   in `fnv1a_pure` fails the script BEFORE `findings.jsonl` is written. This
   prevents the report from claiming "verdict OK" against a regressed package.
3. **Rank** by severity: Critical > High > Medium > Low > Info. Critical/High
   are blocking; Medium/Low are remediation candidates; Info is accepted or
   doc-only.
4. **Minimise repros** to a single Python expression where possible.
5. **Decide** per finding: OPEN (needs remediation), ACCEPTED (documented
   behaviour), or ALREADY_RESOLVED.

## 3. Findings ranked by severity

| # | Severity | Finding | Status | CWE | Source |
|---|----------|---------|--------|-----|--------|
| F-01 | **Medium** | Silent acceptance of non-`bytes` iterables (list/tuple/bytearray/memoryview) | OPEN | CWE-20 | audit §S7 + F-01 |
| F-02 | **Low** | Cryptic TypeError messages leak CPython internals | OPEN | CWE-209 | audit §S7 + F-02 |
| F-03 | Info | FNV-1 ≡ FNV-1a on zero-only inputs (documented mathematical property) | ACCEPTED | — | audit §S9 + F-03 |
| F-04 | Info | README test-vector table drift (pre-existing QA finding) | ALREADY_RESOLVED | — | audit §F-04 (from QA t_8447f319) |
| F-05 | Info | `bytearray`/`memoryview` support decision undocumented | OPEN (rolled into F-01) | — | audit §F-05 |

Severity counts: **0 Critical / 0 High / 1 Medium / 1 Low / 3 Info / 5 total**.

Per-finding detail (location, repro, expected vs actual, recommendation) is in
`findings.jsonl` (one JSON object per line, schema-version=1).

## 4. Reproduction instructions

```bash
# 1. Pin canonical hashes + re-derive every repro + write findings.jsonl:
cd /root/projects/fnv1a-pure
python3 benchmarks/adversarial/findings/triage.py

# 2. Verify a single finding manually (F-01 example):
python3 -c 'from fnv1a_pure import fnv1a_64; print(fnv1a_64([1, 2, 3]))'
#   → returns 15035938162879559083 (int). No exception.

# 3. Re-run the full upstream fuzz harness sweep:
python3 benchmarks/adversarial/runs/run_corpus.py   # ~344s wall-clock
```

Per-finding minimal repros are embedded in each `findings.jsonl` line under
`repro` (shell command) and `repro_one_liner` (eval-able expression).

## 5. Triage decision per finding

| ID | Decision | Rationale |
|----|----------|-----------|
| **F-01** | **OPEN — defer to remediation pass** | Silent acceptance of `list`/`tuple`/`bytearray`/`memoryview` is a documented code-quality issue but not a fuzzing blocker. The audit's recommended fix is a 4-line `isinstance` guard at function entry, producing a clean `TypeError` for unsupported types. Subsumes F-02 and F-05. |
| **F-02** | **OPEN — subsumed by F-01 fix** | Cryptic CPython-internal TypeError messages are user-hostile UX, not a security issue. A single guard at function entry fixes both F-01 and F-02. |
| **F-03** | **ACCEPTED** | `fnv1_x ≡ fnv1a_x` for zero-only inputs is a **documented mathematical property of FNV** (when `byte ^ h == h * byte` for `byte == 0`, both orderings collapse). The test suite explicitly asserts it (`test_fnv1_equals_fnv1a_only_for_null_only_inputs`). Not a bug. |
| **F-04** | **ALREADY_RESOLVED** | README and `fnv1a_pure` agree; only the cycle_71 task brief was stale. Fixed in discover-fix2 at commit `7dfac11` / `14d955f`. No code or doc change required. |
| **F-05** | **OPEN — rolled into F-01 fix** | `bytearray`/`memoryview` are accepted via iteration; the decision is undocumented. Resolution depends on the F-01 fix: if F-01 accepts `bytearray`/`memoryview` explicitly (recommended), F-05 becomes a README update; if F-01 rejects them, F-05 vanishes. |

## 6. Verdict input

This card feeds the slot-05 FUZZING_REPORT card. The verdict inputs are:

- **fuzz_total_iters:** 1,350,036 (≥100k floor met; cycle_71 spec target hit)
- **fuzz_total_crashes:** 0
- **fuzz_total_hangs:** 0
- **fuzz_clean:** true
- **blocking_findings (Critical/High):** none
- **medium_findings:** 1 (F-01) — remediation recommended, not blocking
- **low_findings:** 1 (F-02) — subsumed by F-01 fix
- **info_findings:** 3 (F-03 ACCEPTED, F-04 ALREADY_RESOLVED, F-05 rolled into F-01)

**Suggested slot-05 verdict:** `VERDICT: SHIP` (no Critical/High; Medium/Low are
remediation candidates that do not block the v0.1.0 ship; fuzz run is clean
under the per-surface 300s cap).
