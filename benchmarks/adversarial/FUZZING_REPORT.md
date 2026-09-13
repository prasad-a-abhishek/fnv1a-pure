# cycle_71 Adversary Fuzzing Report — fnv1a-pure v0.1.0

| Field            | Value                                                                                                |
|------------------|------------------------------------------------------------------------------------------------------|
| Cycle            | 71                                                                                                   |
| Repo             | fnv1a-pure                                                                                           |
| Phase            | adversary                                                                                            |
| Report date      | 2026-09-13                                                                                           |
| Target commit    | `0715056` (qa: cycle_71 QA_REPORT — VERDICT: SHIP) on `wt/cycle_71-build`                             |
| Source audit     | `4bc46d2` on `wt/cycle_71-adversary-01` (`benchmarks/adversarial/VULN_AUDIT.md`)                     |
| Harnesses commit | `6c2e815` on `wt/cycle_71-adversary-02` (4 stdlib harnesses)                                         |
| Fuzz run commit  | `61da90d` on `wt/cycle_71-adversary-03` (1,350,036 iters, 0 crashes/hangs)                          |
| Triage commit    | `37dd6ab` on `wt/cycle_71-adversary-04` (`findings.jsonl`, `SUMMARY.json`, `README.md`)              |
| Fuzz surfaces    | 4 (harness_fnv1a_64, harness_fnv1_vs_fnv1a, harness_boundary, harness_type_acceptance)              |
| Total iterations | 1,350,036 randomized + 344 corpus-file replays (corpus-backed)                                       |
| Total wall-clock | ~344s (within per-surface 300s cap, total well under 2700s budget)                                   |

---

## 1. Methodology

**Harness set.** Four stdlib-only Python harnesses committed at
`6c2e815` on `wt/cycle_71-adversary-02` (no atheris, no native deps). Each
harness is standalone, takes a `--iters`/`--seed`/`--len-min`/`--len-max`
argv, prints a JSON summary on stdout, and exits 0 on a clean run.

| Harness                       | LOC  | Surface coverage                                                                   |
|-------------------------------|------|----------------------------------------------------------------------------------|
| `harness_fnv1a_64.py`         | 169  | `fnv1a_64()` randomized fuzz (must never raise; mask & offset invariants)        |
| `harness_fnv1_vs_fnv1a.py`    | 248  | Ordering invariant: FNV-1 vs FNV-1a differ on non-empty inputs                   |
| `harness_boundary.py`         | 257  | Spec ref vectors + 57 boundary-size checks (0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 254, 255, 256, 257, 1024, 10240) + 1 MiB perf check |
| `harness_type_acceptance.py`  | 282  | Per-function × per-type observation table (None/str/int/bytearray/memoryview/list/tuple/generator) |

**Seed corpus.** 344 deterministic inputs across 8 categories built by
`benchmarks/adversarial/corpus/build_corpus.py`:

| Category          | Count | Purpose                                                                      |
|-------------------|-------|------------------------------------------------------------------------------|
| ref_vectors       |     4 | Spec-published AC vectors (fnv1a_32 + fnv1a_64, empty + 3 inputs)             |
| single_byte       |   256 | Every byte value `0x00..0xFF` (256 distinct outputs invariant)                |
| boundaries        |    19 | Boundary sizes (0,1,2,7,8,15,16,31,32,63,64,127,128,254,255,256,257,1024,10240) |
| zero_filled       |     6 | All-zeros at 1, 16, 255, 256, 1024, 10240 bytes                              |
| ones_filled       |     6 | All-`0xFF` at the same sizes                                                  |
| adversarial_bytes |     6 | Alt 0x00/0xFF, period-3, period-7, ascii-low, 1 MiB ascii-max                 |
| random_fixtures   |    32 | Deterministic 10 KiB random blobs (seed=`20260913`)                           |
| malformed         |    15 | Non-bytes descriptors: str, int, None, float, bool, bytearray, memoryview, list, tuple, generator |

**Iterations.** Per-harness budget (cycle_64 lesson: 2700s total + 300s
per-surface cap):

| Harness                  | Iters          | Wall-clock | Cap   | Verdict |
|--------------------------|----------------|------------|-------|---------|
| harness_fnv1a_64         | 1,000,000      | 91.7s      | 300s  | PASS    |
| harness_fnv1_vs_fnv1a    | 250,000        | 83.3s      | 300s  | PASS    |
| harness_boundary         | 100,000        | 168.0s     | 300s  | PASS    |
| harness_type_acceptance  | 36 cells       | 0.02s      | 30s   | PASS    |
| **Total**                | **1,350,036**  | ~344s      | 2700s |         |

13.5× the 100k-iteration floor from the cycle_71 spec. The per-surface
300s cap (cycle_64 retro-lesson) was enforced via
`benchmarks/adversarial/runs/run_corpus.py` (subprocess timeout).

**Environment.** `/usr/local/bin/python3` (CPython 3.11.x), Linux
6.12.67-linuxkit, single process, single thread. `fnv1a-pure`
installed at HEAD via `pip install -e .` from a clean venv (verified by
QA fresh-venv smoke at commit `0715056`).

**Coverage.** Per-harness `coverage_paths` lists every `fnv1a_pure`
module symbol touched during the run (collected via import-trace hooks
inside each harness). All 4 harnesses collectively exercise every
public symbol (`fnv1a_64`, `fnv1_64`, `fnv1a_32`, `fnv1_32`,
`fnv1a_64_hex`, `fnv1a_32_hex`) plus the two internal helpers
(`_fnv1a_64`, `_fnv1_64` for 32-bit and 64-bit). 100% symbol coverage on
the 6 public functions.

---

## 2. Surfaces covered

| #  | Surface                                  | File paths                                                                          | Invariants checked                                                                                       |
|----|------------------------------------------|-------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| S1 | `fnv1a_64(data)` — FNV-1a 64-bit hash    | `fnv1a_pure/__init__.py:fnv1a_64`                                                   | mask `& 0xFFFFFFFFFFFFFFFF` on every step, FNV_OFFSET_64 on empty, no exception on bytes                 |
| S2 | `fnv1_64(data)` — FNV-1 64-bit hash      | `fnv1a_pure/__init__.py:fnv1_64`                                                    | multiply-then-XOR ordering vs fnv1a_64 (must differ for non-empty input)                                |
| S3 | `fnv1a_32(data)` — FNV-1a 32-bit hash    | `fnv1a_pure/__init__.py:fnv1a_32`                                                   | mask `& 0xFFFFFFFF` on every step, FNV_OFFSET_32 on empty, 4 spec vectors match                          |
| S4 | `fnv1_32(data)` — FNV-1 32-bit hash      | `fnv1a_pure/__init__.py:fnv1_32`                                                    | multiply-then-XOR ordering vs fnv1a_32                                                                   |
| S5 | `fnv1a_64_hex(data)` — zero-padded 16-hex | `fnv1a_pure/__init__.py:fnv1a_64_hex`                                              | length == 16, lowercase, deterministic across 100 runs                                                    |
| S6 | `fnv1a_32_hex(data)` — zero-padded 8-hex  | `fnv1a_pure/__init__.py:fnv1a_32_hex`                                               | length == 8, lowercase, deterministic across 100 runs                                                     |
| S7 | Type-system surface (audit §S7)          | `fnv1a_pure/__init__.py:31-56` (all four `_fnv1*` helpers)                          | `None`/`int` raise TypeError; `str`/`bytearray`/`memoryview`/`list`/`tuple`/generator behaviour captured  |
| S8 | Empty-input behaviour                    | `fnv1a_pure/__init__.py:_fnv1a_64` / `_fnv1a_32`                                    | `fnv1a_64(b"") == FNV_OFFSET_64`, `fnv1a_32(b"") == FNV_OFFSET_32`                                       |
| S9 | FNV-1 ≡ FNV-1a on zero-only inputs       | `fnv1a_pure/__init__.py:_fnv1_64` vs `_fnv1a_64`, `_fnv1_32` vs `_fnv1a_32`         | Equality on `b""` and `b"\x00" * N` (audit §S9 + F-03 documented property)                              |
| S10| Performance / amplification (DoS)        | `fnv1a_pure/__init__.py` (all four hash fns)                                        | 1 MiB random input hashes in < 0.05s across all four functions                                          |
| S11| FNV-1 vs FNV-1a ordering distinction     | `fnv1a_pure/__init__.py:_fnv1_64` vs `_fnv1a_64` (and 32-bit)                       | Different outputs for the same non-empty input across 250k randomized inputs + 18 frozen probes           |
| S12| Hex output format / determinism          | `fnv1a_pure/__init__.py:fnv1a_64_hex`, `fnv1a_32_hex`                                | 16-char/8-char zero-padded lowercase, `int(h, 16) == raw_hash` round-trip                                |

12 surfaces — matches the audit inventory 1-to-1 (see
`benchmarks/adversarial/VULN_AUDIT.md §3`).

---

## 3. Findings ranked by severity

Counts:

| Severity | Count | IDs                                  |
|----------|-------|--------------------------------------|
| Critical | 0     | —                                    |
| High     | 0     | —                                    |
| Medium   | 1     | F-01                                 |
| Low      | 1     | F-02                                 |
| Info     | 3     | F-03, F-04, F-05                     |
| **Total**| **5** |                                      |

| ID  | Severity | Title                                                                       | Status              | CWE    | Source                          |
|-----|----------|-----------------------------------------------------------------------------|---------------------|--------|---------------------------------|
| F-01 | **Medium** | Silent acceptance of non-`bytes` iterables (list/tuple/bytearray/memoryview) | OPEN                | CWE-20 | audit §S7 + VULN_AUDIT §F-01    |
| F-02 | Low      | Cryptic TypeError messages leak CPython internals                          | OPEN (subsumed)     | CWE-209| audit §S7 + VULN_AUDIT §F-02    |
| F-03 | Info     | FNV-1 ≡ FNV-1a on zero-only inputs (documented mathematical property)     | ACCEPTED            | —      | audit §S9 + VULN_AUDIT §F-03    |
| F-04 | Info     | README test-vector table drift (pre-existing QA finding)                    | ALREADY_RESOLVED    | —      | QA t_8447f319 + VULN_AUDIT §F-04|
| F-05 | Info     | `bytearray`/`memoryview` support decision undocumented                      | OPEN (rolled in)    | —      | VULN_AUDIT §F-05                |

**Fuzz-induced finding count:** 0 (1,350,036 randomized iterations
across 4 harnesses; 0 crashes, 0 hangs, 0 timeouts).

Per-finding detail (location, repro, expected vs actual, recommendation)
is in `benchmarks/adversarial/findings/findings.jsonl` (one JSON object
per line, schema-version=1). All 5 findings originate from the manual
audit (slot-01); the fuzz run is clean.

### 3.1 F-01 — Silent acceptance of non-`bytes` iterables (Medium, CWE-20)

**Location:** `fnv1a_pure/__init__.py:31-56` (`fnv1a_64`, `fnv1_64`,
`fnv1a_32`, `fnv1_32` — all four hash entry points).

**Issue.** None of the four hash entry points validate `data` is
`bytes`. The body iterates `for byte in data:` and relies on Python's
duck typing. Consequences:

  - `bytes` / `bytearray` / `memoryview` — work correctly (intended
    path; bytearray/memoryview accepted silently, F-05).
  - `list` / `tuple` — work, but elements outside `0..255` silently
    produce a meaningless hash (e.g. `fnv1a_64([1, 2, 3])` returns
    `15035938162879559083` — a meaningless 64-bit number that the
    caller cannot distinguish from a valid hash).
  - `generator yielding bytes` — works, but the consumer cannot tell
    they passed a one-shot iterable.
  - `None` / `int` — raise `TypeError: argument of type 'NoneType' is
    not iterable` / `'int' object is not iterable` (clean).
  - `str` — raises `TypeError: unsupported operand type(s) for ^=:
    'int' and 'str'` deep inside the for-loop (4 bytes in) with a
    CPython-internal message (F-02).

**Expected behavior.** Either (a) raise `TypeError("fnv1a_64 expected
bytes-like, got list")` early at function entry, or (b) explicitly
document and support `bytearray`/`memoryview` and reject
`list`/`tuple`/generator. Recommended: option (a) — strict
`isinstance(data, (bytes, bytearray, memoryview))` guard.

**Blast radius.** Medium. Silent wrong hashes in downstream consumers
(bloom filters, hash tables, cache keys, load-balancer ring hashing)
cause data corruption, missed cache hits, and mis-routing. The
hash IS a valid 64-bit number — callers cannot detect the bug without
cross-checking against a reference implementation. This is exactly the
class of bug that drives the HIGHEST_QUALITY_REPO invariant on totality.

**Remediation.** 4-line isinstance guard at the top of each of the four
hash entry points. Subsumes F-02 (cleaner error message) and F-05
(explicit bytearray/memoryview acceptance).

### 3.2 F-02 — Cryptic TypeError messages (Low, CWE-209)

**Location:** `fnv1a_pure/__init__.py:31-56` (raised from
`for byte in data:`).

**Issue.** Passing a `str` raises `TypeError: unsupported operand
type(s) for ^=: 'int' and 'str'` — the message exposes CPython's
internal operand types and points 4 bytes into the iteration loop,
not at the user-facing API.

**Expected behavior.** A clean, user-facing message: `TypeError("fnv1a_64
expected bytes-like, got str")`.

**Blast radius.** Low — UX issue, not a security issue. The same fix as
F-01 (isinstance guard) addresses both.

**Remediation.** Subsumed by F-01.

### 3.3 F-03 — FNV-1 ≡ FNV-1a on zero-only inputs (Info)

**Location:** `fnv1a_pure/__init__.py:_fnv1_64` vs `_fnv1a_64`
(same for 32-bit).

**Issue.** For inputs that contain only `0x00` bytes, FNV-1 and FNV-1a
produce identical outputs. This is a **mathematical property** of FNV:
when `byte == 0`, both orderings (`hash ^ byte` then `hash * prime`,
and `hash * prime` then `hash ^ byte`) yield the same result because
`hash ^ 0 == hash` and `hash * prime == hash * prime`.

**Status.** ACCEPTED. The test suite explicitly asserts this property
(`test_fnv1_equals_fnv1a_only_for_null_only_inputs`). Not a bug.

**Remediation.** Docs-only: add one line to README Limitations noting
that FNV-1 ≡ FNV-1a on zero-only inputs (well-known property of the
FNV family).

### 3.4 F-04 — README test-vector table drift (Info, ALREADY_RESOLVED)

**Issue.** Cycle_71 task brief was stale on the 32-bit test vectors.
Fixed in `discover-fix2` at commit `7dfac11` / `14d955f`. README and
impl now agree.

**Status.** ALREADY_RESOLVED. No code or doc change required from this
adversary chain.

### 3.5 F-05 — `bytearray`/`memoryview` support undocumented (Info)

**Issue.** `bytearray` and `memoryview` are accepted via Python's
duck-typed iteration; the decision is undocumented in README.

**Status.** OPEN — rolled into F-01. If F-01 accepts
`bytearray`/`memoryview` explicitly (recommended), F-05 becomes a
README update. If F-01 rejects them, F-05 vanishes.

**Remediation.** Subsumed by F-01 fix.

---

## 4. Reproduction instructions

All artefacts live under
`/root/projects/fnv1a-pure/benchmarks/adversarial/`. Every command is
relative to the repo root unless otherwise noted.

### 4.1 Re-run the full upstream fuzz harness sweep (~344s)

```bash
cd /root/projects/fnv1a-pure

# Per-harness invocations (cycle_71 spec budget):
python3 benchmarks/adversarial/harnesses/harness_fnv1a_64.py \
    --iters 1000000 --seed 20260913 --len-min 0 --len-max 2048   # ~92s
python3 benchmarks/adversarial/harnesses/harness_fnv1_vs_fnv1a.py \
    --iters 250000 --seed 20260913 --len-min 1 --len-max 2048   # ~83s
python3 benchmarks/adversarial/harnesses/harness_boundary.py \
    --iters 100000 --seed 20260913 --len-min 0 --len-max 10240  # ~170s
python3 benchmarks/adversarial/harnesses/harness_type_acceptance.py # <1s
```

Or run the orchestrator:

```bash
python3 benchmarks/adversarial/corpus/run_corpus.py    # ~344s total
```

### 4.2 Rebuild the seed corpus (deterministic)

```bash
python3 benchmarks/adversarial/corpus/build_corpus.py \
    --out benchmarks/adversarial/corpus/seed
```

344 inputs across 8 categories; manifest at
`benchmarks/adversarial/corpus/seed/manifest.jsonl`, summary at
`benchmarks/adversarial/corpus/seed/SUMMARY.json`.

### 4.3 Re-run triage (canonical hash pins)

```bash
python3 benchmarks/adversarial/findings/triage.py
```

Pins 12 canonical lcn2/fnv hashes at the top of `triage.py` — any drift
in `fnv1a_pure` fails the script BEFORE `findings.jsonl` is written.
Re-running is byte-identical (deterministic seed).

### 4.4 Re-derive each finding manually

```bash
# F-01: silent acceptance of list — returns 15035938162879559083, no exception
python3 -c 'from fnv1a_pure import fnv1a_64; print(fnv1a_64([1, 2, 3]))'

# F-02: cryptic TypeError on str
python3 -c 'from fnv1a_pure import fnv1a_64; fnv1a_64("hello")'

# F-03: FNV-1 ≡ FNV-1a on zero-only inputs (documented property)
python3 -c 'from fnv1a_pure import fnv1_64, fnv1a_64; assert fnv1_64(b"\x00") == fnv1a_64(b"\x00")'

# F-04: README vs impl agreement (no drift after discover-fix2)
grep -n 'fnv1a_64(b"a")' README.md
python3 -c 'from fnv1a_pure import fnv1a_64; print(fnv1a_64(b"a"))'
#   both: 12638187200555641996

# F-05: bytearray silently accepted
python3 -c 'from fnv1a_pure import fnv1a_64; print(fnv1a_64(bytearray(b"hello")))'
```

### 4.5 Inspect artefacts

```bash
# Per-harness run stats:
ls benchmarks/adversarial/runs/*.run_stats.json
cat benchmarks/adversarial/runs/corpus_run_summary.json | jq

# Findings (JSONL, one object per line, schema-version=1):
cat benchmarks/adversarial/findings/findings.jsonl | jq -c '{id,severity,status,title}'

# Audit (12 surfaces, MITRE CWE-mapped):
wc -l benchmarks/adversarial/VULN_AUDIT.md
```

---

## 5. Verdict

```
VERDICT: SHIP
```

**Rationale.**

- **0 Critical / 0 High.** No unmitigated exploitable vulnerabilities.
- **1 Medium (F-01):** Silent acceptance of `list`/`tuple` is a
  documented code-quality issue. It is NOT a fuzzing blocker — every
  fuzz harness exit-0'd, every spec vector matched, every invariant
  held across 1.35M iterations. The remediation is a 4-line
  isinstance guard; F-01 + F-02 + F-05 all collapse to that single
  change. Per the cycle_71 spec, Medium findings are remediation
  candidates, not blockers.
- **1 Low (F-02):** Subsumed by F-01 fix. No standalone action.
- **3 Info (F-03 ACCEPTED, F-04 ALREADY_RESOLVED, F-05 rolled in).**
  F-03 is a documented mathematical property (test-suite asserts it);
  F-04 was fixed in `discover-fix2`; F-05 becomes a README update once
  F-01's isinstance guard makes bytearray/memoryview explicit.
- **Fuzz run is clean.** 1,350,036 randomized iterations + 344
  corpus-file replays across 4 harnesses. 0 crashes, 0 hangs, 0
  timeouts. Every spec vector matched. Long-input performance is
  ~0.04s for 1 MiB (50× under the 1s budget). Mask invariants held
  across 100k randomized inputs per surface.
- **Algorithm is canonical.** Cross-checked against lcn2/fnv and
  isthe.com/chongo reference outputs at audit time (audit §5). 12/12
  canonical hashes pinned in `triage.py` and re-verified at every
  triage run.

**Verdict inputs from slot-04 triage:**

```
fuzz_total_iters:           1,350,036  (≥ 100k floor met; 13.5×)
fuzz_total_crashes:         0
fuzz_total_hangs:           0
fuzz_clean:                 true
blocking_findings (Crit/High): none
medium_count:               1
low_count:                  1
info_count:                 3
```

---

## 6. Remediation plan (optional — non-blocking)

Per the cycle_71 spec, the verdict is SHIP and these items are
**remediation candidates**, not ship blockers. The orchestrator will
mint a fix card if the operator chooses to address them; otherwise
they roll forward into a follow-up cycle.

### 6.1 F-01 (Medium, src-fix) — Strict bytes-like input guard

**Location:** `fnv1a_pure/__init__.py:31-56` (all four hash entry
points: `fnv1a_64`, `fnv1_64`, `fnv1a_32`, `fnv1_32`).

**Change.** Add at the top of each of the four public hash functions:

```python
if not isinstance(data, (bytes, bytearray, memoryview)):
    raise TypeError(
        f"{func_name} expected bytes-like, got {type(data).__name__}"
    )
```

(Where `func_name` is the literal function name — `"fnv1a_64"`,
`"fnv1_64"`, `"fnv1a_32"`, `"fnv1_32"`.)

**Subsumes:**
- F-01 (no more silent wrong hashes from `list`/`tuple`/generator)
- F-02 (clean user-facing TypeError message)
- F-05 (explicit bytearray/memoryview acceptance — no change to
  current behaviour, but the decision is now documented in code)

**Effort:** 4 lines (one per function) + 4 unit tests. ~15 minutes.

**Risk:** None. bytearray and memoryview are already accepted; the
guard only tightens the rejection path for `list`/`tuple`/`str`/
generator-of-bytes. Existing callers using bytes are unaffected.

### 6.2 F-03 (Info, doc-only) — Document zero-only FNV-1 ≡ FNV-1a

**Location:** `README.md` (add to Limitations section).

**Change.** One-line note: "On inputs containing only `0x00` bytes,
FNV-1 and FNV-1a produce identical outputs (mathematical property of
the FNV family; both orderings collapse when `byte ^ h == h * byte`
for `byte == 0`)."

**Effort:** 2 minutes.

### 6.3 No action required

- **F-02** — subsumed by F-01 fix.
- **F-04** — already resolved in `discover-fix2` at commit `7dfac11`.
- **F-05** — subsumed by F-01 fix (the isinstance guard makes the
  bytearray/memoryview decision explicit in code; README update rolls
  into the F-03 doc-only change above).

---

## Appendix A — Audit-trail anchors

| Slot | Commit    | Branch                       | Artefact                                                |
|------|-----------|------------------------------|---------------------------------------------------------|
| 01   | `4bc46d2` | `wt/cycle_71-adversary-01`   | `benchmarks/adversarial/VULN_AUDIT.md` (467 lines, 12 surfaces, MITRE CWE-mapped) |
| 02   | `6c2e815` | `wt/cycle_71-adversary-02`   | `benchmarks/adversarial/harnesses/` (4 stdlib harnesses, 956 LOC) |
| 03   | `61da90d` | `wt/cycle_71-adversary-03`   | `benchmarks/adversarial/corpus/seed/` (344 inputs) + `benchmarks/adversarial/runs/corpus_run_summary.json` |
| 04   | `37dd6ab` | `wt/cycle_71-adversary-04`   | `benchmarks/adversarial/findings/{findings.jsonl,SUMMARY.json,README.md,triage.py}` |
| 05   | (this)    | `wt/cycle_71-adversary-05`   | `benchmarks/adversarial/FUZZING_REPORT.md`              |

## Appendix B — Verdict line (machine-readable)

```
VERDICT: SHIP
findings_total: 5
by_severity: {Critical: 0, High: 0, Medium: 1, Low: 1, Info: 3}
blocking_findings: []
fuzz_clean: true
fuzz_total_iters: 1350036
fuzz_total_crashes: 0
fuzz_total_hangs: 0
target_commit: 0715056
```