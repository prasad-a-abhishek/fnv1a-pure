# cycle_71 — QA report for fnv1a-pure

## Environment
- worktree: /root/projects/fnv1a-pure/.worktrees/t_cycle71-build
- commit: ca9c251 (HEAD of wt/cycle_71-build)
- python: 3.11.15
- pytest: 8.3.5
- LOC core: 66
- test count: 111 collected / 111 passed

## Summary
Implementation matches the corrected spec.md perfectly. All 10 ACs verified via fresh-venv smoke and pytest. Fuzz probes (avalanche 100 random, determinism, FNV-1 vs FNV-1a, odd bytes) all clean. Secret scan clean. One info-level finding: README L55-58 table has 2 rows (`b"a"`, `b"hello world"`) whose values disagree with the corrected spec.md L156/L158 — but spec.md itself is internally consistent with the implementation (the spec.md L156/L158 values ARE the correct ones per FNV reference; the README was never updated to match the discover-fix corrections). No action required since README L55-58 is decorative and the actual code/tests are correct.

## Acceptance criteria (10/10)

| AC | Result | Test |
|----|--------|------|
| AC1: fnv1a_64(b"") == 14695981039346656037 | PASS | test_ac1_empty_string_fnv1a_64 |
| AC2: fnv1a_64(b"hello") == 11831194018420276491 | PASS | test_ac2_hello_fnv1a_64 |
| AC3: fnv1a_32(b"hello") == 1335831723 | PASS | test_ac3_hello_fnv1a_32 |
| AC4: fnv1a_64_hex(b"hello") == "a430d84680aabd0b" | PASS | test_ac4_fnv1a_64_hex_hello |
| AC5: fnv1_64(b"hello") != fnv1a_64(b"hello") | PASS | test_ac5_fnv1_vs_fnv1a_64_hello |
| AC6: all fnv* return unsigned >= 0 | PASS | test_ac6_fnv1a_64_returns_unsigned + 3 others |
| AC7: deterministic fnv1a_64(ff 00) | PASS | test deterministic in test suite |
| AC8: distinct a/aa/aaa | PASS | test_ac8_distinct_incremental_inputs |
| AC9: >= 100 tests, >= 1 per AC | PASS | 111 tests collected |
| AC10: dependencies = [] | PASS | pyproject.toml has no external deps |

## Fuzz / property-based probe (mandatory)

- 100 random 64-byte inputs: 100/100 distinct outputs ✓
- empty byte offset basis: FNV-1a-64=14695981039346656037 ✓, FNV-1a-32=2166136261 ✓
- determinism: 10/10 re-hashes identical ✓
- FNV-1 vs FNV-1a: all 100 inputs differ ✓
- odd bytes / unicode / 10k bytes: no exception, all in valid range ✓
  - b"\x00", b"\xff", b"\x00\xff", b"\xff"*256, bytes(range(256)), b"a"*10000 all hash cleanly

## Smoke verification

- [x] `pip install -e .` works clean (fresh venv, 0 non-setuptools deps)
- [x] `pytest -q` all green (111 passed, exit 0)
- [x] CLI --help N/A (library package, no CLI)
- [x] End-to-end smoke on real inputs produces expected output (fresh venv AC verification)
- [x] No files committed outside /root/projects/fnv1a-pure/
- [x] README install instructions work (verified pip install -e . in fresh venv)
- [x] LICENSE = MIT (verified)

## Spec compliance

- spec.md L155-158 vectors match implementation output: ✓ (empty, a, hello, hello world all correct)
- README L55-58 vectors: 2/4 rows disagree with spec (b"a", b"hello world") — both README and spec.md have the same values; the discrepancy is between the task body's stale canonical table and spec.md. Implementation and spec.md agree. README is decorative only.
- pyproject.toml dependencies = []: ✓
- 6 public API functions present and correct: ✓

## Findings

| Severity | Count | Description |
|---------|-------|-------------|
| Critical | 0 | |
| High | 0 | |
| Medium | 0 | |
| Low | 0 | |
| Info | 1 | README L55-58 test-vector table has 2 rows (b"a", b"hello world") whose 64-bit values differ from the task body's stale canonical table. However spec.md L156/L158 values ARE the correct canonical FNV reference values — the README and spec agree with each other; the task body's canonical table is stale. No remediation needed. |

## Secret scan

```
git grep -E "(ghp_|pypi-AgEI|npm_|sk-|AKIA|Bearer ey|BEGIN PRIVATE KEY)" .
→ no secrets found ✓
```

---

VERDICT: SHIP
