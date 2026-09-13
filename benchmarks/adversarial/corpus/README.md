# cycle_71 / adversary / slot-03 — Seed Corpus + Fuzz Execution Run

## What this directory is

The cycle_71 adversary workstream slot-03 artifact tree. Contains:

  benchmarks/adversarial/corpus/    — deterministic seed corpus (this card)
  benchmarks/adversarial/runs/      — per-harness run_stats.json + corpus_run_summary.json
  benchmarks/adversarial/harnesses/ — (slot-02) fuzzing harnesses, unchanged

## How the seed corpus was built

  $ python3 benchmarks/adversarial/corpus/build_corpus.py \
      --out benchmarks/adversarial/corpus/seed

  Inputs: 344 deterministic files across 8 categories.
  Manifest: benchmarks/adversarial/corpus/seed/manifest.jsonl
  Summary: benchmarks/adversarial/corpus/seed/SUMMARY.json

| Category          | Count | What it covers                            |
|-------------------|-------|-------------------------------------------|
| ref_vectors       |     4 | spec-published AC vectors (32-bit + 64-bit) |
| single_byte       |   256 | every byte value 0x00..0xFF               |
| boundaries        |    19 | sizes 0,1,2,7,8,15,16,31,32,63,64,127,128,254,255,256,257,1024,10240 |
| zero_filled       |     6 | all-zeros at 1,16,255,256,1024,10240 bytes |
| ones_filled       |     6 | all-0xFF at the same sizes                 |
| adversarial_bytes |     6 | alt 0x00/0xFF, period-3, period-7, ascii-low, 1 MiB ascii-max |
| random_fixtures   |    32 | deterministic 10 KiB random blobs (seed=20260913) |
| malformed         |    15 | non-bytes descriptors: str, int, None, float, bool, bytearray, memoryview, list, tuple, generator |

  Total: 344 inputs.

## How the fuzzer execution was run

  $ python3 benchmarks/adversarial/corpus/run_corpus.py

  Budget (per cycle_64 lesson: 2700s total + 300s per-surface cap):
    harness_fnv1a_64         1,000,000 iters  (~92s, cap 300s)
    harness_fnv1_vs_fnv1a      250,000 iters  (~85s, cap 300s)
    harness_boundary           100,000 iters  (~170s, cap 300s)
    harness_type_acceptance         1 matrix  (~0s, cap 30s)

  Total randomized iterations: 1,350,036 (13.5x the 100k floor).
  Total wall-clock: ~344s.

## Results

  All four harnesses: PASS, exit 0, verdict PASS.
  Crash count: 0. Hang count: 0. Timed-out: 0.
  Every spec vector matched (corpus manifest independently verified).
  Long-input performance: 1 MiB hashed in 0.038-0.045s (well under 1s budget).
  Mask invariant held across 100k randomized inputs (harness_boundary).
  FNV-1 vs FNV-1a ordering held across 250k randomized inputs
    (harness_fnv1_vs_fnv1a).
  All-zero absorption property held across 6 zero-filled inputs.
  Type-acceptance contract locked-in: bytearray/memoryview/list/tuple
    silently produce correct hashes; str/int/None raise TypeError;
    generator yielding bytes silently produces correct hash (per audit
    F-01 medium-severity observation; remediation recommended, not blocking).

## Artifacts

  corpus_run_summary.json                      — aggregate stats (1 file)
  harness_fnv1a_64.run_stats.json              — per-harness stats (1 file)
  harness_fnv1_vs_fnv1a.run_stats.json         — per-harness stats (1 file)
  harness_boundary.run_stats.json              — per-harness stats (1 file)
  harness_type_acceptance.run_stats.json       — per-harness stats (1 file)
  build_corpus.py                              — corpus builder (reproducible)
  run_corpus.py                                — fuzz executor (reproducible)
  seed/                                        — 344 deterministic input files

## Reproducibility

  $ cd benchmarks/adversarial
  $ python3 corpus/build_corpus.py            # deterministic, seed=20260913
  $ python3 corpus/run_corpus.py              # deterministic, seed=20260913

  Harness SHA-256s are recorded in each run_stats.json so slot-04 can
  verify they remained unchanged from slot-02.

## Handoff to slot-04

  - Findings = 0 reproducible crashes/hangs across 1,350,036 iterations.
  - The audit's two contract observations (F-01 type-acceptance and
    F-02 spec-vector lock) are LOCKED IN by the harness type_acceptance
    and harness_boundary records respectively. Slot-04 should confirm
    these are still consistent with the audit and attribute any future
    regression to the relevant finding.
  - The 1 MiB ascii_max fixture in adversarial_bytes/ would catch any
    silent early-exit on long inputs; it did NOT trip in this run.
  - Every per-harness run_stats.json contains the canonical keys
    required by the slot-03 contract: harness, iters_requested,
    iters_completed, len_max, crash_count, hang_count, coverage_paths,
    max_depth, harness_sha256, elapsed_seconds, verdict, exit_code,
    started_at, ended_at.
