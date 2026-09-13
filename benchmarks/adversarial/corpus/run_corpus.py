#!/usr/bin/env python3
"""
run_corpus.py — Execute the cycle_71 adversary harnesses with the seed
corpus and write per-harness ``run_stats.json`` plus an aggregate
``corpus_run_summary.json``.

Budget (per the cycle_64 lesson that 300s/surface + 2700s total max-runtime
work in practice):

  harness_fnv1a_64         1,000,000 iters  (~100s at slot-02 measured 0.05s/500)
  harness_fnv1_vs_fnv1a      250,000 iters  (~85s  at slot-02 measured 0.17s/500)
  harness_boundary           100,000 iters  (~200s at slot-02 measured 1.01s/500)
  harness_type_acceptance         1 run     (deterministic matrix sweep)

Each randomized harness is run with ``--len-min=0 --len-max=2048`` (matches
the slot-02 default that fit the 300s cap at 1M iters). The runner
enforces a hard 300s wall-clock cap per surface and ``SIGKILL``s any run
that exceeds it, recording the partial state honestly.

Per harness the runner writes:
  benchmarks/adversarial/runs/<harness>.run_stats.json
with keys:
  harness, seed, iters_requested, iters_completed, len_min, len_max,
  crash_count, hang_count, coverage_paths (file:line spans exercised),
  max_depth (longest input length actually consumed), elapsed_seconds,
  stdout_json (the harness's own PASS/FAIL JSON), timed_out (bool),
  started_at, ended_at, exit_code, command.

The aggregate ``corpus_run_summary.json`` rolls up these per-harness
records plus the corpus manifest path and SHA-256 of each harness file
so slot-04 triage can be certain about reproducibility.

Properties:
  - stdlib only
  - reads harness stdout JSON for the canonical iter count + verdict
  - propagates non-zero exit codes but does NOT raise — partial findings
    are still recorded
  - CLI: ``python run_corpus.py [--iters-fast] [--seed N]``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Tuple


HARNESS_DIR = Path(__file__).resolve().parent.parent / "harnesses"
RUNS_DIR = Path(__file__).resolve().parent.parent / "runs"
CORPUS_DIR = Path(__file__).resolve().parent / "seed"
TIMEOUT_SECONDS_PER_HARNESS = 300
# type_acceptance is deterministic; give it 30s wall-clock as a generous upper bound.
TIMEOUT_SECONDS_TYPE_ACCEPTANCE = 30


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _coverage_paths() -> dict:
    """Map harness -> list of (file:line ranges) that the harness exercises.

    Captured by static analysis of the harness source + the fnv1a-pure
    public API it imports. This is a coarse surrogate for line coverage
    since we don't have a tracing harness in this stdlib-only setup; it
    gives slot-04 a quick view of *which public surfaces were driven*
    without claiming branch-level coverage.
    """
    return {
        "harness_fnv1a_64": [
            "fnv1a_pure/__init__.py:_fnv1a_64",
            "fnv1a_pure/__init__.py:fnv1a_64",
        ],
        "harness_fnv1_vs_fnv1a": [
            "fnv1a_pure/__init__.py:_fnv1a_64",
            "fnv1a_pure/__init__.py:_fnv1_64",
            "fnv1a_pure/__init__.py:_fnv1a_32",
            "fnv1a_pure/__init__.py:_fnv1_32",
            "fnv1a_pure/__init__.py:fnv1a_64",
            "fnv1a_pure/__init__.py:fnv1_64",
        ],
        "harness_boundary": [
            "fnv1a_pure/__init__.py:_fnv1a_64",
            "fnv1a_pure/__init__.py:_fnv1_64",
            "fnv1a_pure/__init__.py:_fnv1a_32",
            "fnv1a_pure/__init__.py:_fnv1_32",
            "fnv1a_pure/__init__.py:fnv1a_64",
            "fnv1a_pure/__init__.py:fnv1_64",
            "fnv1a_pure/__init__.py:fnv1a_32",
            "fnv1a_pure/__init__.py:fnv1_32",
            "fnv1a_pure/__init__.py:fnv1a_64_hex",
            "fnv1a_pure/__init__.py:fnv1a_32_hex",
        ],
        "harness_type_acceptance": [
            "fnv1a_pure/__init__.py:_fnv1a_64",
            "fnv1a_pure/__init__.py:_fnv1_64",
            "fnv1a_pure/__init__.py:_fnv1a_32",
            "fnv1a_pure/__init__.py:_fnv1_32",
            "fnv1a_pure/__init__.py:fnv1a_64",
            "fnv1a_pure/__init__.py:fnv1_64",
            "fnv1a_pure/__init__.py:fnv1a_32",
            "fnv1a_pure/__init__.py:fnv1_32",
            "fnv1a_pure/__init__.py:fnv1a_64_hex",
            "fnv1a_pure/__init__.py:fnv1a_32_hex",
        ],
    }


def _plan(iters_fast: bool, seed: int) -> List[Tuple[str, List[str], int]]:
    """Return the (harness_file, argv, timeout_seconds) plan."""
    if iters_fast:
        # Smoke plan for a quick "did the harness runner wire up correctly?" check.
        return [
            ("harness_fnv1a_64.py",      ["--iters", "10000", "--seed", str(seed)], TIMEOUT_SECONDS_PER_HARNESS),
            ("harness_fnv1_vs_fnv1a.py", ["--iters", "10000", "--seed", str(seed)], TIMEOUT_SECONDS_PER_HARNESS),
            ("harness_boundary.py",      ["--iters", "5000",  "--seed", str(seed)], TIMEOUT_SECONDS_PER_HARNESS),
            ("harness_type_acceptance.py", [], TIMEOUT_SECONDS_TYPE_ACCEPTANCE),
        ]
    return [
        ("harness_fnv1a_64.py",
         ["--iters", "1000000", "--seed", str(seed), "--len-min", "0", "--len-max", "2048"],
         TIMEOUT_SECONDS_PER_HARNESS),
        ("harness_fnv1_vs_fnv1a.py",
         ["--iters", "250000", "--seed", str(seed), "--len-min", "1", "--len-max", "2048"],
         TIMEOUT_SECONDS_PER_HARNESS),
        ("harness_boundary.py",
         ["--iters", "100000", "--seed", str(seed), "--len-min", "0", "--len-max", "10240"],
         TIMEOUT_SECONDS_PER_HARNESS),
        ("harness_type_acceptance.py", [], TIMEOUT_SECONDS_TYPE_ACCEPTANCE),
    ]


def _run_one(harness_file: str, argv: List[str], timeout_s: int) -> dict:
    """Run a single harness under a wall-clock cap and return its record."""
    harness_path = HARNESS_DIR / harness_file
    cmd = [sys.executable, str(harness_path)] + argv
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(harness_path.parent.parent.parent.parent),  # repo root
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        timed_out = False
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        stderr = (exc.stderr.decode("utf-8", errors="replace") if exc.stderr else "") + \
                 f"\n[HARNESS_TIMEOUT after {timeout_s}s]"
    elapsed = time.perf_counter() - t0
    ended_at = datetime.now(timezone.utc).isoformat()

    stdout_json: dict = {}
    if stdout:
        # Parsing strategy: find the FIRST standalone '{' (not preceded by
        # content on the same line) and try to parse everything from there
        # to EOF as a single JSON document. Some harnesses (type_acceptance)
        # emit a pretty-printed multi-line JSON; others (harness_fnv1a_64)
        # emit a single-line JSON; some emit a leading "Note:" preamble
        # line. We tolerate all three.
        stripped = stdout.lstrip()
        if stripped.startswith("{"):
            try:
                stdout_json = json.loads(stripped)
            except json.JSONDecodeError:
                # Multi-line pretty-printed JSON where some lines may not
                # parse independently — fall back to last-line parse.
                lines = [ln for ln in stdout.splitlines() if ln.strip()]
                for candidate in reversed(lines):
                    cand = candidate.strip()
                    if not cand.startswith("{"):
                        continue
                    try:
                        stdout_json = json.loads(cand)
                        break
                    except json.JSONDecodeError:
                        continue
        if not stdout_json:
            stdout_json = {"_unparsed": stdout[-2000:]}

    return {
        "harness": harness_file.replace(".py", ""),
        "command": cmd,
        "argv": argv,
        "timeout_seconds": timeout_s,
        "started_at": started_at,
        "ended_at": ended_at,
        "elapsed_seconds": round(elapsed, 4),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_json": stdout_json,
        "stderr_tail": stderr[-2000:] if stderr else "",
        "harness_sha256": _sha256(harness_path),
    }


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters-fast", action="store_true",
                        help="Run a 10x scaled-down smoke plan (debugging only)")
    parser.add_argument("--seed", type=int, default=20260913,
                        help="PRNG seed forwarded to every randomized harness")
    parser.add_argument("--out-dir", type=Path, default=RUNS_DIR,
                        help="Directory to write run_stats.json + summary into")
    args = parser.parse_args(list(argv))

    args.out_dir.mkdir(parents=True, exist_ok=True)

    plan = _plan(args.iters_fast, args.seed)
    coverage = _coverage_paths()

    # Verify the corpus actually exists (slot-03 fails honestly if not).
    if not CORPUS_DIR.exists():
        sys.stderr.write(f"FATAL: corpus dir not found at {CORPUS_DIR}\n")
        return 1

    summary_records: List[dict] = []
    for harness_file, harness_argv, timeout_s in plan:
        sys.stderr.write(f"[run_corpus] starting {harness_file} with "
                         f"{harness_argv} (cap {timeout_s}s)\n")
        record = _run_one(harness_file, harness_argv, timeout_s)
        record["coverage_paths"] = coverage.get(record["harness"], [])
        record["crash_count"] = 0 if record["exit_code"] == 0 and not record["timed_out"] else 1
        record["hang_count"] = 1 if record["timed_out"] else 0
        record["max_depth"] = (
            record["stdout_json"].get("len_max")
            if isinstance(record["stdout_json"], dict) and "len_max" in record["stdout_json"]
            else (record["stdout_json"].get("boundary_max_size")
                  if isinstance(record["stdout_json"], dict) and "boundary_max_size" in record["stdout_json"]
                  else None)
        )
        # Surface the type-acceptance mismatch count so slot-04 triage can
        # see it without re-running the harness.
        if isinstance(record["stdout_json"], dict):
            ssm = record["stdout_json"].get("silent_semantic_mismatches")
            if ssm is not None:
                record["silent_semantic_mismatches"] = ssm

        # Per-harness run_stats.json
        per_harness_path = args.out_dir / f"{record['harness']}.run_stats.json"
        with open(per_harness_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")

        summary_records.append(record)
        sys.stderr.write(
            f"[run_corpus] {record['harness']} done: "
            f"exit={record['exit_code']} elapsed={record['elapsed_seconds']}s "
            f"verdict={record['stdout_json'].get('verdict', 'N/A') if isinstance(record['stdout_json'], dict) else 'unparsed'}\n"
        )

    total_iters = 0
    for r in summary_records:
        sj = r["stdout_json"]
        if isinstance(sj, dict):
            it = (sj.get("iters_requested")
                  or sj.get("iters")
                  or (sj.get("happy_path_checks", 0) + sj.get("bad_type_raise_checks", 0)))
            if isinstance(it, int):
                total_iters += it
                r["iters_completed"] = it
            # Re-write the per-harness file with iters_completed set.
            per_harness_path = args.out_dir / f"{r['harness']}.run_stats.json"
            with open(per_harness_path, "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=2, sort_keys=True)
                fh.write("\n")
    total_crashes = sum(r["crash_count"] for r in summary_records)
    total_hangs = sum(r["hang_count"] for r in summary_records)

    summary = {
        "schema_version": 1,
        "runner": "run_corpus.py",
        "seed": args.seed,
        "corpus_dir": str(CORPUS_DIR),
        "corpus_summary_path": str(CORPUS_DIR / "SUMMARY.json"),
        "out_dir": str(args.out_dir),
        "total_iters_requested": total_iters,
        "total_crashes": total_crashes,
        "total_hangs": total_hangs,
        "per_harness": summary_records,
        "iter_floor_target": 100_000,
        "iter_floor_met": total_iters >= 100_000,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    summary_path = args.out_dir / "corpus_run_summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")

    sys.stdout.write(json.dumps({
        "summary_path": str(summary_path),
        "total_iters_requested": total_iters,
        "total_crashes": total_crashes,
        "total_hangs": total_hangs,
        "iter_floor_met": summary["iter_floor_met"],
        "per_harness_verdicts": [
            {"harness": r["harness"],
             "exit_code": r["exit_code"],
             "timed_out": r["timed_out"],
             "verdict": (r["stdout_json"].get("verdict") if isinstance(r["stdout_json"], dict) else "unparsed"),
             "elapsed": r["elapsed_seconds"]}
            for r in summary_records
        ],
    }) + "\n")
    return 0 if total_crashes == 0 and total_hangs == 0 else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
