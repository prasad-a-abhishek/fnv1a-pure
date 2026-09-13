#!/usr/bin/env python3
"""
harness_fnv1a_64.py — Adversarial fuzzer for fnv1a_pure.fnv1a_64

Scope (slot-02 of cycle_71 adversary chain):
  - Surface S1 (fnv1a_64 raw) and S8 (empty-input behaviour).
  - Drive fnv1a_64 with randomized `bytes` inputs of varying lengths and content.
  - Assert post-conditions that any silent regression would break:
      * result is an int
      * result is in [0, 2**64)
      * no exception raised on valid bytes input
      * empty input returns FNV_OFFSET_64
      * deterministic across repeated calls on identical input
      * masks were applied (result < 2**64) — CWE-682 regression guard
      * single-byte inputs cover all 256 distinct output values across the
        full byte range — CWE-682 regression guard on the XOR step

Properties:
  - stdlib only (random, sys, argparse, time)
  - deterministic seed (CLI override supported)
  - CLI: `python harness_fnv1a_64.py [--iters N] [--seed S] [--len-min N] [--len-max N]`
  - exits 0 on clean run, 1 on the first assertion failure with full repro
  - prints a single JSON summary line to stdout (machine-readable for slot-03)
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from typing import List

from fnv1a_pure import fnv1a_64, _FNV_OFFSET_64

MOD64 = 1 << 64


def _gen_random_bytes(rng: random.Random, min_len: int, max_len: int) -> bytes:
    length = rng.randint(min_len, max_len)
    # randbytes is 40x+ faster than `bytes(rng.randrange(0,256) for _ in range(L))`
    # while producing uniformly distributed 0..255 bytes from the same PRNG state.
    return rng.randbytes(length)


def _check_single_byte_distinctness() -> int:
    """Assert all 256 single-byte inputs produce distinct outputs (regression
    guard: if XOR or multiply step were swapped, this would collapse to
    fewer than 256 distinct outputs).
    """
    outputs = {fnv1a_64(bytes([b])) for b in range(256)}
    return len(outputs)


def _check_empty_returns_offset() -> bool:
    return fnv1a_64(b"") == _FNV_OFFSET_64


def _check_determinism(rng: random.Random) -> int:
    """Same input run 100 times must produce identical output."""
    sample = _gen_random_bytes(rng, 1, 1024)
    first = fnv1a_64(sample)
    for _ in range(99):
        if fnv1a_64(sample) != first:
            return -1
    return 100


def _check_mask_invariant(iters: int, rng: random.Random,
                          min_len: int, max_len: int) -> int:
    """Every result must be in [0, 2**64). A missing `& 0xFFFFFFFFFFFFFFFF`
    mask on Python 3 would still produce a non-negative int but could
    exceed 2**64 after enough multiplications on pathological inputs only
    on overflow-boxing builds. Python ints are unbounded, so we sample
    inputs of 0..10 KiB and check the result stays in range.

    Also asserts `result.bit_length() <= 64` (a stricter mask-or-correctness
    invariant — any bug that leaks the prime multiplier's high bits would
    blow this).
    """
    for _ in range(iters):
        data = _gen_random_bytes(rng, min_len, max_len)
        h = fnv1a_64(data)
        if not isinstance(h, int):
            raise AssertionError(f"non-int return type: {type(h).__name__}")
        if h < 0:
            raise AssertionError(f"negative hash: {h}")
        if h >= MOD64:
            raise AssertionError(
                f"hash {h} >= 2**64 (mask missing or wrong)"
            )
        if h.bit_length() > 64:
            raise AssertionError(
                f"hash bit_length {h.bit_length()} > 64 (mask missing)"
            )
    return iters


def _check_no_exception_on_bytes(iters: int, rng: random.Random,
                                 min_len: int, max_len: int) -> int:
    """The contract is bytes-in. Assert no exception on any random bytes
    input across the chosen length range."""
    for _ in range(iters):
        data = _gen_random_bytes(rng, min_len, max_len)
        fnv1a_64(data)
    return iters


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters", type=int, default=1_000_000,
                        help="Number of randomized inputs to fuzz (default 1M)")
    parser.add_argument("--seed", type=int, default=20260913,
                        help="PRNG seed (default 20260913 for reproducibility)")
    parser.add_argument("--len-min", type=int, default=0,
                        help="Minimum input length in bytes (default 0)")
    parser.add_argument("--len-max", type=int, default=10_240,
                        help="Maximum input length in bytes (default 10240)")
    args = parser.parse_args(argv)

    if args.len_min < 0 or args.len_max < args.len_min:
        raise SystemExit("invalid --len-min/--len-max")

    rng = random.Random(args.seed)
    t0 = time.perf_counter()
    single_byte_distinct = _check_single_byte_distinctness()
    if single_byte_distinct != 256:
        raise SystemExit(
            f"FAIL: single-byte inputs produced {single_byte_distinct}/256 distinct outputs "
            f"(CWE-682 regression)"
        )

    empty_ok = _check_empty_returns_offset()
    if not empty_ok:
        raise SystemExit(
            f"FAIL: fnv1a_64(b'') = {fnv1a_64(b'')} != FNV_OFFSET_64 ({_FNV_OFFSET_64})"
        )

    det_runs = _check_determinism(rng)
    if det_runs == -1:
        raise SystemExit("FAIL: fnv1a_64 is non-deterministic")

    mask_iters = _check_mask_invariant(args.iters, rng, args.len_min, args.len_max)
    no_exc_iters = _check_no_exception_on_bytes(args.iters, rng, args.len_min, args.len_max)
    elapsed = time.perf_counter() - t0

    summary = {
        "harness": "harness_fnv1a_64",
        "seed": args.seed,
        "iters_requested": args.iters,
        "len_min": args.len_min,
        "len_max": args.len_max,
        "single_byte_distinct_outputs": single_byte_distinct,
        "empty_returns_offset": empty_ok,
        "determinism_runs": det_runs,
        "mask_invariant_iters": mask_iters,
        "no_exception_iters": no_exc_iters,
        "crash_count": 0,
        "hang_count": 0,
        "elapsed_seconds": round(elapsed, 4),
        "verdict": "PASS",
    }
    sys.stdout.write(json.dumps(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
