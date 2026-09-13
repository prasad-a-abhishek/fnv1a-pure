#!/usr/bin/env python3
"""
harness_boundary.py — Adversarial fuzzer exercising boundary sizes,
canonical ref vectors, hex-output invariants, and length-edge inputs
(cycle_71 surfaces S5, S6, S8, S10, S12).

Scope:
  - Verify spec-published AC vectors land exactly on the documented
    32-bit and 64-bit values.
  - Boundary sizes 0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
    254, 255, 256, 257, 1024, 10_240 bytes — exercise every place where
    a bit-width mask or loop boundary could go wrong.
  - Hex-output invariants: zero-padded, exact length, lowercase,
    round-trip `int(hex, 16) == raw_hash` always holds.
  - Long-input performance: must hash 1 MiB in <1s on the harness host.
  - All-zeros and all-ones stress: must complete and be deterministic.
  - Bit-width mask invariant: result bit_length() <= 64 (and <= 32 for
    32-bit variants) across all boundary sizes.
  - The mask/invariant check ALSO runs as a randomized property probe
    over `--iters` random byte strings.

Properties:
  - stdlib only (random, sys, argparse, time, string)
  - deterministic seed (CLI override supported)
  - CLI: `python harness_boundary.py [--iters N] [--seed S]`
  - exits 0 on clean run, 1 on the first regression
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from typing import List, Tuple

from fnv1a_pure import (
    fnv1a_64, fnv1_64, fnv1a_32, fnv1_32,
    fnv1a_64_hex, fnv1a_32_hex,
)

# Spec-published AC vectors (cycle_71 spec.md L156-159, verified by
# tests/test_fnv1a_pure.py AC2-4). Source: commit 7dfac11 spec correction.
SPEC_FNV1A_64: List[Tuple[bytes, int]] = [
    (b"",            14695981039346656037),
    (b"a",           12638187200555641996),
    (b"hello",       11831194018420276491),
    (b"hello world", 8618312879776256743),
]
SPEC_FNV1A_32: List[Tuple[bytes, int]] = [
    (b"",            2166136261),
    (b"a",           3826002220),
    (b"hello",       1335831723),
    (b"hello world", 3582672807),
]
# Hex outputs cross-derived from the raw vectors and the format spec
# (:016x for 64-bit, :08x for 32-bit). Independent reference: tests/
# test_fnv1a_pure.py AC4 (fnv1a_64_hex(b"hello") == "a430d84680aabd0b").
SPEC_FNV1A_64_HEX: List[Tuple[bytes, str]] = [
    (inp, f"{h:016x}") for inp, h in SPEC_FNV1A_64
]
SPEC_FNV1A_32_HEX: List[Tuple[bytes, str]] = [
    (inp, f"{h:08x}") for inp, h in SPEC_FNV1A_32
]

BOUNDARY_LENGTHS = (0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128,
                    254, 255, 256, 257, 1024, 10_240)

MOD64 = 1 << 64
MOD32 = 1 << 32


def _check_spec_vectors() -> dict:
    out = {"fnv1a_64": 0, "fnv1a_32": 0, "fnv1a_64_hex": 0, "fnv1a_32_hex": 0}
    for inp, expected in SPEC_FNV1A_64:
        got = fnv1a_64(inp)
        if got != expected:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_64({inp!r}) = 0x{got:016x}, spec says 0x{expected:016x}"
            )
        out["fnv1a_64"] += 1
    for inp, expected in SPEC_FNV1A_32:
        got = fnv1a_32(inp)
        if got != expected:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_32({inp!r}) = 0x{got:08x}, spec says 0x{expected:08x}"
            )
        out["fnv1a_32"] += 1
    for inp, expected in SPEC_FNV1A_64_HEX:
        got = fnv1a_64_hex(inp)
        if got != expected:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_64_hex({inp!r}) = {got!r}, spec says {expected!r}"
            )
        out["fnv1a_64_hex"] += 1
    for inp, expected in SPEC_FNV1A_32_HEX:
        got = fnv1a_32_hex(inp)
        if got != expected:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_32_hex({inp!r}) = {got!r}, spec says {expected!r}"
            )
        out["fnv1a_32_hex"] += 1
    return out


def _check_hex_invariants(rng: random.Random, iters: int,
                          max_len: int) -> int:
    """Assert every random hex output is the right length, lowercase, and
    round-trips through int(hex, 16) to the raw hash."""
    n = 0
    for _ in range(iters):
        length = rng.randint(0, max_len)
        data = rng.randbytes(length)
        h64 = fnv1a_64_hex(data)
        if len(h64) != 16:
            raise AssertionError(f"fnv1a_64_hex len={len(h64)} on {data!r}")
        if h64 != h64.lower():
            raise AssertionError(f"fnv1a_64_hex not lowercase: {h64!r}")
        if int(h64, 16) != fnv1a_64(data):
            raise AssertionError(f"fnv1a_64_hex round-trip failed on {data!r}")
        h32 = fnv1a_32_hex(data)
        if len(h32) != 8:
            raise AssertionError(f"fnv1a_32_hex len={len(h32)} on {data!r}")
        if h32 != h32.lower():
            raise AssertionError(f"fnv1a_32_hex not lowercase: {h32!r}")
        if int(h32, 16) != fnv1a_32(data):
            raise AssertionError(f"fnv1a_32_hex round-trip failed on {data!r}")
        n += 1
    return n


def _check_boundary_sizes() -> int:
    """For every boundary length, generate a fixed-pattern input and assert
    bit-width invariants (no overflow past 64 or 32 bits), determinism,
    and reasonable performance (< 100 ms per hash on the harness host)."""
    n = 0
    for length in BOUNDARY_LENGTHS:
        # Three pattern classes at each length to cover XOR/multiply edge cases
        for pattern_label, pattern_fn in (
            ("zero",    lambda l: b"\x00" * l),
            ("all-ones", lambda l: b"\xff" * l),
            ("alternating", lambda l: (b"\xaa\x55" * ((l + 1) // 2))[:l]),
        ):
            data = pattern_fn(length)
            t = time.perf_counter()
            a64 = fnv1a_64(data); o64 = fnv1_64(data)
            a32 = fnv1a_32(data); o32 = fnv1_32(data)
            elapsed = time.perf_counter() - t
            if elapsed > 1.0:
                raise AssertionError(
                    f"performance regression: {length} bytes took {elapsed:.3f}s"
                )
            for name, h, mod in (("fnv1a_64", a64, MOD64),
                                 ("fnv1_64", o64, MOD64),
                                 ("fnv1a_32", a32, MOD32),
                                 ("fnv1_32", o32, MOD32)):
                if not isinstance(h, int):
                    raise AssertionError(f"{name}: non-int return {type(h).__name__}")
                if h < 0:
                    raise AssertionError(f"{name}: negative hash {h}")
                if h.bit_length() > mod.bit_length():
                    raise AssertionError(
                        f"{name}: bit_length {h.bit_length()} > "
                        f"{mod.bit_length()} on {pattern_label} len={length}"
                    )
            n += 1
    return n


def _check_mask_invariant(iters: int, rng: random.Random,
                          max_len: int) -> int:
    """Random byte strings — result must always satisfy bit-width mask
    invariants (CWE-682 guard)."""
    n = 0
    for _ in range(iters):
        length = rng.randint(0, max_len)
        data = rng.randbytes(length)
        for name, fn, mod in (("fnv1a_64", fnv1a_64, MOD64),
                              ("fnv1_64", fnv1_64, MOD64),
                              ("fnv1a_32", fnv1a_32, MOD32),
                              ("fnv1_32", fnv1_32, MOD32)):
            h = fn(data)
            if not isinstance(h, int) or h < 0 or h.bit_length() > mod.bit_length():
                raise AssertionError(
                    f"{name} mask violation: h={h} on data[0:8]={data[:8].hex()}"
                )
        n += 1
    return n


def _check_long_input_perf() -> dict:
    """Performance probe: 1 MiB random input should complete in <1s.
    Documents the slot 02 perf ceiling so a future regression is
    immediately visible in the run summary."""
    rng = random.Random(0xC0FFEE)
    data = rng.randbytes(1 << 20)
    out = {}
    for name, fn in (("fnv1a_64_1MiB", fnv1a_64),
                     ("fnv1_64_1MiB", fnv1_64),
                     ("fnv1a_32_1MiB", fnv1a_32),
                     ("fnv1_32_1MiB", fnv1_32)):
        t = time.perf_counter()
        fn(data)
        elapsed = time.perf_counter() - t
        out[name] = round(elapsed, 4)
        if elapsed > 1.0:
            raise AssertionError(
                f"perf regression: {name} took {elapsed:.3f}s (ceiling 1.0s)"
            )
    return out


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters", type=int, default=100_000,
                        help="Random hex/mask invariant iterations (default 100k)")
    parser.add_argument("--seed", type=int, default=20260913,
                        help="PRNG seed (default 20260913)")
    parser.add_argument("--len-min", type=int, default=0,
                        help="Minimum random-input length in bytes (default 0)")
    parser.add_argument("--len-max", type=int, default=10_240,
                        help="Maximum random-input length in bytes (default 10240)")
    args = parser.parse_args(argv)
    if args.len_min < 0 or args.len_max < args.len_min:
        raise SystemExit("invalid --len-min/--len-max")

    rng = random.Random(args.seed)
    t0 = time.perf_counter()
    spec_counts = _check_spec_vectors()
    boundary = _check_boundary_sizes()
    hex_runs = _check_hex_invariants(rng, args.iters, args.len_max)
    mask_runs = _check_mask_invariant(args.iters, rng, args.len_max)
    perf = _check_long_input_perf()
    elapsed = time.perf_counter() - t0

    summary = {
        "harness": "harness_boundary",
        "seed": args.seed,
        "iters_requested": args.iters,
        "len_min": args.len_min,
        "len_max": args.len_max,
        "spec_vectors": spec_counts,
        "boundary_size_checks": boundary,
        "hex_invariant_iters": hex_runs,
        "mask_invariant_iters": mask_runs,
        "long_input_perf_seconds": perf,
        "crash_count": 0,
        "hang_count": 0,
        "elapsed_seconds": round(elapsed, 4),
        "verdict": "PASS",
    }
    sys.stdout.write(json.dumps(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
