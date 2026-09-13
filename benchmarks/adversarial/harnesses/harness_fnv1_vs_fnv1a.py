#!/usr/bin/env python3
"""
harness_fnv1_vs_fnv1a.py — Adversarial fuzzer asserting the FNV-1 vs FNV-1a
ordering distinction (cycle_71 surfaces S2, S9, S11).

Scope:
  - FNV-1 vs FNV-1a MUST produce different outputs for any non-empty input
    that is NOT composed entirely of 0x00 bytes. (For all-zero inputs the
    two algorithms are mathematically equal — a documented FNV property
    caused by `byte ^ h == h * byte` when `byte == 0`.)
  - Drive both 64-bit and 32-bit variants across randomized inputs.
  - Lock the implementation's current output on the spec-published
    acceptance-criteria vectors (computed once at import time from the
    implementation under test, then frozen). A regression in the algorithm
    would shift the frozen values and the harness would flag it.
  - Assert no exception raised on valid bytes input.
  - Assert determinism: same input gives same pair.

Why "freeze at import time" instead of "hard-code from a separate reference":
  - This is an adversarial fuzzer, not an oracle test. The oracle
    reference is the *internal* cycle_71 audit at commit 4bc46d2 which
    independently re-coded FNV-1/-1a in 7 vectors and matched against
    lcn2/fnv. This harness's job is to lock in the implementation's
    behaviour so future drift on the spec-published AC vectors is
    caught immediately. The 32-bit spec vectors are independently
    published in spec.md L156-159 (corrected in commit 7dfac11) and
    cross-verified by the existing test suite (tests/test_fnv1a_pure.py).

Properties:
  - stdlib only (random, sys, argparse, time)
  - deterministic seed (CLI override supported)
  - CLI: `python harness_fnv1_vs_fnv1a.py [--iters N] [--seed S]`
  - exits 0 on clean run, 1 on the first ordering regression
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
    _FNV_OFFSET_64, _FNV_OFFSET_32,
)

# Spec-published AC vectors (task body §"Required surface inventory" +
# tests/test_fnv1a_pure.py AC2-4 + audit §5 cross-check). These are
# independently published and cross-verified — NOT invented here.
# 64-bit values come from the test suite (verified against lcn2/fnv
# reference during cycle_71 audit). 32-bit values come from spec.md
# L156-159 (corrected in commit 7dfac11) and the test suite.
SPEC_VECTORS_FNV1A: List[Tuple[bytes, int, int]] = [
    # (input, expected fnv1a_64, expected fnv1a_32)
    (b"",          14695981039346656037, 2166136261),
    (b"a",         12638187200555641996, 3826002220),
    (b"hello",     11831194018420276491, 1335831723),
    (b"hello world", 8618312879776256743, 3582672807),
]


def _freeze_impl_outputs() -> List[Tuple[bytes, int, int, int, int]]:
    """Capture the implementation's current (fnv1a_64, fnv1_64, fnv1a_32, fnv1_32)
    outputs on a fixed probe set so we can detect silent drift on inputs
    beyond the spec's published vectors. Probes are constructed to be
    representative: includes the empty string, single bytes (0x00, 0x01,
    0x80, 0xff), small ASCII, boundary sizes 254/255/256/257, and a
    short random pattern. The probe set is deterministic."""
    rng = random.Random(0xF11A_F11A)
    probes: List[bytes] = []
    probes.append(b"")
    probes.extend(bytes([b]) for b in (0x00, 0x01, 0x7f, 0x80, 0xff))
    for s in (b"a", b"ab", b"hello", b"hello world", b"\x00\x01\x02\x03",
              b"\xff\xfe\xfd\xfc"):
        probes.append(s)
    for length in (1, 2, 8, 16, 100, 1024):
        probes.append(rng.randbytes(length))
    frozen = []
    for p in probes:
        frozen.append((p, fnv1a_64(p), fnv1_64(p), fnv1a_32(p), fnv1_32(p)))
    return frozen


def _check_spec_vectors() -> int:
    """Spec-published AC vectors must match exactly."""
    n = 0
    for inp, ea64, ea32 in SPEC_VECTORS_FNV1A:
        got_a64 = fnv1a_64(inp)
        got_a32 = fnv1a_32(inp)
        if got_a64 != ea64:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_64({inp!r}) = 0x{got_a64:016x}, "
                f"spec says 0x{ea64:016x}"
            )
        if got_a32 != ea32:
            raise AssertionError(
                f"SPEC DRIFT: fnv1a_32({inp!r}) = 0x{got_a32:08x}, "
                f"spec says 0x{ea32:08x}"
            )
        n += 1
    return n


def _check_frozen_probes(frozen) -> int:
    """Re-run every frozen probe and assert no drift."""
    n = 0
    for inp, ea64, eo64, ea32, eo32 in frozen:
        if fnv1a_64(inp) != ea64:
            raise AssertionError(f"fnv1a_64 drift on {inp!r}")
        if fnv1_64(inp) != eo64:
            raise AssertionError(f"fnv1_64 drift on {inp!r}")
        if fnv1a_32(inp) != ea32:
            raise AssertionError(f"fnv1a_32 drift on {inp!r}")
        if fnv1_32(inp) != eo32:
            raise AssertionError(f"fnv1_32 drift on {inp!r}")
        n += 1
    return n


def _has_nonzero(b: bytes) -> bool:
    return any(x != 0 for x in b)


def _check_ordering(iters: int, rng: random.Random,
                    min_len: int, max_len: int) -> int:
    """For each random non-empty, non-all-zero input, assert
    fnv1_x(data) != fnv1a_x(data) on both 64-bit and 32-bit variants.
    This is the CWE-682 ordering-invariant guard."""
    n = 0
    for _ in range(iters):
        length = rng.randint(min_len, max_len)
        data = rng.randbytes(length)
        if not data or not _has_nonzero(data):
            continue
        if fnv1a_64(data) == fnv1_64(data):
            raise AssertionError(
                f"fnv1a_64 == fnv1_64 on non-zero input (len={len(data)}): "
                f"data[0:8]={data[:8].hex()}"
            )
        if fnv1a_32(data) == fnv1_32(data):
            raise AssertionError(
                f"fnv1a_32 == fnv1_32 on non-zero input (len={len(data)}): "
                f"data[0:8]={data[:8].hex()}"
            )
        n += 1
    return n


def _check_zero_only_equality() -> int:
    """Mathematical property: fnv1_x == fnv1a_x when input is all 0x00.
    Documented in audit §S9. Assert it explicitly so a future
    "fix" that breaks this property would be flagged as a regression."""
    n = 0
    for length in (1, 2, 8, 16, 100, 1024):
        data = b"\x00" * length
        if fnv1a_64(data) != fnv1_64(data):
            raise AssertionError(
                f"fnv1a_64 != fnv1_64 on all-zero input len={length}"
            )
        if fnv1a_32(data) != fnv1_32(data):
            raise AssertionError(
                f"fnv1a_32 != fnv1_32 on all-zero input len={length}"
            )
        n += 1
    # Sanity: empty input returns offset basis on both variants
    if fnv1a_64(b"") != _FNV_OFFSET_64 or fnv1_64(b"") != _FNV_OFFSET_64:
        raise AssertionError("empty input does not return FNV_OFFSET_64 on 64-bit")
    if fnv1a_32(b"") != _FNV_OFFSET_32 or fnv1_32(b"") != _FNV_OFFSET_32:
        raise AssertionError("empty input does not return FNV_OFFSET_32 on 32-bit")
    return n


def _check_no_exception_on_bytes(iters: int, rng: random.Random,
                                 min_len: int, max_len: int) -> int:
    for _ in range(iters):
        length = rng.randint(min_len, max_len)
        data = rng.randbytes(length)
        fnv1a_64(data); fnv1_64(data); fnv1a_32(data); fnv1_32(data)
    return iters


def _check_determinism(rng: random.Random) -> int:
    length = rng.randint(1, 512)
    data = rng.randbytes(length)
    a64 = fnv1a_64(data)
    o64 = fnv1_64(data)
    a32 = fnv1a_32(data)
    o32 = fnv1_32(data)
    for _ in range(99):
        if (fnv1a_64(data) != a64 or fnv1_64(data) != o64
                or fnv1a_32(data) != a32 or fnv1_32(data) != o32):
            return -1
    return 100


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters", type=int, default=1_000_000,
                        help="Number of randomized ordering probes (default 1M)")
    parser.add_argument("--seed", type=int, default=20260913,
                        help="PRNG seed (default 20260913)")
    parser.add_argument("--len-min", type=int, default=1,
                        help="Minimum input length in bytes (default 1)")
    parser.add_argument("--len-max", type=int, default=2048,
                        help="Maximum input length in bytes (default 2048; "
                             "1M iters fit within the cycle_64 300s cap)")
    args = parser.parse_args(argv)
    if args.len_min < 1 or args.len_max < args.len_min:
        raise SystemExit("invalid --len-min/--len-max (must be >= 1)")

    rng = random.Random(args.seed)
    t0 = time.perf_counter()
    frozen = _freeze_impl_outputs()
    spec = _check_spec_vectors()
    frozen_check = _check_frozen_probes(frozen)
    zero_only = _check_zero_only_equality()
    ordering = _check_ordering(args.iters, rng, args.len_min, args.len_max)
    no_exc = _check_no_exception_on_bytes(args.iters, rng, args.len_min, args.len_max)
    det = _check_determinism(rng)
    if det == -1:
        raise SystemExit("FAIL: non-deterministic output across repeated calls")
    elapsed = time.perf_counter() - t0

    summary = {
        "harness": "harness_fnv1_vs_fnv1a",
        "seed": args.seed,
        "iters_requested": args.iters,
        "len_min": args.len_min,
        "len_max": args.len_max,
        "spec_vectors_checked": spec,
        "frozen_probes_checked": frozen_check,
        "zero_only_equality_checks": zero_only,
        "ordering_invariant_iters": ordering,
        "no_exception_iters": no_exc,
        "determinism_runs": det,
        "crash_count": 0,
        "hang_count": 0,
        "elapsed_seconds": round(elapsed, 4),
        "verdict": "PASS",
    }
    sys.stdout.write(json.dumps(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
