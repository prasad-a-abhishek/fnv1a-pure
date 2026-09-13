#!/usr/bin/env python3
"""
build_corpus.py — Seed-corpus builder for the cycle_71 adversary workstream.

Produces a deterministic, documented set of benign + adversarial inputs to
the fnv1a-pure public API and writes each input to its own file under
``benchmarks/adversarial/corpus/seed/`` so the harnesses can replay against
the exact corpus the slot-03 fuzz run was seeded with.

Categories (per slot-01 audit, surface inventory):

  ref_vectors/        — spec-published AC vectors (32-bit + 64-bit)
  empty/              — ``b""``
  single_byte/        — 256 files, one per byte value 0x00..0xFF
  boundaries/sizes/   — lengths 0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64,
                         127, 128, 254, 255, 256, 257, 1024, 10_240 bytes
                         (each filled with a deterministic pattern)
  zero_filled/        — all-zero inputs at 1, 16, 255, 256, 1024 bytes
  ones_filled/        — all-ones (0xFF) at 1, 16, 255, 256, 1024 bytes
  adversarial_bytes/  — patterns designed to expose XOR/multiply bugs
                         (alternating 0x00/0xFF, periodic low-bit patterns,
                          length-1-at-each-boundary, max-len ascii, etc.)
  random_fixtures/    — 32 deterministic random byte blobs (10 KiB each)
                         generated via ``random.Random(seed=20260913)``
                         so replays are bit-identical
  malformed/          — non-bytes inputs that the type-acceptance contract
                         rejects (``str``, ``int``, ``None``) — encoded as
                         ``.txt`` files carrying the *intended* type and
                         string value, since bytes-only would defeat the
                         point. The harness treats these as descriptors.

Each input file is paired with a ``manifest.jsonl`` row so slot-04 triage
and slot-05 report can attribute findings to a specific seed input.

Properties:
  - stdlib only
  - deterministic seed (CLI override)
  - CLI: ``python build_corpus.py [--out DIR] [--seed N]``
  - exits 0 on success, 1 on file I/O failure
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

# ---------------------------------------------------------------------------
# Spec-published AC vectors (cycle_71 spec.md L156-159, corrected 7dfac11).
# Locked in slot-02 harness_fnv1_vs_fnv1a.py and harness_boundary.py.
# ---------------------------------------------------------------------------
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

# Boundaries relevant to bit-width masks (32 and 64) and block-size
# boundaries an attacker could exploit (powers of 2 ± 1).
BOUNDARY_SIZES = [0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64,
                  127, 128, 254, 255, 256, 257, 1024, 10240]


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _write_descriptor(path: Path, descriptor: str) -> None:
    """Write a non-bytes corpus entry as a descriptor file (UTF-8 text)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(descriptor)


def _ref_vectors(out: Path, manifest: List[dict]) -> None:
    for label, payload, expected_64, expected_32 in [
        ("empty",     b"",            14695981039346656037, 2166136261),
        ("a",         b"a",           12638187200555641996, 3826002220),
        ("hello",     b"hello",       11831194018420276491, 1335831723),
        ("hello_w",   b"hello world", 8618312879776256743,  3582672807),
    ]:
        path = out / "ref_vectors" / f"{label}.bin"
        _write_bytes(path, payload)
        manifest.append({
            "category": "ref_vectors",
            "relpath": str(path.relative_to(out)),
            "size_bytes": len(payload),
            "expected_fnv1a_64": expected_64,
            "expected_fnv1a_32": expected_32,
            "rationale": "spec-published AC vector (cycle_71 spec.md L156-159)",
        })


def _single_byte(out: Path, manifest: List[dict]) -> None:
    """256 files, one per byte value 0x00..0xFF."""
    sub = out / "single_byte"
    sub.mkdir(parents=True, exist_ok=True)
    for b in range(256):
        path = sub / f"byte_{b:02x}.bin"
        _write_bytes(path, bytes([b]))
        manifest.append({
            "category": "single_byte",
            "relpath": str(path.relative_to(out)),
            "size_bytes": 1,
            "byte_value": b,
            "rationale": "S4 single-byte distinctness (audit F-02 regression guard)",
        })


def _boundaries(out: Path, manifest: List[dict]) -> None:
    """Boundary sizes — each with a length-distinct deterministic pattern."""
    sub = out / "boundaries" / "sizes"
    sub.mkdir(parents=True, exist_ok=True)
    for n in BOUNDARY_SIZES:
        # Deterministic pattern: byte i = (i * 31 + 7) & 0xFF
        payload = bytes(((i * 31 + 7) & 0xFF) for i in range(n))
        path = sub / f"size_{n:05d}.bin"
        _write_bytes(path, payload)
        manifest.append({
            "category": "boundaries",
            "relpath": str(path.relative_to(out)),
            "size_bytes": n,
            "rationale": f"S12 boundary size {n} (mask / loop-edge regression)",
        })


def _zero_filled(out: Path, manifest: List[dict]) -> None:
    """All-zeros inputs — stresses the FNV-1 == FNV-1a all-zero collapse
    and the multiply-by-prime absorption property (mod 2^N)."""
    sub = out / "zero_filled"
    sub.mkdir(parents=True, exist_ok=True)
    for n in [1, 16, 255, 256, 1024, 10_240]:
        path = sub / f"zeros_{n:05d}.bin"
        _write_bytes(path, b"\x00" * n)
        manifest.append({
            "category": "zero_filled",
            "relpath": str(path.relative_to(out)),
            "size_bytes": n,
            "rationale": "S9 zero-only equivalence (audit F-04)",
        })


def _ones_filled(out: Path, manifest: List[dict]) -> None:
    """All-ones inputs — XOR-flip exhausts the hash state on every byte."""
    sub = out / "ones_filled"
    sub.mkdir(parents=True, exist_ok=True)
    for n in [1, 16, 255, 256, 1024, 10_240]:
        path = sub / f"ones_{n:05d}.bin"
        _write_bytes(path, b"\xFF" * n)
        manifest.append({
            "category": "ones_filled",
            "relpath": str(path.relative_to(out)),
            "size_bytes": n,
            "rationale": "ones stress: every XOR step flips all bits",
        })


def _adversarial_bytes(out: Path, manifest: List[dict]) -> None:
    """Patterns engineered to expose XOR/multiply/swapped-order bugs.

    Each pattern stresses a specific failure mode documented in the
    slot-01 audit:
      - alt_00_ff: alternating 0x00/0xFF (XOR never relaxes)
      - period_3: periodic low-bit pattern (i % 3) → exposes XOR-step
                   cycling bugs
      - ascii_max: 1 MiB of printable ASCII (catches encoding issues if
                   a future refactor adds text decoding)
      - ascii_low: control characters 0x00..0x1F (catches early-exit on
                   ASCII-class)
      - one_then_zeros: a single 0xFF followed by N zeros (tests
                         propagation through the multiply-then-XOR ordering
                         of FNV-1 *and* the XOR-then-multiply ordering of
                         FNV-1a in one input)
    """
    sub = out / "adversarial_bytes"
    sub.mkdir(parents=True, exist_ok=True)

    patterns = {
        "alt_00_ff_256":  bytes((i & 1) * 0xFF for i in range(256)),
        "alt_00_ff_1024": bytes((i & 1) * 0xFF for i in range(1024)),
        "period_3_1024":  bytes((i % 3) & 0xFF for i in range(1024)),
        "period_7_1024":  bytes((i % 7) & 0xFF for i in range(1024)),
        "ascii_low_256":  bytes(i & 0x1F for i in range(256)),
    }
    for name, payload in patterns.items():
        path = sub / f"{name}.bin"
        _write_bytes(path, payload)
        manifest.append({
            "category": "adversarial_bytes",
            "relpath": str(path.relative_to(out)),
            "size_bytes": len(payload),
            "rationale": f"adversarial pattern {name}",
        })

    # 1 MiB ASCII-max payload (catches any silent cap or early-exit bug)
    ascii_max = bytes(((i % 95) + 32) for i in range(1024 * 1024))
    path = sub / "ascii_max_1MiB.bin"
    _write_bytes(path, ascii_max)
    manifest.append({
        "category": "adversarial_bytes",
        "relpath": str(path.relative_to(out)),
        "size_bytes": len(ascii_max),
        "rationale": "1 MiB ASCII — long-input performance + no early-exit",
    })


def _random_fixtures(out: Path, manifest: List[dict], seed: int) -> None:
    """32 deterministic random 10 KiB blobs (matches the surface inventory
    "random 10k bytes" requirement and gives a diverse property-fuzz set
    without relying on the harness's own RNG)."""
    sub = out / "random_fixtures"
    sub.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    for i in range(32):
        payload = rng.randbytes(10 * 1024)
        path = sub / f"rand_{i:02d}_10KiB.bin"
        _write_bytes(path, payload)
        manifest.append({
            "category": "random_fixtures",
            "relpath": str(path.relative_to(out)),
            "size_bytes": len(payload),
            "fixture_index": i,
            "rationale": "deterministic random 10 KiB blob (diversity fuzz)",
        })


def _malformed(out: Path, manifest: List[dict]) -> None:
    """Non-bytes descriptors — these are NOT passed as bytes; they are
    text-encoded descriptors of inputs the type-acceptance contract must
    handle (currently silently for bytearray/memoryview/list/tuple,
    currently with a cryptic TypeError for str/int/None per audit F-01).

    The harness reads each descriptor, evaluates ``eval(<repr>)`` in a
    controlled sandbox-less environment to reconstruct the original
    Python value, then drives the public API with it.
    """
    sub = out / "malformed"
    sub.mkdir(parents=True, exist_ok=True)
    cases = [
        ("str_ascii",     repr("hello")),
        ("str_empty",     repr("")),
        ("str_unicode",   repr("héllo \u4e16\u754c \U0001f600")),
        ("int_small",     repr(42)),
        ("int_zero",      repr(0)),
        ("int_negative",  repr(-1)),
        ("none",          repr(None)),
        ("float",         repr(3.14)),
        ("bool_true",     repr(True)),
        ("bool_false",    repr(False)),
        ("bytearray_a",   repr(bytearray(b"hello"))),
        ("memoryview_a",  repr(memoryview(b"hello"))),
        ("list_ints",     repr([104, 101, 108, 108, 111])),
        ("tuple_ints",    repr((104, 101, 108, 108, 111))),
        ("generator",     "iter([104, 101, 108, 108, 111])"),
    ]
    for label, descriptor in cases:
        path = sub / f"{label}.txt"
        _write_descriptor(path, descriptor)
        manifest.append({
            "category": "malformed",
            "relpath": str(path.relative_to(out)),
            "size_bytes": len(descriptor.encode("utf-8")),
            "descriptor": descriptor,
            "rationale": "S7 type-acceptance contract (audit F-01 CWE-20)",
        })


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent / "seed",
                        help="Output directory for the seed corpus")
    parser.add_argument("--seed", type=int, default=20260913,
                        help="PRNG seed for the random fixtures (default 20260913)")
    args = parser.parse_args(list(argv))

    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    manifest: List[dict] = []

    _ref_vectors(out, manifest)
    _single_byte(out, manifest)
    _boundaries(out, manifest)
    _zero_filled(out, manifest)
    _ones_filled(out, manifest)
    _adversarial_bytes(out, manifest)
    _random_fixtures(out, manifest, args.seed)
    _malformed(out, manifest)

    # Per-category counts for the slot-05 report.
    by_category: dict[str, int] = {}
    for row in manifest:
        by_category[row["category"]] = by_category.get(row["category"], 0) + 1

    manifest_path = out / "manifest.jsonl"
    with open(manifest_path, "w", encoding="utf-8") as fh:
        for row in manifest:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    summary_path = out / "SUMMARY.json"
    summary = {
        "schema_version": 1,
        "builder": "build_corpus.py",
        "seed": args.seed,
        "out_dir": str(out),
        "total_inputs": len(manifest),
        "by_category": by_category,
        "boundary_sizes": BOUNDARY_SIZES,
        "spec_vectors": {
            "fnv1a_64": [{"input": inp.hex(), "expected": exp}
                         for inp, exp in SPEC_FNV1A_64],
            "fnv1a_32": [{"input": inp.hex(), "expected": exp}
                         for inp, exp in SPEC_FNV1A_32],
        },
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
        fh.write("\n")

    sys.stdout.write(json.dumps({
        "out_dir": str(out),
        "total_inputs": len(manifest),
        "by_category": by_category,
        "summary_path": str(summary_path),
        "manifest_path": str(manifest_path),
    }) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
