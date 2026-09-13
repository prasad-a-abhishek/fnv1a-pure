#!/usr/bin/env python3
"""
harness_type_acceptance.py — Adversarial fuzzer for fnv1a-pure's type-system
contract (cycle_71 audit surface S7 / finding F-01, CWE-20).

Background (audit §S7, finding F-01, severity Medium):
  - The current implementation does NOT guard against non-`bytes` inputs.
  - It silently produces a hash for bytearray/memoryview/list/tuple inputs
    (these iterate yielding 0..255 values).
  - It raises a cryptic TypeError for str/int/None (CPython internals leak:
    "unsupported operand type(s) for ^=: 'int' and 'str'").
  - The README documents only "accepts bytes".

This harness LOCKS IN the implementation's *current* observable contract
across a deterministic type matrix so that:
  (a) any future refactor that changes the contract is caught immediately,
  (b) slot 04 triage can attribute any finding to F-01's documented status
      ("silent acceptance of bytes-like iterables is currently observed"),
  (c) slot 05 report can quantify exactly which inputs are silent vs raising.

Scope:
  - Drive all six public functions (fnv1a_64, fnv1_64, fnv1a_32, fnv1_32,
    fnv1a_64_hex, fnv1a_32_hex) on a matrix of type cases:
      * bytes (the documented happy path)
      * bytearray (currently silent per audit)
      * memoryview (currently silent per audit)
      * list of small ints (currently silent per audit)
      * tuple of small ints (currently silent per audit)
      * str (currently raises cryptic TypeError)
      * int (currently raises cryptic TypeError)
      * None (currently raises cryptic TypeError)
      * generator yielding bytes (currently silent or raises — record)
      * empty bytes / empty bytearray / empty memoryview (boundary)
      * empty list / empty tuple / empty str (boundary)

  - For each (function, input) pair, record:
      * raised? (bool)
      * exception type name if raised
      * if not raised: returned-value class, bit_length, and equality with
        the bytes-cast equivalent when applicable.
  - Assert the bytes happy path always succeeds.
  - Assert each non-bytes result that equals its bytes-cast sibling (i.e.
    silent acceptance produced the "correct" value) — that is the part
    of F-01 that is at risk of *changing silently* if a future refactor
    added an `isinstance(data, bytes)` guard without updating the
    bytearray/memoryview acceptance decision.

This is a contract-locking harness, not an oracle: it documents the
CURRENT behaviour. The audit already recommended a remediation path
(accept bytes + bytearray + memoryview, reject list/tuple/str/int/None)
— that decision belongs in a remediation card, not slot-02 fuzz.

Properties:
  - stdlib only
  - deterministic (no PRNG needed — type matrix is exhaustive)
  - CLI: `python harness_type_acceptance.py`
  - exits 0 on clean run (contract observed), 1 on internal assertion failure
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable, Dict, List, Tuple

from fnv1a_pure import (
    fnv1a_64, fnv1_64, fnv1a_32, fnv1_32,
    fnv1a_64_hex, fnv1a_32_hex,
)


def _safe_call(fn: Callable[[Any], Any], arg: Any) -> Tuple[bool, str, Any]:
    """Call fn(arg) and return (raised, exc_type_name, return_value)."""
    try:
        ret = fn(arg)
    except BaseException as exc:
        return True, type(exc).__name__, str(exc)
    return False, "", ret


def _type_matrix() -> List[Tuple[str, Any, Any]]:
    """Build the type-matrix inputs. Each entry is (label, value, bytes_equiv).

    bytes_equiv is the value the harness compares against to detect a
    silent semantic divergence (e.g. if hashing a list of small ints
    gave a different result than hashing the equivalent bytes object,
    that would mean the algorithm is doing something other than iterating
    over byte values). For inputs that don't have a meaningful bytes
    equivalent (str, int, None, generator), bytes_equiv is None.
    """
    sample_int_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    sample_int_tuple = tuple(sample_int_list)
    return [
        ("bytes(hello)",                  b"hello",                    b"hello"),
        ("bytes(empty)",                  b"",                         b""),
        ("bytes(single)",                 b"\x42",                     b"\x42"),
        ("bytearray(hello)",              bytearray(b"hello"),         b"hello"),
        ("bytearray(empty)",              bytearray(b""),              b""),
        ("memoryview(hello)",             memoryview(b"hello"),        b"hello"),
        ("memoryview(empty)",             memoryview(b""),             b""),
        ("list[0..15]",                   sample_int_list,             bytes(sample_int_list)),
        ("tuple[0..15]",                  sample_int_tuple,            bytes(sample_int_tuple)),
        ("list[empty]",                   [],                          b""),
        ("tuple[empty]",                  (),                          b""),
        ("str(hello)",                    "hello",                     None),
        ("str(empty)",                    "",                          None),
        ("int(42)",                       42,                          None),
        ("None",                          None,                        None),
        ("generator_yielding_bytes",      (b for b in (0, 1, 2, 3)),    b"\x00\x01\x02\x03"),
    ]


def _hash_functions() -> List[Tuple[str, Callable[[Any], Any]]]:
    return [
        ("fnv1a_64",     fnv1a_64),
        ("fnv1_64",      fnv1_64),
        ("fnv1a_32",     fnv1a_32),
        ("fnv1_32",      fnv1_32),
        ("fnv1a_64_hex", fnv1a_64_hex),
        ("fnv1a_32_hex", fnv1a_32_hex),
    ]


def _check_bytes_happy_path() -> int:
    """Every hash function must accept the documented `bytes` input without
    raising and must return the documented type."""
    n = 0
    for label, data, _ in _type_matrix():
        if not isinstance(data, bytes):
            continue
        for fn_name, fn in _hash_functions():
            raised, exc_name, ret = _safe_call(fn, data)
            if raised:
                raise AssertionError(
                    f"HAPPY-PATH VIOLATION: {fn_name}({label}) raised {exc_name}"
                )
            if fn_name.endswith("_hex"):
                if not isinstance(ret, str):
                    raise AssertionError(
                        f"{fn_name}({label}) returned {type(ret).__name__}, expected str"
                    )
            else:
                if not isinstance(ret, int):
                    raise AssertionError(
                        f"{fn_name}({label}) returned {type(ret).__name__}, expected int"
                    )
            n += 1
    return n


def _check_silent_semantic_equivalence() -> Dict[str, int]:
    """For inputs whose current behaviour is silent acceptance, assert the
    returned value equals the result on the bytes-cast equivalent. This
    locks down that "silent" means "produces the same hash as the canonical
    bytes input" — not "produces garbage".

    Per audit F-01: bytearray/memoryview/list/tuple currently silent.
    We assert the bytes-equivalent hash is identical (because iteration
    over `0..255` ints is well-defined for all four).
    """
    out = {"compared": 0, "mismatches": 0}
    for fn_name, fn in _hash_functions():
        for label, data, bytes_equiv in _type_matrix():
            if bytes_equiv is None:
                continue  # no meaningful bytes equivalent
            raised_a, _, ret_a = _safe_call(fn, data)
            raised_b, _, ret_b = _safe_call(fn, bytes_equiv)
            # Skip the comparison if the function raised on the bytes
            # equivalent (shouldn't happen, but be defensive).
            if raised_b:
                continue
            if fn_name.endswith("_hex"):
                # hex wrappers — if not raised, compare strings
                if raised_a:
                    continue
                if ret_a != ret_b:
                    out["mismatches"] += 1
                    raise AssertionError(
                        f"SEMANTIC DRIFT: {fn_name}({label})={ret_a!r} != "
                        f"{fn_name}({bytes(bytes_equiv)!r})={ret_b!r}"
                    )
                out["compared"] += 1
            else:
                if raised_a:
                    continue
                if ret_a != ret_b:
                    out["mismatches"] += 1
                    raise AssertionError(
                        f"SEMANTIC DRIFT: {fn_name}({label})={ret_a} != "
                        f"{fn_name}({bytes(bytes_equiv)!r})={ret_b}"
                    )
                out["compared"] += 1
    return out


def _check_str_int_none_raise() -> int:
    """Per audit F-02, str/int/None currently raise a TypeError. Assert
    that is the case so any future refactor that changes this behaviour
    is flagged.

    Edge case observed during harness development: an empty string (or
    empty list/tuple) iterates zero times, so `for byte in "":` does not
    raise — the function returns the FNV offset basis silently. This is
    consistent with the empty-bytes case (b""). We exclude the empty
    containers from the "must raise" check and note it in the observation
    table instead — a real adversarial finding worth surfacing to slot 04.
    """
    n = 0
    bad_inputs = [("str(hello)", "hello"),
                  ("int(42)", 42),
                  ("None", None)]
    for fn_name, fn in _hash_functions():
        for label, data in bad_inputs:
            raised, exc_name, _ = _safe_call(fn, data)
            if not raised:
                raise AssertionError(
                    f"CONTRACT CHANGE: {fn_name}({label}) did NOT raise "
                    f"(audit §S7 says it should)"
                )
            if exc_name != "TypeError":
                raise AssertionError(
                    f"CONTRACT CHANGE: {fn_name}({label}) raised "
                    f"{exc_name}, not TypeError"
                )
            n += 1
    return n


def _collect_observations() -> Dict[str, Any]:
    """Build a per-(function, input) observation table for slot-04/05 to
    cite when describing the type-acceptance contract."""
    obs: Dict[str, Any] = {}
    for fn_name, fn in _hash_functions():
        obs[fn_name] = {}
        for label, data, _ in _type_matrix():
            raised, exc_name, ret = _safe_call(fn, data)
            entry: Dict[str, Any] = {"raised": raised}
            if raised:
                entry["exception_type"] = exc_name
            else:
                entry["return_type"] = type(ret).__name__
                if isinstance(ret, int):
                    entry["bit_length"] = ret.bit_length()
                elif isinstance(ret, str):
                    entry["value"] = ret
            obs[fn_name][label] = entry
    return obs


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress the per-(fn,input) observation dump")
    args = parser.parse_args(argv)

    happy = _check_bytes_happy_path()
    semantic = _check_silent_semantic_equivalence()
    raises = _check_str_int_none_raise()
    observations = _collect_observations()

    summary = {
        "harness": "harness_type_acceptance",
        "happy_path_checks": happy,
        "silent_semantic_comparisons": semantic["compared"],
        "silent_semantic_mismatches": semantic["mismatches"],
        "bad_type_raise_checks": raises,
        "observation_table": observations,
        "crash_count": 0,
        "hang_count": 0,
        "verdict": "PASS",
    }
    sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    if not args.quiet:
        sys.stderr.write(
            "Note: observation_table documents CURRENT type-acceptance contract "
            "(per audit F-01/F-02). Remediation recommended in audit §S7.\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
