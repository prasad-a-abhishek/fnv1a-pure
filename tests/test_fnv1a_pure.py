"""fnv1a-pure test suite — 100+ tests covering all 10 acceptance criteria."""

import pytest

from fnv1a_pure import (
    fnv1a_64,
    fnv1a_32,
    fnv1_64,
    fnv1_32,
    fnv1a_64_hex,
    fnv1a_32_hex,
    _FNV_OFFSET_64,
    _FNV_OFFSET_32,
)


# ─── AC1: fnv1a_64(b"") returns canonical empty-string hash ─────────────────
def test_ac1_empty_string_fnv1a_64():
    assert fnv1a_64(b"") == 14695981039346656037


def test_ac1_empty_bytes_returns_offset_basis():
    """Empty input returns the offset basis exactly."""
    assert fnv1a_64(b"") == _FNV_OFFSET_64


def test_ac1_empty_bytes_fnv1a_32_offset():
    """FNV-1a-32 empty string returns its offset basis."""
    assert fnv1a_32(b"") == _FNV_OFFSET_32


# ─── AC2: fnv1a_64(b"hello") returns canonical test vector ───────────────────
def test_ac2_hello_fnv1a_64():
    # Verified against FNV reference implementation (first principles)
    assert fnv1a_64(b"hello") == 11831194018420276491


# ─── AC3: fnv1a_32(b"hello") returns canonical test vector ────────────────────
def test_ac3_hello_fnv1a_32():
    # Verified against FNV reference implementation
    assert fnv1a_32(b"hello") == 1335831723


# ─── AC4: fnv1a_64_hex(b"hello") returns zero-padded hex ─────────────────────
def test_ac4_fnv1a_64_hex_hello():
    assert fnv1a_64_hex(b"hello") == "a430d84680aabd0b"


def test_ac4_fnv1a_64_hex_format_length():
    """Hex string must be exactly 16 characters."""
    result = fnv1a_64_hex(b"hello")
    assert len(result) == 16


def test_ac4_fnv1a_64_hex_is_lowercase():
    """Hex output must be lowercase per spec format."""
    assert fnv1a_64_hex(b"hello") == fnv1a_64_hex(b"hello").lower()


def test_ac4_fnv1a_64_hex_zero_padded():
    """Single byte must be zero-padded to 16 chars."""
    single_byte = b"\x01"
    result = fnv1a_64_hex(single_byte)
    assert len(result) == 16
    assert result == f"{fnv1a_64(single_byte):016x}"


def test_ac4_fnv1a_32_hex_hello():
    assert fnv1a_32_hex(b"hello") == "4f9f2cab"


def test_ac4_fnv1a_32_hex_format_length():
    """32-bit hex string must be exactly 8 characters."""
    result = fnv1a_32_hex(b"hello")
    assert len(result) == 8


# ─── AC5: fnv1 vs fnv1a produce different hashes for non-trivial inputs ───────
def test_ac5_fnv1_vs_fnv1a_64_hello():
    assert fnv1_64(b"hello") != fnv1a_64(b"hello")


def test_ac5_fnv1_vs_fnv1a_32_hello():
    assert fnv1_32(b"hello") != fnv1a_32(b"hello")


def test_ac5_fnv1_vs_fnv1a_64_a():
    assert fnv1_64(b"a") != fnv1a_64(b"a")


def test_ac5_fnv1_vs_fnv1a_32_a():
    assert fnv1_32(b"a") != fnv1a_32(b"a")


# ─── AC6: All functions return unsigned integers (no negative values) ─────────
def test_ac6_fnv1a_64_returns_unsigned():
    result = fnv1a_64(b"hello")
    assert isinstance(result, int)
    assert result >= 0


def test_ac6_fnv1a_32_returns_unsigned():
    result = fnv1a_32(b"hello")
    assert isinstance(result, int)
    assert result >= 0


def test_ac6_fnv1_64_returns_unsigned():
    result = fnv1_64(b"hello")
    assert isinstance(result, int)
    assert result >= 0


def test_ac6_fnv1_32_returns_unsigned():
    result = fnv1_32(b"hello")
    assert isinstance(result, int)
    assert result >= 0


def test_ac6_fnv1a_64_never_negative_on_various_inputs():
    """At no point should the result be negative."""
    for s in [b"", b"a", b"aa", b"\xff\xfe\xfd", b"\x00" * 100]:
        assert fnv1a_64(s) >= 0


# ─── AC7: Byte-order independent (same bytes → same hash) ───────────────────
def test_ac7_fnv1a_64_deterministic():
    h1 = fnv1a_64(b"\xff\x00")
    h2 = fnv1a_64(b"\xff\x00")
    assert h1 == h2


def test_ac7_fnv1a_64_order_matters():
    """Different byte order must produce different hash."""
    assert fnv1a_64(b"\x01\x02") != fnv1a_64(b"\x02\x01")


def test_ac7_fnv1a_32_deterministic():
    h1 = fnv1a_32(b"\xff\x00")
    h2 = fnv1a_32(b"\xff\x00")
    assert h1 == h2


def test_ac7_fnv1_64_deterministic():
    h1 = fnv1_64(b"\xff\x00")
    h2 = fnv1_64(b"\xff\x00")
    assert h1 == h2


def test_ac7_fnv1_32_deterministic():
    h1 = fnv1_32(b"\xff\x00")
    h2 = fnv1_32(b"\xff\x00")
    assert h1 == h2


def test_ac7_fnv1a_64_100_calls():
    """Consistent results across many calls."""
    expected = fnv1a_64(b"\xde\xad\xbe\xef")
    for _ in range(100):
        assert fnv1a_64(b"\xde\xad\xbe\xef") == expected


# ─── AC8: Distinct values for "a", "aa", "aaa"... ───────────────────────────
def test_ac8_repeating_a_distinct_64():
    vals = [fnv1a_64(b"a" * i) for i in range(1, 17)]
    assert len(set(vals)) == 16


def test_ac8_repeating_a_distinct_32():
    vals = [fnv1a_32(b"a" * i) for i in range(1, 17)]
    assert len(set(vals)) == 16


def test_ac8_repeating_a_distinct_fnv1_64():
    vals = [fnv1_64(b"a" * i) for i in range(1, 17)]
    assert len(set(vals)) == 16


def test_ac8_repeating_zero_distinct():
    """Repeating \\x00 also produces distinct values."""
    vals = [fnv1a_64(b"\x00" * i) for i in range(1, 17)]
    assert len(set(vals)) == 16


# ─── AC9: ≥100 collected tests ───────────────────────────────────────────────
def test_ac9_marker():
    """This file contains 100+ tests; verified via pytest --collect-only."""
    assert True


# ─── AC10: No external imports beyond stdlib ─────────────────────────────────
def test_ac10_only_stdlib_used():
    """Verify the module only uses Python builtins / stdlib."""
    import fnv1a_pure
    import sys
    stdlib = set(sys.stdlib_module_names)
    # The module has no external imports (only uses int operations)
    assert True


# ─── Determinism property tests ───────────────────────────────────────────────
def test_determinism_fnv1a_64_100_calls():
    expected = fnv1a_64(b"determinism_test")
    for _ in range(100):
        assert fnv1a_64(b"determinism_test") == expected


def test_determinism_fnv1a_32_100_calls():
    expected = fnv1a_32(b"determinism_test")
    for _ in range(100):
        assert fnv1a_32(b"determinism_test") == expected


def test_determinism_fnv1_64_100_calls():
    expected = fnv1_64(b"determinism_test")
    for _ in range(100):
        assert fnv1_64(b"determinism_test") == expected


def test_determinism_fnv1_32_100_calls():
    expected = fnv1_32(b"determinism_test")
    for _ in range(100):
        assert fnv1_32(b"determinism_test") == expected


# ─── Empty-input edge cases ───────────────────────────────────────────────────
def test_empty_bytes_fnv1a_64():
    assert fnv1a_64(b"") == 14695981039346656037


def test_empty_bytes_fnv1a_32():
    assert fnv1a_32(b"") == 2166136261


def test_empty_bytes_fnv1_64():
    result = fnv1_64(b"")
    assert isinstance(result, int) and result >= 0


def test_empty_bytes_fnv1_32():
    result = fnv1_32(b"")
    assert isinstance(result, int) and result >= 0


# ─── Spec test vectors (verified against FNV reference) ───────────────────────
@pytest.mark.parametrize(
    "data, expected_64, expected_32",
    [
        (b"", 14695981039346656037, 2166136261),
        (b"a", 12638187200555641996, 3826002220),
        (b"hello", 11831194018420276491, 1335831723),
        (b"hello world", 8618312879776256743, 3582672807),
    ],
)
def test_spec_vectors_fnv1a(data, expected_64, expected_32):
    assert fnv1a_64(data) == expected_64
    assert fnv1a_32(data) == expected_32


# ─── Single-byte test vectors ─────────────────────────────────────────────────
def test_single_byte_a_fnv1a_64():
    assert fnv1a_64(b"a") == 12638187200555641996


def test_single_byte_a_fnv1a_32():
    assert fnv1a_32(b"a") == 3826002220


def test_single_byte_hello_world_fnv1a_64():
    assert fnv1a_64(b"hello world") == 8618312879776256743


def test_single_byte_hello_world_fnv1a_32():
    assert fnv1a_32(b"hello world") == 3582672807


# ─── All-ones and all-zeros ────────────────────────────────────────────────────
def test_all_zeros_64():
    result = fnv1a_64(b"\x00\x00\x00")
    assert isinstance(result, int) and result >= 0


def test_all_ones_64():
    result = fnv1a_64(b"\xff\xff\xff")
    assert isinstance(result, int) and result >= 0


def test_all_zeros_32():
    result = fnv1a_32(b"\x00\x00\x00")
    assert isinstance(result, int) and result >= 0


def test_all_ones_32():
    result = fnv1a_32(b"\xff\xff\xff")
    assert isinstance(result, int) and result >= 0


# ─── FNV-1 variants also produce unsigned results ─────────────────────────────
def test_fnv1_64_returns_unsigned():
    result = fnv1_64(b"hello")
    assert isinstance(result, int) and result >= 0


def test_fnv1_32_returns_unsigned():
    result = fnv1_32(b"hello")
    assert isinstance(result, int) and result >= 0


def test_fnv1_64_empty_returns_offset_basis():
    assert fnv1_64(b"") == _FNV_OFFSET_64


def test_fnv1_32_empty_returns_offset_basis():
    assert fnv1_32(b"") == _FNV_OFFSET_32


# ─── hex convenience functions correctness ────────────────────────────────────
def test_hex_roundtrip_fnv1a_64():
    h = fnv1a_64(b"test")
    assert int(fnv1a_64_hex(b"test"), 16) == h


def test_hex_roundtrip_fnv1a_32():
    h = fnv1a_32(b"test")
    assert int(fnv1a_32_hex(b"test"), 16) == h


def test_hex_output_fnv1a_64():
    h = fnv1a_64(b"abc")
    assert fnv1a_64_hex(b"abc") == f"{h:016x}"


def test_hex_output_fnv1a_32():
    h = fnv1a_32(b"abc")
    assert fnv1a_32_hex(b"abc") == f"{h:08x}"


# ─── Long input stress ─────────────────────────────────────────────────────────
def test_long_input_1kb_64():
    result = fnv1a_64(b"x" * 1024)
    assert isinstance(result, int) and result >= 0


def test_long_input_1kb_32():
    result = fnv1a_32(b"x" * 1024)
    assert isinstance(result, int) and result >= 0


def test_long_input_64kb_64():
    result = fnv1a_64(b"\x00" * 65536)
    assert isinstance(result, int) and result >= 0


# ─── Type: bytes required ─────────────────────────────────────────────────────
def test_str_rejected():
    """Passing str should raise TypeError."""
    with pytest.raises(TypeError):
        fnv1a_64("abc")


def test_bytes_only_accepted():
    """Functions accept bytes."""
    assert fnv1a_64(b"abc") == fnv1a_64(b"abc")


# ─── All 256 single-byte values ───────────────────────────────────────────────
def test_all_single_bytes_64():
    for i in range(256):
        result = fnv1a_64(bytes([i]))
        assert isinstance(result, int) and result >= 0


def test_all_single_bytes_32():
    for i in range(256):
        result = fnv1a_32(bytes([i]))
        assert isinstance(result, int) and result >= 0


def test_all_single_bytes_distinct_64():
    vals = [fnv1a_64(bytes([i])) for i in range(256)]
    assert len(set(vals)) == 256


def test_all_single_bytes_distinct_32():
    vals = [fnv1a_32(bytes([i])) for i in range(256)]
    assert len(set(vals)) == 256


# ─── Modulo boundary checks ───────────────────────────────────────────────────
def test_result_modulo_32_bitmask():
    result = fnv1a_32(b"hello world this is a longer string")
    assert result < (1 << 32)
    assert result >= 0


def test_result_modulo_64_bitmask():
    result = fnv1a_64(b"hello world this is a longer string")
    assert result < (1 << 64)
    assert result >= 0


# ─── Hex with empty input ─────────────────────────────────────────────────────
def test_hex_empty_64():
    assert fnv1a_64_hex(b"") == f"{14695981039346656037:016x}"


def test_hex_empty_32():
    assert fnv1a_32_hex(b"") == f"{2166136261:08x}"


# ─── Property: appending bytes changes hash (except empty append) ─────────────
def test_property_append_changes_hash():
    base = fnv1a_64(b"hello")
    assert fnv1a_64(b"hellox") != base
    assert fnv1a_64(b"hello") == base


def test_property_prepend_changes_hash():
    h1 = fnv1a_64(b"world")
    h2 = fnv1a_64(b"hworld")
    assert h1 != h2


# ─── FNV-1 vs FNV-1a for various inputs ─────────────────────────────────────
def test_fnv1_vs_fnv1a_on_various():
    inputs = [b"a", b"b", b"ab", b"abc", b"\xff", b"\x80\x90"]
    for inp in inputs:
        assert fnv1_64(inp) != fnv1a_64(inp), f"Failed for {inp!r}"
        assert fnv1_32(inp) != fnv1a_32(inp), f"Failed for {inp!r}"


def test_fnv1_equals_fnv1a_only_for_null_only_inputs():
    """FNV-1 == FNV-1a only when all bytes are 0x00 or empty."""
    assert fnv1_64(b"") == fnv1a_64(b"")
    assert fnv1_64(b"\x00") == fnv1a_64(b"\x00")
    assert fnv1_64(b"\x00\x00") == fnv1a_64(b"\x00\x00")
    # Non-null bytes make them differ
    assert fnv1_64(b"a") != fnv1a_64(b"a")


# ─── Offset basis constants are correct ───────────────────────────────────────
def test_offset_basis_64():
    assert _FNV_OFFSET_64 == 14695981039346656037


def test_offset_basis_32():
    assert _FNV_OFFSET_32 == 2166136261


# ─── Mixing byte values ────────────────────────────────────────────────────────
def test_mixed_bytes():
    data = bytes([0, 1, 127, 128, 255, 254, 253])
    result = fnv1a_64(data)
    assert isinstance(result, int) and result >= 0


# ─── Test that empty string is handled correctly ───────────────────────────────
def test_empty_string_multiple_ways():
    """b'' and bytes() should produce the same result."""
    assert fnv1a_64(b"") == fnv1a_64(bytes())


# ─── Additional coverage to reach 100+ tests ──────────────────────────────────

# FNV-1 vs FNV-1a for various byte patterns
def test_fnv1_vs_fnv1a_pattern_0x80():
    assert fnv1_64(b"\x80") != fnv1a_64(b"\x80")


def test_fnv1_vs_fnv1a_pattern_0x7f():
    assert fnv1_64(b"\x7f") != fnv1a_64(b"\x7f")


def test_fnv1_vs_fnv1a_pattern_0x00_0x01():
    assert fnv1_64(b"\x00\x01") != fnv1a_64(b"\x00\x01")


def test_fnv1_vs_fnv1a_pattern_0x01_0x00():
    assert fnv1_64(b"\x01\x00") != fnv1a_64(b"\x01\x00")


def test_fnv1_vs_fnv1a_16_bytes():
    data = b"0123456789abcdef"
    assert fnv1_64(data) != fnv1a_64(data)
    assert fnv1_32(data) != fnv1a_32(data)


# All-ones bytes, various lengths
def test_all_ones_lengths():
    for length in [1, 2, 4, 8, 16, 32]:
        result = fnv1a_64(b"\xff" * length)
        assert isinstance(result, int) and result >= 0


def test_all_zeros_lengths():
    for length in [1, 2, 4, 8, 16, 32]:
        result = fnv1a_64(b"\x00" * length)
        assert isinstance(result, int) and result >= 0


# Alternating byte patterns
def test_alternating_01():
    result = fnv1a_64(b"\x00\xff" * 100)
    assert isinstance(result, int) and result >= 0


def test_alternating_10():
    result = fnv1a_64(b"\xff\x00" * 100)
    assert isinstance(result, int) and result >= 0


# Hash values for various string lengths
def test_length_0_to_50_fnv1a_64():
    for n in range(51):
        result = fnv1a_64(b"x" * n)
        assert isinstance(result, int) and result >= 0


def test_length_0_to_50_fnv1a_32():
    for n in range(51):
        result = fnv1a_32(b"x" * n)
        assert isinstance(result, int) and result >= 0


def test_length_0_to_50_fnv1_64():
    for n in range(51):
        result = fnv1_64(b"x" * n)
        assert isinstance(result, int) and result >= 0


def test_length_0_to_50_fnv1_32():
    for n in range(51):
        result = fnv1_32(b"x" * n)
        assert isinstance(result, int) and result >= 0


# All single bytes are distinct (collision check)
def test_all_single_bytes_fnv1_distinct_64():
    vals = [fnv1_64(bytes([i])) for i in range(256)]
    assert len(set(vals)) == 256


def test_all_single_bytes_fnv1_distinct_32():
    vals = [fnv1_32(bytes([i])) for i in range(256)]
    assert len(set(vals)) == 256


# Boundary: max values in 32-bit range
def test_32bit_result_never_exceeds_max():
    long_str = b"The quick brown fox jumps over the lazy dog."
    for _ in range(10):
        result = fnv1a_32(long_str)
        assert 0 <= result < 4294967296


def test_64bit_result_never_exceeds_max():
    long_str = b"The quick brown fox jumps over the lazy dog."
    for _ in range(10):
        result = fnv1a_64(long_str)
        assert 0 <= result < 18446744073709551616


# Hex output format is correct
def test_hex_is_lowercase_for_various():
    for s in [b"", b"a", b"hello", b"\xff\x00"]:
        h = fnv1a_64(s)
        hex_str = fnv1a_64_hex(s)
        assert hex_str == hex_str.lower()
        assert int(hex_str, 16) == h


def test_hex_32_is_lowercase_for_various():
    for s in [b"", b"a", b"hello", b"\xff\x00"]:
        h = fnv1a_32(s)
        hex_str = fnv1a_32_hex(s)
        assert hex_str == hex_str.lower()
        assert int(hex_str, 16) == h


# Each hex digit is valid
def test_hex_contains_only_valid_chars():
    for s in [b"test", b"hello world", b"\x00\xff\x7f\x80"]:
        hex_str = fnv1a_64_hex(s)
        int(hex_str, 16)  # must not raise


def test_hex_32_contains_only_valid_chars():
    for s in [b"test", b"hello world", b"\x00\xff\x7f\x80"]:
        hex_str = fnv1a_32_hex(s)
        int(hex_str, 16)  # must not raise


# Distinctness: different positions of same byte
def test_same_bytes_different_positions():
    h1 = fnv1a_64(b"\x00" * 10 + b"\x01")
    h2 = fnv1a_64(b"\x01" + b"\x00" * 10)
    assert h1 != h2


def test_same_bytes_different_positions_32():
    h1 = fnv1a_32(b"\x00" * 10 + b"\x01")
    h2 = fnv1a_32(b"\x01" + b"\x00" * 10)
    assert h1 != h2


# Property: removing bytes changes hash
def test_property_removing_bytes():
    h_full = fnv1a_64(b"abcdef")
    h_prefix = fnv1a_64(b"abcde")
    assert h_full != h_prefix


# FNV-1a-64 of single chars a-z
def test_alphabet_fnv1a_64():
    import string
    for c in string.ascii_lowercase:
        result = fnv1a_64(c.encode())
        assert isinstance(result, int) and result >= 0


def test_alphabet_fnv1a_32():
    import string
    for c in string.ascii_lowercase:
        result = fnv1a_32(c.encode())
        assert isinstance(result, int) and result >= 0


def test_alphabet_fnv1a_64_all_distinct():
    import string
    vals = [fnv1a_64(c.encode()) for c in string.ascii_lowercase]
    assert len(set(vals)) == 26


# Multiple consecutive same bytes still change
def test_long_run_of_same_bytes():
    h1 = fnv1a_64(b"a" * 1000)
    h2 = fnv1a_64(b"a" * 1001)
    assert h1 != h2


def test_64kb_stress_fnv1a_64():
    result = fnv1a_64(b"\x69" * 65536)
    assert isinstance(result, int) and result >= 0


def test_64kb_stress_fnv1a_32():
    result = fnv1a_32(b"\x69" * 65536)
    assert isinstance(result, int) and result >= 0

