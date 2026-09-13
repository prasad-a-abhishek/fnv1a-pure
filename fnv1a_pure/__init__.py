# fnv1a-pure: pure-stdlib Fowler-Noll-Vo FNV-1a and FNV-1 hash
# Copy from spec verbatim — do NOT refactor or "improve" the algorithm.

# 64-bit constants
_FNV_OFFSET_64 = 14695981039346656037
_FNV_PRIME_64 = 1099511628211

# 32-bit constants
_FNV_OFFSET_32 = 2166136261
_FNV_PRIME_32 = 16777619


def _fnv1a_64(data: bytes) -> int:
    """FNV-1a-64: hash XOR byte, then multiply by prime (mod 2^64)."""
    h = _FNV_OFFSET_64
    for byte in data:
        h ^= byte
        h = (h * _FNV_PRIME_64) & 0xFFFFFFFFFFFFFFFF
    return h


def _fnv1_64(data: bytes) -> int:
    """FNV-1-64: multiply by prime first, then XOR byte (mod 2^64)."""
    h = _FNV_OFFSET_64
    for byte in data:
        h = (h * _FNV_PRIME_64) & 0xFFFFFFFFFFFFFFFF
        h ^= byte
    return h


def fnv1a_64(data: bytes) -> int:
    """FNV-1a-64 hash of a byte string. Returns unsigned 64-bit int."""
    return _fnv1a_64(data)


def fnv1_64(data: bytes) -> int:
    """FNV-1-64 hash of a byte string. Returns unsigned 64-bit int."""
    return _fnv1_64(data)


def fnv1a_32(data: bytes) -> int:
    """FNV-1a-32 hash of a byte string. Returns unsigned 32-bit int."""
    h = _FNV_OFFSET_32
    for byte in data:
        h ^= byte
        h = (h * _FNV_PRIME_32) & 0xFFFFFFFF
    return h


def fnv1_32(data: bytes) -> int:
    """FNV-1-32 hash of a byte string. Returns unsigned 32-bit int."""
    h = _FNV_OFFSET_32
    for byte in data:
        h = (h * _FNV_PRIME_32) & 0xFFFFFFFF
        h ^= byte
    return h


def fnv1a_64_hex(data: bytes) -> str:
    """FNV-1a-64 as zero-padded 16-character hex string."""
    return f"{fnv1a_64(data):016x}"


def fnv1a_32_hex(data: bytes) -> str:
    """FNV-1a-32 as zero-padded 8-character hex string."""
    return f"{fnv1a_32(data):08x}"
