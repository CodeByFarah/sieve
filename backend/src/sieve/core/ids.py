"""Identifier generation.

Primary keys are UUIDv7 (RFC 9562): a 48-bit millisecond timestamp followed by random bits.
Time-ordered keys keep B-tree inserts append-mostly, unlike random UUIDv4. Ordering *within* a
millisecond is not guaranteed and nothing relies on it.
"""

import secrets
import time
import uuid

_TIMESTAMP_BITS = 48
_RAND_A_BITS = 12
_RAND_B_BITS = 62
_VERSION = 0x7
_VARIANT = 0b10


def uuid7(timestamp_ms: int | None = None) -> uuid.UUID:
    ts = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not 0 <= ts < 1 << _TIMESTAMP_BITS:
        raise ValueError("timestamp out of range for UUIDv7")
    rand_a = secrets.randbits(_RAND_A_BITS)
    rand_b = secrets.randbits(_RAND_B_BITS)
    value = (ts << 80) | (_VERSION << 76) | (rand_a << 64) | (_VARIANT << 62) | rand_b
    return uuid.UUID(int=value)


def uuid7_timestamp_ms(value: uuid.UUID) -> int:
    return value.int >> 80
