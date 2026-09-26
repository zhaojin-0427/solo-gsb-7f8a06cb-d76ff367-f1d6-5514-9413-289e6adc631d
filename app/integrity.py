"""Hash-chain integrity for opened stream events.

Every event that becomes *open* (part of the contiguous prefix up to the
stream's high-water mark) is linked into a SHA-256 chain::

    digest(n) = SHA-256(
        digest(n - 1)                      # raw 32 bytes, or 32 zero bytes
        + canonical_event_bytes(event(n))  # UTF-8 compact JSON array
    )

where ``canonical_event_bytes`` serialises exactly the triple

    [stream_id, sequence, data]

as compact JSON (``separators=(",", ":")``) with every object's keys
sorted -- including nested objects inside ``data`` (``sort_keys=True``);
non-ASCII characters are emitted as raw UTF-8 bytes. The top-level value
is an *array* in the fixed key order stream id, sequence, data, not the
three-key object accepted on the ingestion API. Digests are raw 32-byte
values on the wire of this module; the API renders them as lowercase
hexadecimal.

Out-of-order events that merely sit behind a gap get no digest: the chain
is extended once, in sequence order, at the moment the gap is filled and
those sequences open. After a prefix compaction the digest *at* the
compaction bound is retained as the chain anchor, so later links continue
from it even though the anchor event itself has been deleted.

An earlier build mistakenly serialised the object
``{"stream_id", "sequence", "data}`` instead of the array; chains stored
by that build are verified with :func:`legacy_object_event_bytes` at
startup so they can be migrated to the agreed array encoding. This module
only depends on the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Raw 32-byte "previous digest" used for the first link of every chain:
#: sequence 1 of an uncompacted stream, or the zero anchor planted at a
#: compaction bound while migrating chains whose prefix is already gone.
ZERO_DIGEST = b"\x00" * 32

#: Length of a SHA-256 digest in bytes.
DIGEST_LEN = 32


def canonical_event_bytes(
    stream_id: str, sequence: int, data: Any
) -> bytes:
    """Return the canonical UTF-8 compact JSON bytes of one event.

    The event is the array ``[stream_id, sequence, data]`` in that fixed
    order, serialised without insignificant whitespace. Every object
    nested inside *data* has its keys sorted, and non-ASCII characters
    are encoded as raw UTF-8.
    """
    return json.dumps(
        [stream_id, sequence, data],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def legacy_object_event_bytes(
    stream_id: str, sequence: int, data: Any
) -> bytes:
    """Reproduce the *old*, non-conformant object encoding byte for byte.

    Earlier builds linked the object
    ``{"data", "sequence", "stream_id"}`` (sorted keys, compact) rather
    than the agreed ``[stream_id, sequence, data]`` array. This exists
    solely so startup can verify chains written by those builds before
    rewriting them; new links must always use
    :func:`canonical_event_bytes`.
    """
    return json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _chain_step(previous: bytes, event_bytes: bytes) -> bytes:
    if len(previous) != DIGEST_LEN:
        raise ValueError("previous digest must be exactly 32 bytes")
    return hashlib.sha256(previous + event_bytes).digest()


def chain_digest(
    previous: bytes, stream_id: str, sequence: int, data: Any
) -> bytes:
    """One chain step: SHA-256 over *previous* || canonical array bytes."""
    return _chain_step(
        previous, canonical_event_bytes(stream_id, sequence, data)
    )


def legacy_object_chain_digest(
    previous: bytes, stream_id: str, sequence: int, data: Any
) -> bytes:
    """Chain step using the old object encoding (verification only)."""
    return _chain_step(
        previous, legacy_object_event_bytes(stream_id, sequence, data)
    )
