"""Hash-chain integrity for opened stream events.

Every event that becomes *open* (part of the contiguous prefix up to the
stream's high-water mark) is linked into a SHA-256 chain::

    digest(n) = SHA-256(
        digest(n - 1)                      # raw 32 bytes, or 32 zero bytes
        + canonical_json(event(n)).UTF-8   # for the chain's first item
    )

where ``canonical_json`` serialises exactly the object
``{"stream_id", "sequence", "data"}`` as compact JSON with sorted object
keys (``separators=(",", ":")``, ``sort_keys=True``); non-ASCII
characters are emitted as raw UTF-8 bytes, matching the compact
representation stored at ingestion. Digests are raw 32-byte values on
the wire of this module; the API renders them as lowercase hexadecimal.

Out-of-order events that merely sit behind a gap get no digest: the chain
is extended once, in sequence order, at the moment the gap is filled and
those sequences open. After a prefix compaction the digest *at* the
compaction bound is retained as the chain anchor, so later links continue
from it even though the anchor event itself has been deleted.

This module only depends on the Python standard library.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: Raw 32-byte "previous digest" used for the first link of every chain:
#: sequence 1 of an uncompacted stream, or the first retained sequence
#: after a compaction on a database that predates the digest table.
ZERO_DIGEST = b"\x00" * 32

#: Length of a SHA-256 digest in bytes.
DIGEST_LEN = 32


def canonical_event_bytes(
    stream_id: str, sequence: int, data: Any
) -> bytes:
    """Return the canonical UTF-8 compact JSON bytes of one event.

    The object has exactly the three keys ``data``, ``sequence`` and
    ``stream_id`` (sorted, as is every nested object key), no insignificant
    whitespace and non-ASCII characters encoded as raw UTF-8.
    """
    return json.dumps(
        {"stream_id": stream_id, "sequence": sequence, "data": data},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def chain_digest(
    previous: bytes, stream_id: str, sequence: int, data: Any
) -> bytes:
    """One chain step: SHA-256 over *previous* || canonical event bytes."""
    if len(previous) != DIGEST_LEN:
        raise ValueError("previous digest must be exactly 32 bytes")
    payload = previous + canonical_event_bytes(stream_id, sequence, data)
    return hashlib.sha256(payload).digest()
