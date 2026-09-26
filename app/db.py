"""SQLite-backed registry: nonces and ordered per-stream events.

A nonce is registered with a single ``INSERT``; the ``PRIMARY KEY``
constraint makes the registration atomic under concurrent writers. A
nonce that has already been consumed (and committed) is rejected as a
replay. A failed signature check never inserts anything, so failed
attempts do not consume a nonce.

Stream events are stored per ``(stream_id, sequence)``. Each stream has a
high-water mark: only events whose sequence is contiguous from 1 up to
the mark are "ready". Events ahead of a gap are buffered and become
visible in one atomic jump when the gap is filled. Nonce registration,
event insertion and the watermark update happen inside a single
``BEGIN IMMEDIATE`` transaction, so concurrent commits can never open the
same sequence twice.

On top of the watermark each stream keeps a *confirmed* cursor: the
highest sequence already consumed and acknowledged in order. Claim/ack
hand out the single next event ("confirmed + 1", never past the
watermark) under a short-lived lease held in the same database, so the
in-flight sequence, its random token and its expiry all survive a
process restart. Claim and ack each run inside ``BEGIN IMMEDIATE``,
which serialises concurrent consumers.

Finally each stream keeps a *compaction* bound ``compacted_until``: the
highest confirmed prefix that has been deleted to reclaim space. The
bound only moves forward and never past ``confirmed_seq``; advancing it
and deleting the bound's events are one ``BEGIN IMMEDIATE`` write
transaction, serialised against event ingestion, claim and ack. Reads
run inside a single deferred transaction, so they always see one
consistent snapshot of the bound, the watermark and the events.

Every opened event additionally carries a link of a SHA-256 *integrity
chain* (see :mod:`app.integrity`): when a gap is filled and a run of
sequences opens, each link is computed in sequence order from the
previous digest (32 zero bytes for the chain's first link) and the
event's canonical JSON array ``[stream_id, sequence, data]``. Events
merely buffered behind a gap get no digest. When a prefix is compacted
the digest *at* the new bound is atomically retained as the chain
anchor, so later writes and checks continue from it.

Two kinds of older databases are upgraded at startup, in a single
write transaction per upgrade:

* databases created before the integrity feature get every stream's
  retained, already-open events chained from the existing compaction
  bound (a zero-digest anchor is planted at a positive bound);
* databases whose chains were linked with the old, non-conformant
  three-key *object* encoding are first fully verified against that old
  encoding and only then rewritten with the agreed *array* encoding; a
  corrupted old chain aborts startup instead of being silently
  overwritten. Chains whose prefix has been compacted away cannot be
  reconstructed through the deleted events, so a zero-digest anchor is
  planted at the compaction bound and only the retained interval is
  re-chained -- verification can never cover the deleted prefix.

Events, nonces, leases, watermarks, consumer cursors and compaction
bounds are never touched by an upgrade, and every upgrade is fully
retryable after an interrupted start.
"""

from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from .integrity import (
    ZERO_DIGEST,
    chain_digest,
    legacy_object_chain_digest,
)

# Result status of a transactional event submission.
StoreStatus = Literal["ok", "replayed_nonce", "duplicate_sequence"]

# Result status of a resumable claim/ack handshake.
ClaimStatus = Literal["claimed", "empty", "leased"]
AckStatus = Literal[
    "acknowledged", "no_lease", "invalid_token", "lease_expired"
]

# Result status of a prefix compaction request.
CompactStatus = Literal["ok", "ahead_of_confirmed"]

# A claimed event is held for its consumer for this many seconds; once the
# lease expires another consumer may claim the same sequence, receiving a
# fresh random token.
LEASE_TTL_SECONDS = 30

#: Value persisted in ``schema_meta`` once digest chains use the agreed
#: canonical JSON array ``[stream_id, sequence, data]``.
DIGEST_FORMAT_ARRAY_V1 = "array-v1"


class IntegrityChainError(RuntimeError):
    """Startup found a persisted digest chain that does not verify.

    Raised instead of rewriting the offending links, so corruption is
    never silently hidden by a migration.
    """


class NonceStore:
    """Thin wrapper over a SQLite database holding nonces and events."""

    def __init__(self, db_path: str, lease_ttl_seconds: int = LEASE_TTL_SECONDS) -> None:
        self.db_path = db_path
        self.lease_ttl_seconds = lease_ttl_seconds
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        # A fresh connection per call is cheap in SQLite and avoids
        # sharing connection state across worker threads.
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        # Autocommit mode: callers own their transactions explicitly
        # (init/register rely on the context manager, store_stream_event
        # uses BEGIN IMMEDIATE). With the legacy implicit-transaction
        # isolation level, the PRAGMAs below would themselves open a
        # transaction and an explicit BEGIN would raise
        # "cannot start a transaction within a transaction".
        conn.isolation_level = None
        # NOTE: journal_mode=WAL performs an implicit COMMIT when it
        # actually changes the journal mode; in autocommit mode that is
        # harmless, and after the first connection it is a no-op.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def init_db(self) -> None:
        with closing(self._connect()) as conn, conn:
            # Establish WAL mode up front so later PRAGMA executions are
            # no-ops incapable of committing an open transaction.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce      TEXT PRIMARY KEY,
                    method     TEXT NOT NULL,
                    path       TEXT NOT NULL,
                    seen_at    INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_events (
                    stream_id  TEXT NOT NULL,
                    sequence   INTEGER NOT NULL CHECK (sequence >= 1),
                    data_json  TEXT NOT NULL,
                    nonce      TEXT NOT NULL,
                    seen_at    INTEGER NOT NULL,
                    PRIMARY KEY (stream_id, sequence)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_watermarks (
                    stream_id   TEXT PRIMARY KEY,
                    high_water  INTEGER NOT NULL CHECK (high_water >= 0)
                )
                """
            )
            # Per-stream consumption cursor: confirmed_seq is the highest
            # sequence acknowledged in order; claim/ack advance it by one.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_consumers (
                    stream_id     TEXT PRIMARY KEY,
                    confirmed_seq INTEGER NOT NULL CHECK (confirmed_seq >= 0)
                )
                """
            )
            # At most one in-flight lease per stream. A row exists only
            # while an event is claimed and unacknowledged; an expired row
            # is left in place until the next claim replaces it with a
            # fresh token, at which point its sequence is redelivered.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_leases (
                    stream_id   TEXT PRIMARY KEY,
                    sequence    INTEGER NOT NULL CHECK (sequence >= 1),
                    token       TEXT NOT NULL UNIQUE,
                    expires_at  INTEGER NOT NULL
                )
                """
            )
            # Prefix compaction bound: sequences <= compacted_until have
            # been deleted. The bound is monotonic and is never allowed to
            # pass confirmed_seq, so both cursors only ever move forward.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_compactions (
                    stream_id       TEXT PRIMARY KEY,
                    compacted_until INTEGER NOT NULL CHECK (compacted_until >= 0)
                )
                """
            )
            # Integrity hash chain, one row per sequence that has ever
            # opened (become part of the contiguous prefix). A prefix
            # compaction deletes links strictly below the new bound but
            # keeps the digest AT the bound as the anchor later links
            # continue from; with compacted_until == 0 no link is removed.
            digest_table_existed = conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'stream_digests'"
            ).fetchone() is not None
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stream_digests (
                    stream_id  TEXT NOT NULL,
                    sequence   INTEGER NOT NULL CHECK (sequence >= 1),
                    digest     BLOB NOT NULL,
                    PRIMARY KEY (stream_id, sequence)
                )
                """
            )
            # Single-row key/value bookkeeping; in particular the digest
            # encoding marker ("array-v1") that tells startup whether the
            # stored chains still use the old object encoding.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key    TEXT PRIMARY KEY,
                    value  TEXT NOT NULL
                )
                """
            )
            marker_row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'digest_format'"
            ).fetchone()

        digest_format = marker_row[0] if marker_row is not None else None
        if digest_format == DIGEST_FORMAT_ARRAY_V1:
            # Current encoding: nothing to upgrade.
            return
        if digest_format is None and not digest_table_existed:
            # Database predating integrity chaining (or a brand-new one:
            # the rebuild is a no-op without streams and just stamps the
            # marker).
            self._backfill_legacy_chains()
        elif digest_format is None or self._looks_like_object_format(
            digest_format
        ):
            # Buggy build that linked the three-key object instead of the
            # agreed array: verify the old chains, then migrate in one
            # write transaction; corruption aborts startup.
            self._migrate_object_encoded_chains(digest_format)
        else:
            raise IntegrityChainError(
                f"unknown digest format marker {digest_format!r}; refusing "
                "to touch the integrity chains"
            )

    def _backfill_legacy_chains(self) -> None:
        """Build integrity links for events retained by a pre-feature DB.

        For every known stream the existing compaction bound is treated
        as the chain frontier: with a positive bound a *zero-digest
        anchor* is stored at the bound (the deleted prefix cannot be
        reconstructed), and each retained event above the bound up to the
        committed watermark is then linked in sequence order with the
        current array encoding. Sequences above a missing run (events
        that were merely buffered behind a gap, or any physically missing
        row) receive no link, exactly as a fresh ingestion would have
        done. The rebuild and the format marker are one write
        transaction, so an interrupted start simply retries from
        scratch; events, watermarks, leases, consumers and compaction
        bounds are all left untouched.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            for stream_id, high_water, compacted_until in self._iter_streams(
                conn
            ):
                self._rebuild_stream_chain(
                    conn,
                    stream_id,
                    high_water,
                    compacted_until,
                    chain_digest,
                    plant_zero_anchor=True,
                )
            conn.execute(
                "INSERT INTO schema_meta (key, value) "
                "VALUES ('digest_format', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (DIGEST_FORMAT_ARRAY_V1,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _migrate_object_encoded_chains(self, marker: str) -> None:
        """Rewrite old object-encoded digest chains as array chains.

        The stored chains were linked against the three-key object
        ``{"stream_id", "sequence", "data}`` instead of the agreed array
        ``[stream_id, sequence, data]``. Inside a single ``BEGIN
        IMMEDIATE`` transaction every stream's stored chain is first
        *verified* against the old encoding -- anchor at the compaction
        bound, zero digest at sequence 1, each retained opened event up
        to the watermark, no extra or missing links. Only when the whole
        database verifies are the links deleted and rebuilt with the
        array encoding (a zero-digest anchor is planted at a compaction
        bound, since the deleted prefix is no longer available) and the
        format marker flipped. Any discrepancy raises
        :class:`IntegrityChainError` and leaves the database byte-for-byte
        untouched, so a corrupted old chain is never silently rewritten.
        Restarting after an interrupted migration simply retries it.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            # Guard: every linked stream must have a watermark row (links
            # only exist for opened sequences, which always create one).
            # Orphan links must not survive a marker flip unnoticed.
            watermark_streams = {
                stream_id
                for stream_id, in conn.execute(
                    "SELECT stream_id FROM stream_watermarks"
                ).fetchall()
            }
            linked_streams = {
                stream_id
                for stream_id, in conn.execute(
                    "SELECT DISTINCT stream_id FROM stream_digests"
                ).fetchall()
            }
            orphans = linked_streams - watermark_streams
            if orphans:
                raise IntegrityChainError(
                    f"digest rows exist for streams without a watermark: "
                    f"{sorted(orphans)}; refusing to migrate"
                )

            # Pass 1: verify every persisted link against the old object
            # encoding. Fail loudly on the first discrepancy.
            for stream_id, high_water, compacted_until in self._iter_streams(
                conn
            ):
                rows = conn.execute(
                    "SELECT sequence, digest FROM stream_digests "
                    "WHERE stream_id = ? ORDER BY sequence ASC",
                    (stream_id,),
                ).fetchall()
                if compacted_until > 0:
                    # Compacted stream: the anchor AT the bound must be
                    # present, and only the retained interval
                    # (bound, watermark] can be covered. The deleted prefix
                    # cannot be checked.
                    anchor = self._anchor_digest(
                        conn, stream_id, compacted_until, rows
                    )
                    if anchor is None:
                        raise IntegrityChainError(
                            f"stream {stream_id!r}: missing chain anchor at "
                            f"compaction bound {compacted_until}; old chain "
                            "cannot be verified and will not be rewritten"
                        )
                    previous = bytes(anchor)
                else:
                    previous = ZERO_DIGEST
                expected_sequences = range(compacted_until + 1, high_water + 1)
                # Every link other than the bound anchor itself must be
                # accounted for below: no stale links below the bound, no
                # missing or extra links in the retained open interval.
                retained = {
                    sequence: digest
                    for sequence, digest in rows
                    if sequence != compacted_until or compacted_until == 0
                }
                for sequence in expected_sequences:
                    event_row = conn.execute(
                        "SELECT data_json FROM stream_events "
                        "WHERE stream_id = ? AND sequence = ?",
                        (stream_id, sequence),
                    ).fetchone()
                    stored = retained.pop(sequence, None)
                    if event_row is None or stored is None:
                        raise IntegrityChainError(
                            f"stream {stream_id!r}: old object-encoded chain "
                            f"is incomplete at sequence {sequence}"
                        )
                    expected = legacy_object_chain_digest(
                        previous,
                        stream_id,
                        sequence,
                        json.loads(event_row[0]),
                    )
                    if bytes(stored) != expected:
                        raise IntegrityChainError(
                            f"stream {stream_id!r}: stored digest at sequence "
                            f"{sequence} does not match the old object-encoded "
                            "chain; refusing to rewrite a corrupted chain"
                        )
                    previous = expected
                # Links past the watermark or inside a deleted prefix mean
                # the stored chain is not the chain the code produced.
                if retained:
                    raise IntegrityChainError(
                        f"stream {stream_id!r}: unexpected digest rows at "
                        f"sequences {sorted(retained)} outside the open "
                        "retained interval"
                    )

            # Pass 2: the old chains are intact. Rebuild every stream with
            # the array encoding, planting zero anchors at compaction
            # bounds, and flip the marker -- all in this one transaction.
            for stream_id, high_water, compacted_until in self._iter_streams(
                conn
            ):
                conn.execute(
                    "DELETE FROM stream_digests WHERE stream_id = ?",
                    (stream_id,),
                )
                self._rebuild_stream_chain(
                    conn,
                    stream_id,
                    high_water,
                    compacted_until,
                    chain_digest,
                    plant_zero_anchor=compacted_until > 0,
                )
            conn.execute(
                "INSERT INTO schema_meta (key, value) "
                "VALUES ('digest_format', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (DIGEST_FORMAT_ARRAY_V1,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _looks_like_object_format(marker: str) -> bool:
        """Recognise markers left by the buggy object-encoding build."""
        # The buggy build predates schema_meta; in practice the marker is
        # simply absent. Accept an explicit legacy label as well so
        # databases stamped out of band are still migratable.
        return marker in ("object-v1", "object")

    @staticmethod
    def _iter_streams(
        conn: sqlite3.Connection,
    ) -> List[Tuple[str, int, int]]:
        """Return ``(stream_id, high_water, compacted_until)`` per stream."""
        streams = conn.execute(
            "SELECT stream_id, high_water FROM stream_watermarks"
        ).fetchall()
        result = []
        for stream_id, high_water in streams:
            compact_row = conn.execute(
                "SELECT compacted_until FROM stream_compactions "
                "WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            compacted_until = compact_row[0] if compact_row is not None else 0
            result.append((stream_id, high_water, compacted_until))
        return result

    @staticmethod
    def _anchor_digest(
        conn: sqlite3.Connection,
        stream_id: str,
        compacted_until: int,
        rows: Optional[List[Tuple[int, bytes]]] = None,
    ) -> Optional[bytes]:
        """Return the raw 32-byte retained anchor at the bound, if any."""
        if rows is not None:
            for sequence, digest in rows:
                if sequence == compacted_until:
                    return bytes(digest)
            return None
        row = conn.execute(
            "SELECT digest FROM stream_digests "
            "WHERE stream_id = ? AND sequence = ?",
            (stream_id, compacted_until),
        ).fetchone()
        return bytes(row[0]) if row is not None else None

    @staticmethod
    def _rebuild_stream_chain(
        conn: sqlite3.Connection,
        stream_id: str,
        high_water: int,
        compacted_until: int,
        link,
        *,
        plant_zero_anchor: bool,
    ) -> None:
        """Write one stream's retained chain inside *conn*'s transaction.

        A zero-digest anchor is stored *at* a positive compaction bound
        when *plant_zero_anchor* is set; retained events from
        ``compacted_until + 1`` up to *high_water* are linked in sequence
        order, stopping at the first missing event (a gap that could
        never have opened). ``link`` is the per-step digest function, so
        the same routine serves the current array encoding.
        """
        if plant_zero_anchor and compacted_until > 0:
            conn.execute(
                "INSERT INTO stream_digests (stream_id, sequence, digest) "
                "VALUES (?, ?, ?)",
                (stream_id, compacted_until, ZERO_DIGEST),
            )
        previous = ZERO_DIGEST
        sequence = compacted_until + 1
        while sequence <= high_water:
            row = conn.execute(
                "SELECT data_json FROM stream_events "
                "WHERE stream_id = ? AND sequence = ?",
                (stream_id, sequence),
            ).fetchone()
            if row is None:
                # First gap: nothing past it could have opened, so the
                # chain legitimately ends here.
                break
            digest = link(previous, stream_id, sequence, json.loads(row[0]))
            conn.execute(
                "INSERT INTO stream_digests (stream_id, sequence, digest) "
                "VALUES (?, ?, ?)",
                (stream_id, sequence, digest),
            )
            previous = digest
            sequence += 1

    def register(self, nonce: str, method: str, path: str, now: int) -> bool:
        """Atomically claim *nonce*.

        Returns ``True`` when this call is the first to consume it,
        ``False`` when it was already consumed (a replay). The insert is
        the only operation in the transaction, so the unique-constraint
        check and the insert are atomic.
        """
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO used_nonces "
                "(nonce, method, path, seen_at) VALUES (?, ?, ?, ?)",
                (nonce, method, path, now),
            )
            # The connection's context manager commits here; for a
            # unique-constraint violation INSERT OR IGNORE simply reports
            # rowcount == 0 without raising.
            return cursor.rowcount == 1

    def store_stream_event(
        self,
        *,
        nonce: str,
        method: str,
        path: str,
        now: int,
        stream_id: str,
        sequence: int,
        data: Any,
    ) -> Tuple[StoreStatus, List[int], int]:
        """Claim *nonce*, store one event and advance the watermark.

        The nonce claim, the event insert, the watermark update and the
        integrity links for every newly opened sequence run in a single
        ``BEGIN IMMEDIATE`` transaction, which serialises concurrent
        writers: either all effects commit together or none of them do. In
        particular, a duplicate sequence rolls the nonce claim back as
        well, so a rejected submission never consumes its nonce.

        Returns ``(status, opened, watermark)`` where ``opened`` is the
        strictly ordered list of sequences that became readable due to
        this very submission (empty for a buffered out-of-order event)
        and ``watermark`` is the stream's high-water mark afterwards. On
        a rejected submission both are empty / zero and nothing is
        committed.
        """
        conn = self._connect()
        # BEGIN IMMEDIATE takes a RESERVED lock immediately and queues
        # all other writers until commit, guaranteeing a single
        # watermark advance per gap fill.
        try:
            conn.execute("BEGIN IMMEDIATE")

            # 1) Global nonce claim, shared with POST /verify.
            cursor = conn.execute(
                "INSERT OR IGNORE INTO used_nonces "
                "(nonce, method, path, seen_at) VALUES (?, ?, ?, ?)",
                (nonce, method, path, now),
            )
            if cursor.rowcount == 0:
                conn.rollback()
                return "replayed_nonce", [], 0

            # 2) Event insert; a repeated (stream_id, sequence) conflicts
            #    even if the earlier event is still buffered, and also once
            #    the earlier event has been compacted away: a resubmitted
            #    confirmed sequence is still a duplicate, never a refill.
            compact_row = conn.execute(
                "SELECT compacted_until FROM stream_compactions "
                "WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            compacted_until = compact_row[0] if compact_row is not None else 0
            if sequence <= compacted_until:
                # Rollback also releases the nonce: conflicts must not
                # consume it, mirroring signature/timestamp failures.
                conn.rollback()
                return "duplicate_sequence", [], 0

            cursor = conn.execute(
                "INSERT OR IGNORE INTO stream_events "
                "(stream_id, sequence, data_json, nonce, seen_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    stream_id,
                    sequence,
                    json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                    nonce,
                    now,
                ),
            )
            if cursor.rowcount == 0:
                # Rollback also releases the nonce: conflicts must not
                # consume it, mirroring signature/timestamp failures.
                conn.rollback()
                return "duplicate_sequence", [], 0

            # 3) Advance the watermark across the longest contiguous run.
            row = conn.execute(
                "SELECT high_water FROM stream_watermarks WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            high_water = row[0] if row is not None else 0

            opened: List[int] = []
            if sequence == high_water + 1:
                # This event fills the slot right after the mark; walk
                # forward over whatever was already buffered (the current
                # sequence included) until the first missing number.
                candidate = sequence

                # Integrity chain frontier: the stored link at the current
                # watermark when one exists (a retained post-compaction
                # anchor, or simply the previous link); otherwise the
                # 32-zero anchor used at the start of every chain.
                anchor_row = conn.execute(
                    "SELECT digest FROM stream_digests "
                    "WHERE stream_id = ? AND sequence = ?",
                    (stream_id, high_water),
                ).fetchone()
                previous = anchor_row[0] if anchor_row is not None else ZERO_DIGEST

                while True:
                    event_row = conn.execute(
                        "SELECT data_json FROM stream_events "
                        "WHERE stream_id = ? AND sequence = ?",
                        (stream_id, candidate),
                    ).fetchone()
                    if event_row is None:
                        break
                    opened.append(candidate)
                    # Only now does the event leave the gap buffer and
                    # become part of the chain; buffered events have no
                    # link yet. The link input is the canonical array
                    # [stream_id, sequence, data], not the ingestion
                    # object.
                    digest = chain_digest(
                        previous, stream_id, candidate, json.loads(event_row[0])
                    )
                    conn.execute(
                        "INSERT INTO stream_digests "
                        "(stream_id, sequence, digest) VALUES (?, ?, ?)",
                        (stream_id, candidate, digest),
                    )
                    previous = digest
                    candidate += 1
                high_water = candidate - 1
                conn.execute(
                    "INSERT INTO stream_watermarks (stream_id, high_water) "
                    "VALUES (?, ?) "
                    "ON CONFLICT(stream_id) DO UPDATE SET "
                    "high_water = excluded.high_water",
                    (stream_id, high_water),
                )
            # sequence > high_water + 1: a gap remains, so the event is
            # simply buffered, the mark does not move and no digest is
            # written for it.

            conn.commit()
            return "ok", opened, high_water
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def ready_events(
        self, stream_id: str, after_seq: int
    ) -> Tuple[int, int, List[Dict[str, Any]]]:
        """Return ``(compacted_until, watermark, events)`` for *stream_id*.

        Events are returned in sequence order; only sequences greater
        than *after_seq* and no greater than the committed high-water
        mark are included. Reading is non-destructive.

        The bound, the watermark and the rows are read inside one
        deferred transaction, so a concurrent writer (ingestion, claim/ack
        or compaction) can never make the answer internally inconsistent
        -- in particular the returned events always form the contiguous
        prefix ``(compacted_until, watermark]`` (filtered by *after_seq*).
        """
        if after_seq < 0:
            raise ValueError("after_seq must be non-negative")
        with closing(self._connect()) as conn:
            # A plain BEGIN takes no write lock; all reads within it see a
            # single snapshot (WAL), so a compaction committing between
            # the two SELECTs cannot hide an event the watermark still
            # covers.
            conn.execute("BEGIN")
            try:
                compact_row = conn.execute(
                    "SELECT compacted_until FROM stream_compactions "
                    "WHERE stream_id = ?",
                    (stream_id,),
                ).fetchone()
                compacted_until = compact_row[0] if compact_row is not None else 0
                row = conn.execute(
                    "SELECT high_water FROM stream_watermarks "
                    "WHERE stream_id = ?",
                    (stream_id,),
                ).fetchone()
                high_water = row[0] if row is not None else 0
                lower = max(after_seq, compacted_until)
                rows = conn.execute(
                    "SELECT sequence, data_json FROM stream_events "
                    "WHERE stream_id = ? AND sequence > ? AND sequence <= ? "
                    "ORDER BY sequence ASC",
                    (stream_id, lower, high_water),
                ).fetchall()
            finally:
                conn.rollback()
        events = [
            {"sequence": sequence, "data": json.loads(data_json)}
            for sequence, data_json in rows
        ]
        return compacted_until, high_water, events

    def claim_next_event(
        self, stream_id: str, now: Optional[int] = None
    ) -> Tuple[ClaimStatus, Optional[Dict[str, Any]]]:
        """Hand out the stream's next unconsumed event under a lease.

        The claimable sequence is ``confirmed_seq + 1`` and must not
        exceed the committed watermark: buffered events behind a gap are
        never handed out. The check, lease (re)creation and token
        generation run inside one ``BEGIN IMMEDIATE`` transaction, so
        concurrent claims for the same stream are serialised: exactly one
        caller gets the event while the lease is live; everyone else gets
        ``"leased"``. Once the lease expires the same sequence is handed
        out again with a new random token and a new expiry.

        Returns ``(status, claim)`` where *claim* is
        ``{"sequence", "data", "token", "expires_at"}`` for
        ``"claimed"`` and ``None`` for ``"empty"``/``"leased"``.
        """
        if now is None:
            now = int(time.time())
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            watermark_row = conn.execute(
                "SELECT high_water FROM stream_watermarks WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            high_water = watermark_row[0] if watermark_row is not None else 0

            consumer_row = conn.execute(
                "SELECT confirmed_seq FROM stream_consumers WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            confirmed_seq = consumer_row[0] if consumer_row is not None else 0

            next_sequence = confirmed_seq + 1

            # No event confirmed-and-opened is available yet: either the
            # stream is unknown / behind a gap, or every open event has
            # already been acknowledged.
            if next_sequence > high_water:
                conn.rollback()
                return "empty", None

            lease_row = conn.execute(
                "SELECT sequence, expires_at FROM stream_leases "
                "WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            if lease_row is not None:
                leased_sequence, expires_at = lease_row
                # A live lease pins the next sequence; an expired lease
                # on an already-acknowledged sequence is stale (the ack
                # normally deletes it) and is simply replaced below.
                if leased_sequence == next_sequence and expires_at > now:
                    conn.rollback()
                    return "leased", None

            data_row = conn.execute(
                "SELECT data_json FROM stream_events "
                "WHERE stream_id = ? AND sequence = ?",
                (stream_id, next_sequence),
            ).fetchone()
            # Defensive: the watermark guarantees this row exists.
            if data_row is None:
                conn.rollback()
                return "empty", None

            token = secrets.token_hex(20)
            expires_at = now + self.lease_ttl_seconds
            conn.execute(
                "INSERT INTO stream_leases (stream_id, sequence, token, expires_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(stream_id) DO UPDATE SET "
                "sequence = excluded.sequence, "
                "token = excluded.token, "
                "expires_at = excluded.expires_at",
                (stream_id, next_sequence, token, expires_at),
            )
            conn.commit()
            return "claimed", {
                "sequence": next_sequence,
                "data": json.loads(data_row[0]),
                "token": token,
                "expires_at": expires_at,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def acknowledge_lease(
        self, stream_id: str, token: str, now: Optional[int] = None
    ) -> Tuple[AckStatus, Optional[int]]:
        """Confirm the stream's current lease using its random *token*.

        Only a still-unexpired lease presenting the exact token handed out
        by :meth:`claim_next_event` succeeds. Success atomically advances
        the stream's confirmed sequence to the leased sequence and clears
        the lease. Any other case -- no outstanding lease, an old/wrong
        token, a duplicate ack, or an expired lease -- returns a failure
        status and changes nothing. The whole decision and its effects are
        one ``BEGIN IMMEDIATE`` transaction, serialising acknowledgements
        against competing claims.

        Returns ``(status, sequence)`` where *sequence* is the confirmed
        sequence on success and ``None`` for every failure status.
        """
        if now is None:
            now = int(time.time())
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            lease_row = conn.execute(
                "SELECT sequence, token, expires_at FROM stream_leases "
                "WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            if lease_row is None:
                conn.rollback()
                return "no_lease", None
            sequence, current_token, expires_at = lease_row

            if expires_at <= now:
                conn.rollback()
                return "lease_expired", None
            # Constant-time comparison: tokens are bearer secrets and the
            # ack endpoint must not leak them through response timing.
            if not hmac.compare_digest(current_token, token):
                conn.rollback()
                return "invalid_token", None

            conn.execute(
                "INSERT INTO stream_consumers (stream_id, confirmed_seq) "
                "VALUES (?, ?) "
                "ON CONFLICT(stream_id) DO UPDATE SET "
                "confirmed_seq = excluded.confirmed_seq",
                (stream_id, sequence),
            )
            conn.execute(
                "DELETE FROM stream_leases WHERE stream_id = ?",
                (stream_id,),
            )
            conn.commit()
            return "acknowledged", sequence
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def compact_stream(
        self, stream_id: str, through_seq: int
    ) -> Tuple[CompactStatus, int, int]:
        """Delete the stream's confirmed prefix up to *through_seq*.

        Only sequences already acknowledged (``through_seq <=
        confirmed_seq``) may be removed; the compaction bound
        ``compacted_until`` is persisted and can only move forward.
        Advancing the bound, deleting ``sequence <= bound`` events and
        dropping integrity links ``sequence < bound`` happen in one
        ``BEGIN IMMEDIATE`` transaction, serialised against event
        ingestion, claim and ack, so a reader can never observe a bound
        past the deleted rows or a deletion past the bound. The integrity
        digest AT the new bound is retained as the chain anchor: later
        events chain onto it even though the anchor event itself is
        deleted.

        An unknown stream has ``confirmed_seq == 0``: the only accepted
        request there is ``through_seq == 0``, which succeeds idempotently
        without creating any state.

        Returns ``(status, compacted_until, confirmed_seq)``; on
        ``"ahead_of_confirmed"`` nothing changes and both values reflect
        the current cursors (``0`` for an unknown stream). A request at or
        below the existing bound is idempotent and returns the bound.
        """
        if through_seq < 0:
            raise ValueError("through_seq must be non-negative")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            consumer_row = conn.execute(
                "SELECT confirmed_seq FROM stream_consumers WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            confirmed_seq = consumer_row[0] if consumer_row is not None else 0

            compact_row = conn.execute(
                "SELECT compacted_until FROM stream_compactions "
                "WHERE stream_id = ?",
                (stream_id,),
            ).fetchone()
            compacted_until = compact_row[0] if compact_row is not None else 0

            if through_seq > confirmed_seq:
                # The caller may only discard events already confirmed in
                # order; a live lease on an unconfirmed event is implicitly
                # protected as well, since its sequence is confirmed_seq + 1.
                conn.rollback()
                return "ahead_of_confirmed", compacted_until, confirmed_seq

            # Monotonic bound: an equal or smaller request is a no-op that
            # simply reports the persisted bound (idempotent success).
            if through_seq > compacted_until:
                conn.execute(
                    "INSERT INTO stream_compactions "
                    "(stream_id, compacted_until) VALUES (?, ?) "
                    "ON CONFLICT(stream_id) DO UPDATE SET "
                    "compacted_until = excluded.compacted_until",
                    (stream_id, through_seq),
                )
                conn.execute(
                    "DELETE FROM stream_events "
                    "WHERE stream_id = ? AND sequence <= ?",
                    (stream_id, through_seq),
                )
                # Remove only links strictly below the new bound: the
                # digest AT the bound is the chain anchor later writes and
                # integrity checks continue from, so it must survive the
                # deletion of its event. through_seq == 0 deletes nothing.
                conn.execute(
                    "DELETE FROM stream_digests "
                    "WHERE stream_id = ? AND sequence < ?",
                    (stream_id, through_seq),
                )
                compacted_until = through_seq

            conn.commit()
            return "ok", compacted_until, confirmed_seq
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def stream_integrity(
        self, stream_id: str
    ) -> Tuple[int, int, bytes, Optional[int]]:
        """Recompute one stream's integrity chain inside a single snapshot.

        The recomputation starts at the compaction anchor -- the retained
        digest whose sequence equals ``compacted_until`` (32 zero bytes
        when the bound is 0 or no anchor exists) -- and walks every
        retained, opened event from ``compacted_until + 1`` up to the
        high-water mark in sequence order, replaying each SHA-256 chain
        step over the event's canonical JSON array
        ``[stream_id, sequence, data]`` and comparing it against the
        stored digest. Only this retained interval
        ``(compacted_until, watermark]`` can ever be covered: events at
        or below a positive bound have been physically deleted and
        cannot be replayed. The bound, watermark, anchor, event rows and
        digest rows are all read inside one deferred transaction, so the
        answer can never mix states from two concurrent commits.

        Returns ``(compacted_until, watermark, tail_digest,
        first_invalid_sequence)``:

        * ``tail_digest`` is the recomputed digest of the last verified
          sequence (the chain tail), or 32 zero bytes for an unknown /
          still-empty stream whose chain has not started;
        * ``first_invalid_sequence`` is the first sequence whose event is
          missing or whose stored digest does not match, or ``None`` when
          every retained opened event verifies.
        """
        with closing(self._connect()) as conn:
            conn.execute("BEGIN")
            try:
                watermark_row = conn.execute(
                    "SELECT high_water FROM stream_watermarks "
                    "WHERE stream_id = ?",
                    (stream_id,),
                ).fetchone()
                if watermark_row is None:
                    # Unknown stream: empty chain. Nothing to roll back
                    # over; a buffered-only stream is indistinguishable
                    # here and answers identically.
                    return 0, 0, ZERO_DIGEST, None
                high_water = watermark_row[0]

                compact_row = conn.execute(
                    "SELECT compacted_until FROM stream_compactions "
                    "WHERE stream_id = ?",
                    (stream_id,),
                ).fetchone()
                compacted_until = compact_row[0] if compact_row is not None else 0

                anchor_row = conn.execute(
                    "SELECT digest FROM stream_digests "
                    "WHERE stream_id = ? AND sequence = ?",
                    (stream_id, compacted_until),
                ).fetchone()
                if anchor_row is not None:
                    tail = bytes(anchor_row[0])
                    if len(tail) != 32:
                        tail = ZERO_DIGEST
                else:
                    # Bound 0 (chain start) or a legacy-style bound without
                    # a retained anchor: verify from the zero digest.
                    tail = ZERO_DIGEST

                first_invalid: Optional[int] = None
                sequence = compacted_until + 1
                while sequence <= high_water:
                    event_row = conn.execute(
                        "SELECT data_json FROM stream_events "
                        "WHERE stream_id = ? AND sequence = ?",
                        (stream_id, sequence),
                    ).fetchone()
                    if event_row is None:
                        first_invalid = sequence
                        break
                    expected = chain_digest(
                        tail, stream_id, sequence, json.loads(event_row[0])
                    )
                    stored_row = conn.execute(
                        "SELECT digest FROM stream_digests "
                        "WHERE stream_id = ? AND sequence = ?",
                        (stream_id, sequence),
                    ).fetchone()
                    if stored_row is None or bytes(stored_row[0]) != expected:
                        first_invalid = sequence
                        break
                    tail = expected
                    sequence += 1
            finally:
                conn.rollback()
        return compacted_until, high_water, tail, first_invalid
