from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from dashboard_store import DB_PATH


RELEASE_TTL_MINUTES = 20


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    return connection


def init_release_store() -> None:
    """
    Create the held_payloads table if it does not exist.

    Raw payloads are kept separate from dashboard metadata.
    """

    connection = _connect()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS held_payloads (
                event_id TEXT PRIMARY KEY,
                release_token_hash TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                raw_text TEXT,
                raw_file_base64 TEXT,
                original_filename TEXT,
                mime_type TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(event_id)
                    REFERENCES security_events(id)
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def create_held_payload(
    *,
    event_id: str,
    release_token: str,
    payload_type: str,
    raw_text: str | None = None,
    raw_file_base64: str | None = None,
    original_filename: str | None = None,
    mime_type: str | None = None,
) -> None:
    """
    Store the original blocked payload and only a hash of
    the release token.

    The plaintext release token is returned to the caller
    from main.py but is never persisted.
    """

    if payload_type not in {
        "text",
        "file",
    }:
        raise ValueError(
            "Unsupported payload type."
        )

    if payload_type == "text":
        if raw_text is None:
            raise ValueError(
                "raw_text is required for text payloads."
            )

        raw_file_base64 = None
        original_filename = None
        mime_type = None

    elif payload_type == "file":
        if raw_file_base64 is None:
            raise ValueError(
                "raw_file_base64 is required for file payloads."
            )

        raw_text = None

    init_release_store()

    now = _utc_now()
    expires_at = (
        now
        + timedelta(
            minutes=RELEASE_TTL_MINUTES
        )
    )

    connection = _connect()

    try:
        connection.execute(
            """
            INSERT INTO held_payloads (
                event_id,
                release_token_hash,
                payload_type,
                raw_text,
                raw_file_base64,
                original_filename,
                mime_type,
                created_at,
                expires_at,
                consumed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                event_id,
                _hash_token(release_token),
                payload_type,
                raw_text,
                raw_file_base64,
                original_filename,
                mime_type,
                _iso(now),
                _iso(expires_at),
            ),
        )

        connection.commit()

    finally:
        connection.close()


def _clear_payload(
    connection: sqlite3.Connection,
    event_id: str,
) -> None:
    """
    Permanently clear the raw held payload while preserving
    the event tombstone/state for safe status polling.
    """

    connection.execute(
        """
        UPDATE held_payloads
        SET
            raw_text = NULL,
            raw_file_base64 = NULL,
            original_filename = NULL,
            mime_type = NULL
        WHERE event_id = ?
        """,
        (event_id,),
    )


def _expire_if_needed(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> sqlite3.Row:
    """
    Expire a held payload when its TTL has elapsed.

    The row is retained as a tombstone so callers receive
    EXPIRED instead of an ambiguous not-found response.
    """

    if row["consumed"]:
        return row

    expires_at = _parse_iso(
        row["expires_at"]
    )

    if _utc_now() >= expires_at:

        _clear_payload(
            connection,
            row["event_id"],
        )

        connection.execute(
            """
            UPDATE held_payloads
            SET consumed = 1
            WHERE event_id = ?
            """,
            (row["event_id"],),
        )

        connection.commit()

        updated = connection.execute(
            """
            SELECT *
            FROM held_payloads
            WHERE event_id = ?
            """,
            (row["event_id"],),
        ).fetchone()

        return updated

    return row


def get_release_status(
    *,
    event_id: str,
    release_token: str,
) -> dict[str, Any]:
    """
    Return the current reviewer approval state.

    The caller must possess the event-specific release token.
    """

    init_release_store()

    connection = _connect()

    try:
        row = connection.execute(
            """
            SELECT
                hp.*,
                se.state AS security_state
            FROM held_payloads hp
            LEFT JOIN security_events se
                ON se.id = hp.event_id
            WHERE hp.event_id = ?
            """,
            (event_id,),
        ).fetchone()

        if row is None:
            raise PermissionError(
                "Invalid release credentials."
            )

        expected_hash = row[
            "release_token_hash"
        ]

        supplied_hash = _hash_token(
            release_token
        )

        if not hmac.compare_digest(
            expected_hash,
            supplied_hash,
        ):
            raise PermissionError(
                "Invalid release credentials."
            )

        row = _expire_if_needed(
            connection,
            row,
        )

        security_state = row[
            "security_state"
        ]

        if row["consumed"]:

            if security_state == "REJECTED":
                state = "REJECTED"

            elif security_state == "APPROVED":
                state = "RELEASED"

            else:
                expires_at = _parse_iso(
                    row["expires_at"]
                )

                if _utc_now() >= expires_at:
                    state = "EXPIRED"
                else:
                    state = (
                        security_state
                        or "TERMINAL"
                    )

        else:

            if security_state == "APPROVED":
                state = "APPROVED"

            elif security_state == "REJECTED":
                state = "REJECTED"

            elif security_state == "BLOCKED":
                state = "PENDING"

            else:
                state = (
                    security_state
                    or "PENDING"
                )

        return {
            "event_id": event_id,
            "state": state,
        }

    finally:
        connection.close()


def consume_release(
    *,
    event_id: str,
    release_token: str,
) -> dict[str, Any]:
    """
    Atomically authorize and consume a reviewer-approved
    release.

    This operation is one-time and fail-closed.
    """

    init_release_store()

    connection = _connect()

    try:
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                hp.*,
                se.state AS security_state
            FROM held_payloads hp
            LEFT JOIN security_events se
                ON se.id = hp.event_id
            WHERE hp.event_id = ?
            """,
            (event_id,),
        ).fetchone()

        if row is None:
            connection.rollback()

            raise PermissionError(
                "Invalid release credentials."
            )

        expected_hash = row[
            "release_token_hash"
        ]

        supplied_hash = _hash_token(
            release_token
        )

        if not hmac.compare_digest(
            expected_hash,
            supplied_hash,
        ):
            connection.rollback()

            raise PermissionError(
                "Invalid release credentials."
            )

        if row["consumed"]:
            connection.rollback()

            raise PermissionError(
                "Release has already been consumed."
            )

        expires_at = _parse_iso(
            row["expires_at"]
        )

        if _utc_now() >= expires_at:

            _clear_payload(
                connection,
                event_id,
            )

            connection.execute(
                """
                UPDATE held_payloads
                SET consumed = 1
                WHERE event_id = ?
                """,
                (event_id,),
            )

            connection.commit()

            raise PermissionError(
                "Release has expired."
            )

        if row["security_state"] != "APPROVED":
            connection.rollback()

            raise PermissionError(
                "Release has not been approved."
            )

        payload_type = row[
            "payload_type"
        ]

        raw_text = row[
            "raw_text"
        ]

        raw_file_base64 = row[
            "raw_file_base64"
        ]

        original_filename = row[
            "original_filename"
        ]

        mime_type = row[
            "mime_type"
        ]

        _clear_payload(
            connection,
            event_id,
        )

        connection.execute(
            """
            UPDATE held_payloads
            SET consumed = 1
            WHERE event_id = ?
            """,
            (event_id,),
        )

        connection.commit()

        return {
            "event_id": event_id,
            "state": "RELEASED",
            "payload_type": payload_type,
            "raw_text": raw_text,
            "raw_file_base64": raw_file_base64,
            "original_filename": original_filename,
            "mime_type": mime_type,
        }

    except Exception:
        if connection.in_transaction:
            connection.rollback()

        raise

    finally:
        connection.close()


def purge_held_payload(
    event_id: str,
) -> None:
    """
    Clear a held payload after reviewer rejection.

    The row is retained as a tombstone so the extension can
    still observe the REJECTED dashboard state.
    """

    init_release_store()

    connection = _connect()

    try:

        _clear_payload(
            connection,
            event_id,
        )

        connection.execute(
            """
            UPDATE held_payloads
            SET consumed = 1
            WHERE event_id = ?
            """,
            (event_id,),
        )

        connection.commit()

    finally:
        connection.close()


def cleanup_expired_payloads() -> int:
    """
    Remove raw payload data for all expired/unconsumed
    held payloads.

    Returns the number of rows processed.
    """

    init_release_store()

    connection = _connect()

    try:
        now = _utc_now()

        rows = connection.execute(
            """
            SELECT event_id, expires_at
            FROM held_payloads
            WHERE consumed = 0
            """
        ).fetchall()

        processed = 0

        for row in rows:

            expires_at = _parse_iso(
                row["expires_at"]
            )

            if now >= expires_at:

                _clear_payload(
                    connection,
                    row["event_id"],
                )

                connection.execute(
                    """
                    UPDATE held_payloads
                    SET consumed = 1
                    WHERE event_id = ?
                    """,
                    (row["event_id"],),
                )

                processed += 1

        connection.commit()

        return processed

    finally:
        connection.close()


init_release_store()