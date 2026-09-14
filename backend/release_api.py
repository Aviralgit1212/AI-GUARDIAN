from __future__ import annotations

import ipaddress

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
)

from release_store import (
    consume_release,
    get_release_status,
)


router = APIRouter(
    prefix="/release",
    tags=["release"],
)


def _require_localhost(
    request: Request,
) -> None:
    """
    Release operations are intentionally restricted
    to the local machine.

    The browser extension and backend communicate
    through 127.0.0.1.
    """

    client = request.client

    if client is None:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        )

    try:
        address = ipaddress.ip_address(
            client.host
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        ) from exc

    if not address.is_loopback:
        raise HTTPException(
            status_code=403,
            detail="Local access required.",
        )


def _get_release_token(
    request: Request,
) -> str:
    token = request.headers.get(
        "X-Guardian-Release-Token"
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Release credentials required.",
        )

    return token


@router.get(
    "/{event_id}/status"
)
def release_status(
    event_id: str,
    request: Request,
):
    """
    Return the reviewer approval state for one
    specific blocked event.

    The event-specific release token is required.
    """

    _require_localhost(
        request
    )

    release_token = _get_release_token(
        request
    )

    try:
        return get_release_status(
            event_id=event_id,
            release_token=release_token,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid release credentials.",
        ) from exc


@router.post(
    "/{event_id}"
)
def release_event(
    event_id: str,
    request: Request,
):
    """
    Consume a reviewer-approved release.

    This endpoint only authorizes the release.
    It does NOT return the original sensitive payload.

    The extension already retains the original content
    and will re-submit/re-inject it only after approval.
    """

    _require_localhost(
        request
    )

    release_token = _get_release_token(
        request
    )

    try:
        result = consume_release(
            event_id=event_id,
            release_token=release_token,
        )

    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail="Release not authorized.",
        ) from exc

    return {
        "event_id": result[
            "event_id"
        ],
        "state": result[
            "state"
        ],
    }