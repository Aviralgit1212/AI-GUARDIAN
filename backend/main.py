from __future__ import annotations

from dashboard_api import router as dashboard_router
from release_api import router as release_router
import base64
import json
import mimetypes
import secrets
import urllib.request

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dashboard_store import (
    create_security_event,
)
from release_store import create_held_payload
from scanner.scanner import Scanner
from policy.policy import PolicyEngine
from risk.risk import RiskEngine
from decision.decision import DecisionEngine
from redact.redact import Redactor
from redact.pdf_redact import (
    RedactionError,
    redact_pdf,
)
from redact.image_redact import (
    ImageRedactionError,
    redact_and_verify_image,
)
from redact.docx_redact import (
    DocxRedactionError,
    redact_docx,
)
from extraction.extraction import (
    extract_pages,
    extract_text,
)
from extraction.image_ocr import (
    extract_image,
)


app = FastAPI()

app.include_router(
    dashboard_router
)

app.include_router(
    release_router
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
        "OPTIONS",
    ],
    allow_headers=["*"],
)


scanner = Scanner()
policy_engine = PolicyEngine()
risk_engine = RiskEngine()
decision_engine = DecisionEngine()
redactor = Redactor()


class ScanRequest(BaseModel):
    text: str


def run_security_pipeline(
    text: str,
) -> dict:
    """
    Run the existing security pipeline for
    plain text or extracted file text.
    """

    entities = scanner.scan(
        text
    )

    flagged_entities = (
        policy_engine.evaluate(
            entities
        )
    )

    risk = risk_engine.calculate(
        flagged_entities
    )

    decision = decision_engine.decide(
        risk
    )

    redacted_text = None

    if decision == "REDACT":
        redacted_text = redactor.redact(
            text,
            flagged_entities,
        )

    return {
        "entities": flagged_entities,
        "risk": risk,
        "decision": decision,
        "redacted_text": redacted_text,
    }


def _notify_corsair_block(
    *,
    event_id: str,
    risk: str,
    entities: list[dict],
) -> None:
    """
    Notify the reviewer through the Corsair sidecar.

    Only metadata is sent. Raw sensitive values are
    never sent to Slack.
    """

    detection_types: list[str] = []

    for entity in entities:
        entity_type = entity.get(
            "entity_type"
        )

        if (
            isinstance(
                entity_type,
                str,
            )
            and entity_type
        ):
            detection_types.append(
                entity_type
            )

    detection = (
        ", ".join(
            sorted(
                set(detection_types)
            )
        )
        or "Sensitive data"
    )

    payload = {
        "event_id": event_id,
        "risk": risk,
        "detection": detection,
        "dashboard_url": (
            "http://127.0.0.1:5173"
        ),
    }

    try:
        request = urllib.request.Request(
            "http://127.0.0.1:9000/notify",
            data=json.dumps(
                payload
            ).encode("utf-8"),
            headers={
                "Content-Type":
                    "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request,
            timeout=3,
        ) as response:

            if response.status != 200:
                print(
                    "[AI Guardian] Corsair notification "
                    f"returned HTTP {response.status}"
                )

            else:
                print(
                    "[AI Guardian] Corsair BLOCK notification: PASS"
                )

    except Exception as exc:
        # Notification failure must NEVER weaken
        # the underlying BLOCK decision.
        print(
            "[AI Guardian] Corsair notification failed:",
            exc,
        )


def _record_dashboard_event(
    *,
    request: Request,
    input_type: str,
    filename: str | None,
    security_result: dict,
    held_payload: dict | None = None,
) -> tuple[str, str | None]:
    """
    Record Dashboard metadata only, and — for BLOCK
    decisions — mint a release token and (optionally)
    hand the original payload to release_store for
    later reviewer-gated release.

    Raw text, file bytes, and matched sensitive
    values are never stored or sent to Slack. The
    release token is only ever returned to the caller
    that made the original request, never to Corsair/Slack.
    """

    origin = request.headers.get(
        "origin"
    )

    if origin:
        site = (
            origin
            .split("://", 1)[-1]
            .split("/", 1)[0]
        )
    else:
        site = "unknown"

    decision = security_result.get(
        "decision",
        "BLOCK",
    )

    if decision == "ALLOW":
        state = "ALLOWED"

    elif decision == "REDACT":
        state = "REDACTED"

    else:
        state = "BLOCKED"

    event_id = create_security_event(
        username="local-user",
        site=site,
        input_type=input_type,
        filename=filename,
        risk=security_result.get(
            "risk",
            "UNKNOWN",
        ),
        decision=decision,
        state=state,
        entities=security_result.get(
            "entities",
            [],
        ),
        status_detail=security_result.get(
            "status_detail"
        ),
    )

    release_token = None

    if decision == "BLOCK":

        release_token = secrets.token_urlsafe(
            32
        )

        if held_payload is not None:

            create_held_payload(
                event_id=event_id,
                release_token=release_token,
                **held_payload,
            )

        _notify_corsair_block(
            event_id=event_id,
            risk=security_result.get(
                "risk",
                "UNKNOWN",
            ),
            entities=security_result.get(
                "entities",
                [],
            ),
        )

    return event_id, release_token


def _held_payload_for_text(
    text: str,
) -> dict:
    """
    Build the held_payload kwargs for a
    BLOCKed plain-text /scan request.
    """

    return {
        "payload_type": "text",
        "raw_text": text,
    }


def _held_payload_for_file(
    file_bytes: bytes,
    filename: str,
    content_type: str | None,
) -> dict:
    """
    Build the held_payload kwargs for a
    BLOCKed /scan-file request.

    Prefers the browser-supplied content type;
    falls back to guessing from the filename,
    then to a generic binary type.
    """

    guessed_type, _ = mimetypes.guess_type(
        filename
    )

    resolved_type = (
        content_type
        or guessed_type
        or "application/octet-stream"
    )

    return {
        "payload_type": "file",
        "raw_file_base64": base64.b64encode(
            file_bytes
        ).decode("ascii"),
        "original_filename": filename,
        "mime_type": resolved_type,
    }


def _fail_closed_response(
    filename: str,
    byte_count: int,
    security_result: dict,
    error: str,
) -> dict:
    """
    Return the common fail-closed file response.

    The original file is never returned.
    """

    return {
        "filename": filename,
        "byte_count": byte_count,
        "entities": security_result[
            "entities"
        ],
        "risk": security_result[
            "risk"
        ],
        "decision": "BLOCK",
        "redacted_text": None,
        "redacted_file_base64": None,
        "redacted_filename": None,
        "redacted_mime_type": None,
        "error": error,
    }


@app.post("/ping")
def ping():
    return {
        "status": "got it"
    }


@app.post("/scan")
def scan(
    request: ScanRequest,
    http_request: Request,
):
    security_result = (
        run_security_pipeline(
            request.text
        )
    )

    held_payload = (
        _held_payload_for_text(
            request.text
        )
        if security_result["decision"] == "BLOCK"
        else None
    )

    event_id, release_token = _record_dashboard_event(
        request=http_request,
        input_type="TEXT",
        filename=None,
        security_result=security_result,
        held_payload=held_payload,
    )

    return {
        **security_result,
        "event_id": event_id,
        "release_token": release_token,
    }


@app.post("/scan-file")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
):
    filename = file.filename or ""
    filename_lower = filename.lower()

    file_bytes = await file.read()

    image_input = (
        filename_lower.endswith(
            (
                ".png",
                ".jpg",
                ".jpeg",
            )
        )
    )

    try:

        if image_input:

            # IMAGE/OCR — 6.4.5
            # One OCR pass produces the text used by
            # the common security pipeline.
            # The same image is reprocessed only
            # inside the format-specific redaction
            # adapter when REDACT is required.

            image_ocr_result = extract_image(
                file_bytes
            )

            extracted_text = (
                image_ocr_result.full_text
            )

        else:

            extracted_text = extract_text(
                file_bytes,
                filename,
            )

    except ValueError as exc:

        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


    security_result = run_security_pipeline(
        extracted_text
    )


    response = {
        "filename": filename,
        "byte_count": len(file_bytes),
        **security_result,
        "redacted_file_base64": None,
        "redacted_filename": None,
        "redacted_mime_type": None,
    }


    # --------------------------------------------------
    # REDACT — FORMAT-SPECIFIC ADAPTER DISPATCH
    # --------------------------------------------------

    if security_result[
        "decision"
    ] == "REDACT":

        try:

            # --------------------------------------------------
            # PDF — EXISTING 5H PATH, KEPT INTACT
            # --------------------------------------------------

            if filename_lower.endswith(
                ".pdf"
            ):

                page_texts = extract_pages(
                    file_bytes
                )

                entities_by_page: dict[
                    int,
                    list[str],
                ] = {}


                for (
                    page_number,
                    page_text,
                ) in enumerate(
                    page_texts
                ):

                    page_entities = scanner.scan(
                        page_text
                    )

                    flagged_page_entities = (
                        policy_engine.evaluate(
                            page_entities
                        )
                    )

                    page_strings: list[
                        str
                    ] = []


                    for entity in (
                        flagged_page_entities
                    ):

                        entity_text = entity.get(
                            "text"
                        )


                        if (
                            isinstance(
                                entity_text,
                                str,
                            )
                            and entity_text
                        ):

                            page_strings.append(
                                entity_text
                            )


                    if page_strings:

                        entities_by_page[
                            page_number
                        ] = page_strings


                redacted_bytes = redact_pdf(
                    file_bytes,
                    entities_by_page,
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    "application/pdf"
                )


            # --------------------------------------------------
            # DOCX — NEW 6.3 PATH
            # --------------------------------------------------

            elif filename_lower.endswith(
                ".docx"
            ):

                redacted_bytes = redact_docx(
                    file_bytes,
                    security_result[
                        "entities"
                    ],
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    "application/"
                    "vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                )


            # --------------------------------------------------
            # IMAGE — 6.4 PATH
            # --------------------------------------------------

            elif filename_lower.endswith(
                (
                    ".png",
                    ".jpg",
                    ".jpeg",
                )
            ):

                entity_matches: list[
                    tuple[int, int, str]
                ] = []


                for entity in (
                    security_result[
                        "entities"
                    ]
                ):

                    entity_text = entity.get(
                        "text"
                    )

                    entity_start = entity.get(
                        "start"
                    )

                    entity_end = entity.get(
                        "end"
                    )


                    if not isinstance(
                        entity_text,
                        str,
                    ) or not entity_text:

                        raise ImageRedactionError(
                            "Sensitive image entity "
                            "has no valid text."
                        )


                    if (
                        not isinstance(
                            entity_start,
                            int,
                        )
                        or not isinstance(
                            entity_end,
                            int,
                        )
                    ):

                        raise ImageRedactionError(
                            "Sensitive image entity "
                            "has invalid offsets."
                        )


                    entity_matches.append(
                        (
                            entity_start,
                            entity_end,
                            entity_text,
                        )
                    )


                redacted_result = (
                    redact_and_verify_image(
                        file_bytes,
                        entity_matches,
                    )
                )


                response[
                    "redacted_text"
                ] = None


                response[
                    "redacted_file_base64"
                ] = base64.b64encode(
                    redacted_result.redacted_bytes
                ).decode(
                    "ascii"
                )


                response[
                    "redacted_filename"
                ] = (
                    f"redacted_{filename}"
                )


                response[
                    "redacted_mime_type"
                ] = (
                    redacted_result.mime_type
                )


            # --------------------------------------------------
            # UNSUPPORTED REDACTION FORMAT
            # --------------------------------------------------

            else:

                failed_response = (
                    _fail_closed_response(
                        filename,
                        len(file_bytes),
                        security_result,
                        "Could not generate a "
                        "safe version of "
                        "this file — blocked.",
                    )
                )


                _record_dashboard_event(
                    request=request,
                    input_type=(
                        filename_lower.rsplit(
                            ".",
                            1,
                        )[-1].upper()
                        if "."
                        in filename_lower
                        else "FILE"
                    ),
                    filename=filename,
                    security_result={
                        "entities":
                            failed_response[
                                "entities"
                            ],
                        "risk":
                            failed_response[
                                "risk"
                            ],
                        "decision":
                            failed_response[
                                "decision"
                            ],
                        "status_detail":
                            failed_response.get(
                                "error"
                            ),
                    },
                )


                return failed_response


        except (
            ValueError,
            RedactionError,
            DocxRedactionError,
            ImageRedactionError,
        ):

            # FAIL CLOSED:
            # Never return the original file after
            # a failed redaction attempt.
            # Never return an unverified redacted file.

            failed_response = (
                _fail_closed_response(
                    filename,
                    len(file_bytes),
                    security_result,
                    "Could not generate a "
                    "safe version of "
                    "this file — blocked.",
                )
            )


            _record_dashboard_event(
                request=request,
                input_type=(
                    filename_lower.rsplit(
                        ".",
                        1,
                    )[-1].upper()
                    if "."
                    in filename_lower
                    else "FILE"
                ),
                filename=filename,
                security_result={
                    "entities":
                        failed_response[
                            "entities"
                        ],
                    "risk":
                        failed_response[
                            "risk"
                        ],
                    "decision":
                        failed_response[
                            "decision"
                        ],
                    "status_detail":
                        failed_response.get(
                            "error"
                        ),
                },
            )


            return failed_response


    # --------------------------------------------------
    # DASHBOARD EVENT — FINAL DECISION
    # --------------------------------------------------

    event_id, release_token = _record_dashboard_event(
        request=request,
        input_type=(
            filename_lower.rsplit(
                ".",
                1,
            )[-1].upper()
            if "."
            in filename_lower
            else "FILE"
        ),
        filename=filename,
        security_result={
            "entities": response[
                "entities"
            ],
            "risk": response[
                "risk"
            ],
            "decision": response[
                "decision"
            ],
        },
        held_payload=(
            _held_payload_for_file(
                file_bytes,
                filename,
                file.content_type,
            )
            if response["decision"] == "BLOCK"
            else None
        ),
    )

    response["event_id"] = event_id

    if release_token is not None:
        response["release_token"] = release_token


    return response