from __future__ import annotations

import io
from pathlib import Path

from PIL import Image

from extraction.image_ocr import extract_image
from redact.image_mapping import map_entity_text_to_regions
from redact.image_redact import (
    ImageRedactionError,
    redact_and_verify_image,
    redact_image_regions,
    verify_redacted_image_bytes,
)


BASE_DIR = Path(
    __file__
).resolve().parent

REAL_IMAGE = (
    BASE_DIR / "AI_Guardian_OCR_Real_1.png"
)

BASELINE_IMAGE = (
    BASE_DIR / "AI_Guardian_OCR_Test.png"
)

TARGET_PHONE = "555-123-4567"


def get_phone_span(
    image_path: Path,
) -> tuple[int, int, str]:
    result = extract_image(
        image_path.read_bytes()
    )

    start = result.full_text.index(
        TARGET_PHONE
    )

    end = start + len(
        TARGET_PHONE
    )

    return (
        start,
        end,
        TARGET_PHONE,
    )


def test_single_region_redaction() -> None:
    assert REAL_IMAGE.exists()

    entity_match = get_phone_span(
        REAL_IMAGE
    )

    result = redact_and_verify_image(
        REAL_IMAGE.read_bytes(),
        [entity_match],
    )

    assert result.redacted_bytes
    assert result.mime_type == "image/png"
    assert result.extension == ".png"

    verification = extract_image(
        result.redacted_bytes
    )

    assert TARGET_PHONE not in (
        verification.full_text
    )

    print(
        "6.4.4 single-region pixel redaction: PASS"
    )


def test_sensitive_value_removed_from_pixels(
) -> None:
    assert REAL_IMAGE.exists()

    entity_match = get_phone_span(
        REAL_IMAGE
    )

    result = redact_and_verify_image(
        REAL_IMAGE.read_bytes(),
        [entity_match],
    )

    with Image.open(
        io.BytesIO(
            result.redacted_bytes
        )
    ) as image:

        image.load()

        assert image.format == "PNG"

        pixels = image.convert(
            "RGB"
        )

        black_pixels = 0

        for pixel in pixels.crop(
            (
                55,
                30,
                165,
                55,
            )
        ).getdata():

            if pixel == (
                0,
                0,
                0,
            ):
                black_pixels += 1

        assert black_pixels > 0

    print(
        "6.4.4 opaque pixel replacement: PASS"
    )


def test_multiple_region_redaction() -> None:
    assert BASELINE_IMAGE.exists()

    original_bytes = (
        BASELINE_IMAGE.read_bytes()
    )

    result = extract_image(
        original_bytes
    )

    phone_start = result.full_text.index(
        TARGET_PHONE
    )

    phone_end = (
        phone_start
        + len(TARGET_PHONE)
    )

    confidential = (
        "CONFIDENTIAL"
    )

    confidential_start = (
        result.full_text.index(
            confidential
        )
    )

    confidential_end = (
        confidential_start
        + len(confidential)
    )

    redacted = redact_and_verify_image(
        original_bytes,
        [
            (
                phone_start,
                phone_end,
                TARGET_PHONE,
            ),
            (
                confidential_start,
                confidential_end,
                confidential,
            ),
        ],
    )

    verification = extract_image(
        redacted.redacted_bytes
    )

    assert TARGET_PHONE not in (
        verification.full_text
    )

    assert confidential not in (
        verification.full_text
    )

    print(
        "6.4.4 multiple sensitive regions: PASS"
    )


def test_mapping_and_redaction_consistency() -> None:
    assert REAL_IMAGE.exists()

    source_bytes = (
        REAL_IMAGE.read_bytes()
    )

    ocr_result = extract_image(
        source_bytes
    )

    mapped = map_entity_text_to_regions(
        ocr_result.full_text,
        ocr_result.regions,
        TARGET_PHONE,
    )

    assert len(mapped) == 1

    redacted = redact_image_regions(
        source_bytes,
        mapped,
    )

    assert redacted.redacted_bytes

    verify_redacted_image_bytes(
        redacted.redacted_bytes,
        [TARGET_PHONE],
    )

    print(
        "6.4.4 mapping-to-redaction contract: PASS"
    )


def test_verification_failure_is_fail_closed() -> None:
    assert REAL_IMAGE.exists()

    source_bytes = (
        REAL_IMAGE.read_bytes()
    )

    failed = False

    try:
        verify_redacted_image_bytes(
            source_bytes,
            [TARGET_PHONE],
        )

    except ImageRedactionError:
        failed = True

    assert failed, (
        "Verification should have failed because "
        "the original image still contains the phone number."
    )

    print(
        "6.4.4 verification failure fail-closed: PASS"
    )


def test_invalid_empty_image_rejected() -> None:
    failed = False

    try:
        redact_image_regions(
            b"",
            [],
        )

    except ImageRedactionError:
        failed = True

    assert failed

    print(
        "6.4.4 empty image rejection: PASS"
    )


def test_invalid_no_entity_rejected() -> None:
    assert REAL_IMAGE.exists()

    failed = False

    try:
        redact_and_verify_image(
            REAL_IMAGE.read_bytes(),
            [],
        )

    except ImageRedactionError:
        failed = True

    assert failed

    print(
        "6.4.4 missing entity rejection: PASS"
    )


def main() -> None:
    test_single_region_redaction()

    test_sensitive_value_removed_from_pixels()

    test_multiple_region_redaction()

    test_mapping_and_redaction_consistency()

    test_verification_failure_is_fail_closed()

    test_invalid_empty_image_rejected()

    test_invalid_no_entity_rejected()

    print(
        "6.4.4 IMAGE REDACTION + VERIFICATION: PASS"
    )


if __name__ == "__main__":
    main()