from __future__ import annotations

from pathlib import Path

from extraction.image_ocr import (
    OCRRegion,
    extract_image,
)


BASE_DIR = Path(__file__).resolve().parent

REAL_IMAGE = (
    BASE_DIR / "AI_Guardian_OCR_Real_1.png"
)

BASELINE_IMAGE = (
    BASE_DIR / "AI_Guardian_OCR_Test.png"
)

TARGET_PHONE = "555-123-4567"


def test_real_screenshot_extraction() -> None:
    assert REAL_IMAGE.exists(), (
        f"Missing fixture: {REAL_IMAGE}"
    )

    result = extract_image(
        REAL_IMAGE.read_bytes()
    )

    assert TARGET_PHONE in result.full_text, (
        "Sensitive phone number was not found "
        "in OCR full_text."
    )

    assert result.regions, (
        "OCR returned no regions."
    )

    phone_regions = [
        region
        for region in result.regions
        if region.text == TARGET_PHONE
    ]

    assert len(phone_regions) == 1, (
        "Expected exactly one OCR region "
        "for the test phone number."
    )

    phone = phone_regions[0]

    assert isinstance(
        phone,
        OCRRegion,
    )

    assert phone.width > 0
    assert phone.height > 0
    assert phone.confidence >= 0

    print(
        "6.4.2 real screenshot extraction: PASS"
    )

    print(
        "6.4.2 phone target detection: PASS"
    )

    print(
        "6.4.2 phone bounding box: PASS"
    )


def test_baseline_extraction() -> None:
    assert BASELINE_IMAGE.exists(), (
        f"Missing fixture: {BASELINE_IMAGE}"
    )

    result = extract_image(
        BASELINE_IMAGE.read_bytes()
    )

    assert "Guardian" in result.full_text
    assert "OCR" in result.full_text
    assert "Test" in result.full_text
    assert "Customer" in result.full_text
    assert "Phone:" in result.full_text
    assert TARGET_PHONE in result.full_text
    assert "CONFIDENTIAL" in result.full_text
    assert "Status:" in result.full_text
    assert "externally" in result.full_text

    assert len(result.regions) >= 10

    print(
        "6.4.2 baseline extraction: PASS"
    )


def test_corrupted_image_rejected() -> None:
    corrupted = b"this is not a valid image"

    try:
        extract_image(
            corrupted
        )
    except ValueError:
        print(
            "6.4.2 corrupted image handling: PASS"
        )
        return

    raise AssertionError(
        "Corrupted image was not rejected."
    )


def test_empty_image_rejected() -> None:
    try:
        extract_image(
            b""
        )
    except ValueError:
        print(
            "6.4.2 empty image handling: PASS"
        )
        return

    raise AssertionError(
        "Empty image was not rejected."
    )


def main() -> None:
    test_real_screenshot_extraction()

    test_baseline_extraction()

    test_corrupted_image_rejected()

    test_empty_image_rejected()

    print(
        "6.4.2 IMAGE OCR ADAPTER: PASS"
    )


if __name__ == "__main__":
    main()