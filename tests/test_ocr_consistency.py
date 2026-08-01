"""Unit tests for OCR Font/Field Consistency module."""

import pytest
from pathlib import Path
from doc_forensics.core.ocr_consistency import analyze_ocr_consistency
from doc_forensics.report.schema import CheckStatus
from tests.generate_synthetic_samples import generate_authentic_passport, generate_tampered_ocr, OUTPUT_DIR


@pytest.fixture(scope="module")
def setup_ocr_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    auth_p = generate_authentic_passport(OUTPUT_DIR / "test_auth_ocr.jpg")
    tamp_p = generate_tampered_ocr(OUTPUT_DIR / "test_tamp_ocr.jpg")
    return auth_p, tamp_p


def test_ocr_consistency_authentic(setup_ocr_dataset):
    auth_p, _ = setup_ocr_dataset
    result = analyze_ocr_consistency(auth_p)

    assert result.module_name == "ocr_consistency"
    assert result.status in (CheckStatus.AUTHENTIC, CheckStatus.INCONCLUSIVE)


def test_ocr_consistency_tampered_retyped_font(setup_ocr_dataset):
    _, tamp_p = setup_ocr_dataset
    result = analyze_ocr_consistency(tamp_p, max_z_score_threshold=1.8)

    assert result.module_name == "ocr_consistency"
    assert result.status in (CheckStatus.SUSPECTED_TAMPERING, CheckStatus.INCONCLUSIVE)
    assert result.score >= 0.30
