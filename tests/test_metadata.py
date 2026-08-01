"""Unit tests for metadata forensic check module."""

import pytest
from pathlib import Path
from doc_forensics.core.metadata import analyze_metadata
from doc_forensics.report.schema import CheckStatus
from tests.generate_synthetic_samples import generate_authentic_passport, generate_tampered_metadata, OUTPUT_DIR


@pytest.fixture(scope="module")
def setup_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    auth_p = generate_authentic_passport(OUTPUT_DIR / "test_auth_meta.jpg")
    tamp_p = generate_tampered_metadata(OUTPUT_DIR / "test_tamp_meta.jpg")
    return auth_p, tamp_p


def test_metadata_authentic(setup_dataset):
    auth_p, _ = setup_dataset
    result = analyze_metadata(auth_p)

    assert result.module_name == "metadata"
    assert result.status == CheckStatus.AUTHENTIC
    assert result.score == 0.0
    assert "flagged_software" in result.details
    assert len(result.details["flagged_software"]) == 0


def test_metadata_tampered_software_signature(setup_dataset):
    _, tamp_p = setup_dataset
    result = analyze_metadata(tamp_p)

    assert result.module_name == "metadata"
    assert result.status == CheckStatus.SUSPECTED_TAMPERING
    assert result.score >= 0.65
    assert "photoshop" in result.details["flagged_software"]
    assert "Editing software signature" in result.explanation
