"""Unit tests for Error Level Analysis (ELA) forensic check module."""

import pytest
from pathlib import Path
from doc_forensics.core.ela import analyze_ela, perform_ela
from doc_forensics.report.schema import CheckStatus
from doc_forensics.utils.image_io import load_image
from tests.generate_synthetic_samples import generate_authentic_passport, generate_tampered_ela, OUTPUT_DIR


@pytest.fixture(scope="module")
def setup_ela_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    auth_p = generate_authentic_passport(OUTPUT_DIR / "test_auth_ela.jpg")
    tamp_p = generate_tampered_ela(OUTPUT_DIR / "test_tamp_ela.jpg")
    return auth_p, tamp_p


def test_perform_ela_basic(setup_ela_dataset):
    auth_p, _ = setup_ela_dataset
    pil_img, _, _ = load_image(auth_p)

    error_2d, scaled_diff, scale = perform_ela(pil_img, quality=90, scale=15.0)
    assert error_2d.ndim == 2
    assert scaled_diff.shape[2] == 3
    assert scale == 15.0


def test_ela_authentic(setup_ela_dataset):
    auth_p, _ = setup_ela_dataset
    result = analyze_ela(auth_p, quality=90)

    assert result.module_name == "ela"
    assert result.status in (CheckStatus.AUTHENTIC, CheckStatus.INCONCLUSIVE)
    assert "mean_error" in result.details


def test_ela_tampered_recompression(setup_ela_dataset):
    _, tamp_p = setup_ela_dataset
    result = analyze_ela(tamp_p, quality=90, save_heatmap=True, output_heatmap_dir=OUTPUT_DIR / "heatmaps")

    assert result.module_name == "ela"
    assert result.status in (CheckStatus.SUSPECTED_TAMPERING, CheckStatus.INCONCLUSIVE)
    assert result.score >= 0.35
    assert result.heatmap_path is not None
    assert Path(result.heatmap_path).exists()
