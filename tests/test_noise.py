"""Unit tests for Noise Residual Analysis module."""

import pytest
from pathlib import Path
from doc_forensics.core.noise_analysis import analyze_noise
from doc_forensics.report.schema import CheckStatus
from tests.generate_synthetic_samples import generate_authentic_passport, generate_tampered_noise, OUTPUT_DIR


@pytest.fixture(scope="module")
def setup_noise_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    auth_p = generate_authentic_passport(OUTPUT_DIR / "test_auth_noise.jpg")
    tamp_p = generate_tampered_noise(OUTPUT_DIR / "test_tamp_noise.jpg")
    return auth_p, tamp_p


def test_noise_authentic(setup_noise_dataset):
    auth_p, _ = setup_noise_dataset
    result = analyze_noise(auth_p)

    assert result.module_name == "noise_analysis"
    assert result.status in (CheckStatus.AUTHENTIC, CheckStatus.INCONCLUSIVE)


def test_noise_tampered_splicing(setup_noise_dataset):
    _, tamp_p = setup_noise_dataset
    result = analyze_noise(tamp_p, save_heatmap=True, output_heatmap_dir=OUTPUT_DIR / "heatmaps")

    assert result.module_name == "noise_analysis"
    assert result.status in (CheckStatus.SUSPECTED_TAMPERING, CheckStatus.INCONCLUSIVE)
    assert result.score >= 0.35
    assert result.heatmap_path is not None
    assert Path(result.heatmap_path).exists()
