"""Unit tests for Copy-Move Forgery Detection module."""

import pytest
from pathlib import Path
from doc_forensics.core.copy_move import analyze_copy_move
from doc_forensics.report.schema import CheckStatus
from tests.generate_synthetic_samples import generate_authentic_passport, generate_tampered_copymove, OUTPUT_DIR


@pytest.fixture(scope="module")
def setup_copymove_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    auth_p = generate_authentic_passport(OUTPUT_DIR / "test_auth_cm.jpg")
    tamp_p = generate_tampered_copymove(OUTPUT_DIR / "test_tamp_cm.jpg")
    return auth_p, tamp_p


def test_copy_move_authentic(setup_copymove_dataset):
    auth_p, _ = setup_copymove_dataset
    result = analyze_copy_move(auth_p)

    assert result.module_name == "copy_move"
    assert result.status in (CheckStatus.AUTHENTIC, CheckStatus.INCONCLUSIVE)
    assert result.score == 0.0
    assert len(result.details["bounding_boxes"]) == 0


def test_copy_move_tampered_duplication(setup_copymove_dataset):
    _, tamp_p = setup_copymove_dataset
    result = analyze_copy_move(tamp_p, min_cluster_size=4)

    assert result.module_name == "copy_move"
    assert result.status == CheckStatus.SUSPECTED_TAMPERING
    assert result.score >= 0.50
    assert result.details["suspicious_clusters_count"] > 0
    assert len(result.details["bounding_boxes"]) > 0
