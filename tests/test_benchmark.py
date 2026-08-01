"""Benchmark test suite runner."""

from doc_forensics.utils.benchmark import run_benchmark
from tests.generate_synthetic_samples import OUTPUT_DIR


def test_benchmark_execution():
    """Unit test runner for benchmark evaluation."""
    metrics = run_benchmark(OUTPUT_DIR)
    assert "metadata" in metrics
    assert "ela" in metrics
    assert "copy_move" in metrics
    assert "ocr_consistency" in metrics
    assert "noise_analysis" in metrics


if __name__ == "__main__":
    run_benchmark(OUTPUT_DIR)
