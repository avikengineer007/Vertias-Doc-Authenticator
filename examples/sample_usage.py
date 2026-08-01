"""Sample programmatic usage of doc-forensics Python library."""

from pathlib import Path
from doc_forensics import (
    ForensicScanner,
    CheckStatus,
    analyze_metadata,
    analyze_ela,
    analyze_copy_move,
    analyze_ocr_consistency,
    analyze_noise
)

def run_individual_module_checks(image_path: str):
    """Example 1: Calling standalone deterministic forensic check modules directly."""
    print(f"--- Running Standalone Module Checks on: {image_path} ---")

    # 1. EXIF Metadata Check
    meta_res = analyze_metadata(image_path)
    print(f"Metadata Status: {meta_res.status} | Score: {meta_res.score} | Reason: {meta_res.explanation}")

    # 2. Error Level Analysis (ELA)
    ela_res = analyze_ela(image_path, quality=90, save_heatmap=True, output_heatmap_dir="./heatmaps")
    print(f"ELA Status:      {ela_res.status} | Score: {ela_res.score} | Heatmap: {ela_res.heatmap_path}")

    # 3. Copy-Move Forgery Detection
    cm_res = analyze_copy_move(image_path)
    print(f"Copy-Move Status: {cm_res.status} | Score: {cm_res.score} | Clusters: {cm_res.details.get('suspicious_clusters_count')}")

    # 4. OCR Font & Field Consistency
    ocr_res = analyze_ocr_consistency(image_path)
    print(f"OCR Status:      {ocr_res.status} | Score: {ocr_res.score} | Flagged Fields: {ocr_res.details.get('flagged_fields_count')}")

    # 5. Sensor Noise Residual Analysis
    noise_res = analyze_noise(image_path, save_heatmap=True, output_heatmap_dir="./heatmaps")
    print(f"Noise Status:    {noise_res.status} | Score: {noise_res.score} | Reason: {noise_res.explanation}")


def run_full_forensic_scanner(image_path: str):
    """Example 2: Using ForensicScanner high-level orchestrator."""
    print(f"\n--- Running Full Forensic Scanner on: {image_path} ---")

    scanner = ForensicScanner(
        save_heatmaps=True,
        output_heatmap_dir="./heatmaps",
        ela_quality=90
    )

    report = scanner.scan(image_path)

    print(f"\nOverall Verdict:    {report.verdict.value}")
    print(f"Overall Risk Score: {round(report.overall_risk_score * 100, 1)}%")
    print(f"\nExecutive Summary:\n{report.summary}")

    # Export report to JSON string
    json_output = report.to_json(indent=2)
    print(f"\nStructured JSON Report Preview (first 300 chars):\n{json_output[:300]}...")


if __name__ == "__main__":
    sample_img = "tests/synthetic_dataset/authentic_passport.jpg"
    if Path(sample_img).exists():
        run_individual_module_checks(sample_img)
        run_full_forensic_scanner(sample_img)
    else:
        print(f"Sample image '{sample_img}' not found. Run 'python -m tests.generate_synthetic_samples' to generate test data.")
