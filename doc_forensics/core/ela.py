import io
import time
from pathlib import Path
from typing import Dict, Any, Union, Optional, Tuple

try:
    from PIL import Image  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from doc_forensics.utils.image_io import load_image, save_heatmap_overlay
from doc_forensics.report.schema import CheckResult, CheckStatus


def perform_ela(
    pil_img: Image.Image,
    quality: int = 90,
    scale: float = 15.0
) -> Tuple[np.ndarray, np.ndarray, float]:
    """
    Perform Error Level Analysis by re-compressing at `quality` and computing absolute pixel difference.
    
    Args:
        pil_img: Base PIL Image object.
        quality: JPEG compression quality level (0-100).
        scale: Error intensity scaling factor.
        
    Returns:
        Tuple of (2D float error heatmap, RGB scaled error image, max patch ratio).
    """
    # Save image in memory as JPEG with target quality level
    buffer = io.BytesIO()
    pil_img.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)

    recompressed_img = Image.open(buffer).convert("RGB")

    orig_arr = np.array(pil_img, dtype=np.float32)
    recomp_arr = np.array(recompressed_img, dtype=np.float32)

    # Compute absolute RGB difference
    abs_diff = np.abs(orig_arr - recomp_arr)
    # Average across RGB channels to produce 2D error matrix
    error_2d = np.mean(abs_diff, axis=2)

    scaled_diff_rgb = np.clip(abs_diff * scale, 0, 255).astype(np.uint8)

    return error_2d, scaled_diff_rgb, scale


def analyze_ela(
    image_path: Union[str, Path],
    quality: int = 90,
    patch_size: int = 16,
    anomaly_threshold: float = 3.2,
    save_heatmap: bool = False,
    output_heatmap_dir: Optional[Union[str, Path]] = None
) -> CheckResult:
    """
    Analyze image using Error Level Analysis to detect localized JPEG re-compression anomalies.
    
    Args:
        image_path: Path to target document image.
        quality: JPEG quality for re-compression baseline (default 90).
        patch_size: Grid block size for regional error variance analysis.
        anomaly_threshold: Standard deviations above mean to flag an anomalous patch.
        save_heatmap: If True, save a heatmap visual overlay image to disk.
        output_heatmap_dir: Directory where heatmap image will be stored.
        
    Returns:
        CheckResult containing ELA max regional error score, status, and explanation.
    """
    start_time = time.time()
    path = Path(image_path)

    try:
        pil_img, rgb_arr, _ = load_image(path)
    except Exception as e:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="ela",
            status=CheckStatus.INCONCLUSIVE,
            score=0.5,
            explanation=f"Failed to load image for ELA: {str(e)}",
            details={},
            execution_time_ms=exec_ms
        )

    # Inspect format for JPEG re-compression artifacts compatibility
    img_fmt = (pil_img.format or path.suffix.strip(".").upper()).upper()
    if img_fmt not in ("JPEG", "JPG"):
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="ela",
            status=CheckStatus.INCONCLUSIVE,
            score=0.0,
            explanation=f"ELA check skipped: Image format '{img_fmt}' does not contain JPEG re-compression artifacts.",
            details={"skipped": True, "format": img_fmt},
            execution_time_ms=exec_ms
        )

    h, w = rgb_arr.shape[:2]
    error_2d, _, _ = perform_ela(pil_img, quality=quality)

    # Grid patch analysis
    grid_h = max(1, h // patch_size)
    grid_w = max(1, w // patch_size)
    patch_errors = []

    for i in range(grid_h):
        for j in range(grid_w):
            patch = error_2d[i * patch_size : (i + 1) * patch_size, j * patch_size : (j + 1) * patch_size]
            patch_errors.append(float(np.mean(patch)))

    patch_errors_arr = np.array(patch_errors)
    mean_error = float(np.mean(patch_errors_arr))
    std_error = float(np.std(patch_errors_arr))
    max_error = float(np.max(patch_errors_arr))

    # Identify anomalous patches significantly higher than background average
    if std_error > 1e-4:
        z_scores = (patch_errors_arr - mean_error) / std_error
        anomalous_patches = int(np.sum(z_scores > anomaly_threshold))
        max_z_score = float(np.max(z_scores))
    else:
        anomalous_patches = 0
        max_z_score = 0.0

    # Calculate overall ELA risk score (0.0 to 1.0)
    peak_ratio = (max_error / (mean_error + 1e-5))
    total_patches = len(patch_errors)
    anomalous_ratio = anomalous_patches / max(1, total_patches)

    ela_score = 0.0
    if peak_ratio > 2.8 and max_z_score > 2.5:
        ela_score += 0.45
    if anomalous_ratio > 0.005 or anomalous_patches >= 1:
        ela_score += 0.35
    if max_error > 15.0:
        ela_score += 0.20

    ela_score = float(np.clip(ela_score, 0.0, 1.0))

    heatmap_path_str = None
    if save_heatmap:
        out_dir = Path(output_heatmap_dir) if output_heatmap_dir else path.parent / "forensic_heatmaps"
        out_path = out_dir / f"{path.stem}_ela_heatmap.png"
        saved = save_heatmap_overlay(rgb_arr, error_2d, out_path)
        heatmap_path_str = str(saved)

    details: Dict[str, Any] = {
        "quality_level": quality,
        "mean_error": round(mean_error, 3),
        "std_error": round(std_error, 3),
        "max_error": round(max_error, 3),
        "peak_ratio": round(peak_ratio, 3),
        "max_z_score": round(max_z_score, 3),
        "anomalous_patches_count": anomalous_patches,
        "anomalous_patch_ratio": round(anomalous_ratio, 4),
        "total_patches": total_patches
    }

    exec_ms = (time.time() - start_time) * 1000.0

    if ela_score >= 0.40 and (anomalous_patches > 0 or peak_ratio > 3.2):
        explanation = (
            f"Localized JPEG compression anomaly detected: {anomalous_patches} region(s) exhibit error levels "
            f"{round(max_z_score, 2)} std dev above background mean (Peak ratio: {round(peak_ratio, 2)}x)."
        )
        status = CheckStatus.SUSPECTED_TAMPERING
    elif ela_score >= 0.25:
        explanation = (
            f"Moderate ELA error variance detected (Max error: {round(max_error, 2)}, Peak ratio: {round(peak_ratio, 2)}x). "
            f"Inconclusive without secondary check confirmation."
        )
        status = CheckStatus.INCONCLUSIVE
    else:
        explanation = (
            f"Error Level Analysis shows uniform compression levels across document (Peak ratio: {round(peak_ratio, 2)}x)."
        )
        status = CheckStatus.AUTHENTIC

    return CheckResult(
        module_name="ela",
        status=status,
        score=ela_score,
        explanation=explanation,
        details=details,
        execution_time_ms=exec_ms,
        heatmap_path=heatmap_path_str
    )
