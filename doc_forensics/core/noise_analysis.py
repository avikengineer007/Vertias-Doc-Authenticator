"""Sensor noise residual and local noise variance inconsistency forensic module."""

import time
from pathlib import Path
from typing import Dict, Any, Union, Optional
from PIL import Image
import numpy as np

from doc_forensics.utils.image_io import load_image, save_heatmap_overlay
from doc_forensics.report.schema import CheckResult, CheckStatus

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from scipy.ndimage import median_filter, gaussian_filter
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


def extract_noise_residual(gray_img: np.ndarray) -> np.ndarray:
    """
    Extract high-frequency noise residual by subtracting low-pass filtered image from original.
    
    Args:
        gray_img: Grayscale uint8 image.
        
    Returns:
        2D float32 noise residual array.
    """
    img_float = gray_img.astype(np.float32)

    if HAS_CV2:
        # Use median blur to preserve sharp edges while smoothing sensor noise
        denoised = cv2.medianBlur(gray_img, 3).astype(np.float32)
    elif HAS_SCIPY:
        denoised = median_filter(img_float, size=3)
    else:
        # Simple 3x3 uniform box filter fallback
        kernel = np.ones((3, 3), dtype=np.float32) / 9.0
        # Simple padding convolution
        pad = np.pad(img_float, ((1, 1), (1, 1)), mode='reflect')
        denoised = np.zeros_like(img_float)
        for i in range(3):
            for j in range(3):
                denoised += pad[i:i+img_float.shape[0], j:j+img_float.shape[1]] * kernel[i, j]

    noise_residual = np.abs(img_float - denoised)
    return noise_residual


def analyze_noise(
    image_path: Union[str, Path],
    patch_size: int = 32,
    anomaly_threshold: float = 3.0,
    save_heatmap: bool = False,
    output_heatmap_dir: Optional[Union[str, Path]] = None
) -> CheckResult:
    """
    Analyze image for sensor noise residual inconsistencies (splicing detection).
    
    Args:
        image_path: Path to target document image file.
        patch_size: Grid block size for local noise variance comparison.
        anomaly_threshold: Z-score threshold for anomalous noise patch detection.
        save_heatmap: If True, save a heatmap visual overlay image to disk.
        output_heatmap_dir: Directory where heatmap image will be saved.
        
    Returns:
        CheckResult containing status, noise variance score, heatmap path, and explanation.
    """
    start_time = time.time()
    path = Path(image_path)

    try:
        _, rgb_arr, gray_arr = load_image(path)
    except Exception as e:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="noise_analysis",
            status=CheckStatus.INCONCLUSIVE,
            score=0.5,
            explanation=f"Failed to load image for noise analysis: {str(e)}",
            details={},
            execution_time_ms=exec_ms
        )

    h, w = gray_arr.shape[:2]
    noise_residual = extract_noise_residual(gray_arr)

    # Grid patch noise variance calculation
    grid_h = max(1, h // patch_size)
    grid_w = max(1, w // patch_size)

    patch_variances = []
    for i in range(grid_h):
        for j in range(grid_w):
            patch = noise_residual[i * patch_size : (i + 1) * patch_size, j * patch_size : (j + 1) * patch_size]
            var = float(np.var(patch))
            patch_variances.append(var)

    patch_var_arr = np.array(patch_variances)
    mean_var = float(np.mean(patch_var_arr))
    std_var = float(np.std(patch_var_arr))
    max_var = float(np.max(patch_var_arr))

    if std_var > 1e-4:
        z_scores = (patch_var_arr - mean_var) / std_var
        anomalous_patches = int(np.sum(z_scores > anomaly_threshold))
        max_z_score = float(np.max(z_scores))
    else:
        anomalous_patches = 0
        max_z_score = 0.0

    total_patches = len(patch_variances)
    anomalous_ratio = anomalous_patches / max(1, total_patches)

    # Noise score formulation
    noise_score = 0.0
    if max_z_score > anomaly_threshold and anomalous_ratio > 0.005:
        noise_score += 0.50
    if anomalous_ratio > 0.02:
        noise_score += 0.35
    if (max_var / (mean_var + 1e-5)) > 5.0:
        noise_score += 0.15

    noise_score = float(np.clip(noise_score, 0.0, 1.0))

    heatmap_path_str = None
    if save_heatmap:
        out_dir = Path(output_heatmap_dir) if output_heatmap_dir else path.parent / "forensic_heatmaps"
        out_path = out_dir / f"{path.stem}_noise_heatmap.png"
        saved = save_heatmap_overlay(rgb_arr, noise_residual, out_path)
        heatmap_path_str = str(saved)

    details: Dict[str, Any] = {
        "mean_noise_variance": round(mean_var, 3),
        "std_noise_variance": round(std_var, 3),
        "max_noise_variance": round(max_var, 3),
        "max_z_score": round(max_z_score, 3),
        "anomalous_patches_count": anomalous_patches,
        "anomalous_patch_ratio": round(anomalous_ratio, 4),
        "total_patches": total_patches
    }

    exec_ms = (time.time() - start_time) * 1000.0

    if noise_score >= 0.55 and anomalous_patches >= 2:
        status = CheckStatus.SUSPECTED_TAMPERING
        explanation = (
            f"Splicing/noise inconsistency detected: {anomalous_patches} region(s) exhibit anomalous sensor noise "
            f"variance ({round(max_z_score, 2)} std dev above document mean)."
        )
    elif noise_score >= 0.35 or anomalous_patches == 1:
        status = CheckStatus.INCONCLUSIVE
        explanation = (
            f"Moderate noise variance variation across patches (Max z-score: {round(max_z_score, 2)}). "
            f"Requires secondary confirmation."
        )
    else:
        status = CheckStatus.AUTHENTIC
        explanation = "Sensor noise statistics are consistent across all document regions."

    return CheckResult(
        module_name="noise_analysis",
        status=status,
        score=noise_score,
        explanation=explanation,
        details=details,
        execution_time_ms=exec_ms,
        heatmap_path=heatmap_path_str
    )
