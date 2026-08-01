"""Font and field consistency analysis using OCR and stroke/glyph geometry."""

import time
from pathlib import Path
from typing import Dict, Any, Union, List, Tuple, Optional

try:
    import numpy as np  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from doc_forensics.utils.image_io import load_image
from doc_forensics.report.schema import CheckResult, CheckStatus

try:
    import cv2  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    import pytesseract  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_PYTESSERACT = True
except ImportError:
    HAS_PYTESSERACT = False


def _compute_stroke_width(bin_roi: np.ndarray) -> float:
    """Compute average stroke width of a binarized text ROI using distance transform."""
    if not HAS_CV2 or bin_roi.size == 0:
        return 0.0
    
    # Text pixels are foreground (255)
    fg = (bin_roi > 0).astype(np.uint8)
    if np.sum(fg) == 0:
        return 0.0

    dist = cv2.distanceTransform(fg, cv2.DIST_L2, 3)
    # Local skeleton peaks represent half-stroke widths
    non_zero = dist[dist > 0]
    if len(non_zero) == 0:
        return 0.0
    
    # 2x mean radius = average stroke width
    return float(2.0 * np.mean(non_zero))


def extract_word_boxes(gray_img: np.ndarray) -> List[Dict[str, Any]]:
    """
    Extract word bounding boxes and metrics using pytesseract (or OpenCV contours fallback).
    """
    boxes: List[Dict[str, Any]] = []

    if HAS_PYTESSERACT:
        try:
            data = pytesseract.image_to_data(gray_img, output_type=pytesseract.Output.DICT)
            n_boxes = len(data["text"])
            for i in range(n_boxes):
                text = str(data["text"][i]).strip()
                conf = int(data["conf"][i]) if data["conf"][i] != "-1" else 0
                if len(text) > 0 and conf > 30:
                    x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                    boxes.append({
                        "text": text,
                        "box": (x, y, w, h),
                        "conf": conf
                    })
        except Exception:
            pass

    # Fallback using OpenCV morphological text line detection if pytesseract returns empty
    if not boxes and HAS_CV2:
        # Otsu threshold
        _, thresh = cv2.threshold(gray_img, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

        # Morphological close to group adjacent characters
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (10, 3))
        dilated = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)

        contours, _ = cv2.findContours(dilated, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in contours:
            x, y, w, h = cv2.boundingRect(cnt)
            # Filter out tiny noise and full-page frames
            img_h, img_w = gray_img.shape[:2]
            if 10 <= h <= img_h * 0.4 and 15 <= w <= img_w * 0.8:
                boxes.append({
                    "text": "[GLYPH_FIELD]",
                    "box": (x, y, w, h),
                    "conf": 80
                })

    return boxes


def analyze_ocr_consistency(
    image_path: Union[str, Path],
    max_z_score_threshold: float = 2.5
) -> CheckResult:
    """
    Analyze document fields for font/stroke width inconsistencies across text fields.
    
    Args:
        image_path: Path to target document image file.
        max_z_score_threshold: Z-score threshold above which a field font metric is considered anomalous.
        
    Returns:
        CheckResult containing status, risk score, flagged fields, and explanation.
    """
    start_time = time.time()
    path = Path(image_path)

    try:
        _, rgb_arr, gray_arr = load_image(path)
    except Exception as e:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="ocr_consistency",
            status=CheckStatus.INCONCLUSIVE,
            score=0.5,
            explanation=f"Failed to load image for OCR font analysis: {str(e)}",
            details={},
            execution_time_ms=exec_ms
        )

    word_boxes = extract_word_boxes(gray_arr)

    if len(word_boxes) < 3:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="ocr_consistency",
            status=CheckStatus.INCONCLUSIVE,
            score=0.3,
            explanation="Insufficient text fields detected to establish document font profile baseline.",
            details={"word_count": len(word_boxes)},
            execution_time_ms=exec_ms
        )

    field_metrics = []
    for b in word_boxes:
        x, y, w, h = b["box"]
        roi = gray_arr[y:y+h, x:x+w]

        if HAS_CV2 and roi.size > 0:
            _, bin_roi = cv2.threshold(roi, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
            stroke_width = _compute_stroke_width(bin_roi)
        else:
            stroke_width = 0.0

        char_height = float(h)
        field_metrics.append({
            "text": b["text"],
            "box": b["box"],
            "height": char_height,
            "stroke_width": stroke_width
        })

    # Filter fields with valid stroke width
    valid_strokes = [fm["stroke_width"] for fm in field_metrics if fm["stroke_width"] > 0]
    heights = [fm["height"] for fm in field_metrics]

    if not valid_strokes:
        # Fall back to character height profiling if stroke width unavailable
        mean_h = float(np.mean(heights))
        std_h = float(np.std(heights))
        metric_values = np.array(heights)
        mean_val, std_val = mean_h, std_h
        metric_key = "height"
    else:
        metric_values = np.array([fm["stroke_width"] for fm in field_metrics])
        mean_val = float(np.mean(metric_values))
        std_val = float(np.std(metric_values))
        metric_key = "stroke_width"

    flagged_fields = []
    if std_val > 1e-3:
        z_scores = (metric_values - mean_val) / std_val
        for idx, z in enumerate(z_scores):
            if abs(z) > max_z_score_threshold:
                fm = field_metrics[idx]
                flagged_fields.append({
                    "text": fm["text"],
                    "box": fm["box"],
                    "metric_key": metric_key,
                    "value": round(fm[metric_key], 2),
                    "z_score": round(float(z), 2)
                })

    exec_ms = (time.time() - start_time) * 1000.0

    score = 0.0
    if flagged_fields:
        score = float(np.clip(0.65 + 0.10 * len(flagged_fields), 0.65, 1.0))
        status = CheckStatus.SUSPECTED_TAMPERING
        explanation = (
            f"Font/field inconsistency detected: {len(flagged_fields)} text field(s) deviate significantly "
            f"(z-score > {max_z_score_threshold}) from document font profile baseline."
        )
    else:
        status = CheckStatus.AUTHENTIC
        explanation = (
            f"Font and stroke width metrics are uniform across all {len(field_metrics)} analyzed text fields."
        )

    details: Dict[str, Any] = {
        "analyzed_fields_count": len(field_metrics),
        "dominant_metric": metric_key,
        "mean_metric_val": round(mean_val, 2),
        "std_metric_val": round(std_val, 2),
        "flagged_fields_count": len(flagged_fields),
        "flagged_fields": flagged_fields
    }

    return CheckResult(
        module_name="ocr_consistency",
        status=status,
        score=score,
        explanation=explanation,
        details=details,
        execution_time_ms=exec_ms
    )
