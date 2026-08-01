"""Copy-move forgery detection using keypoint matching and geometric displacement clustering."""

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
    from sklearn.cluster import DBSCAN  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


def detect_copy_move_keypoints(
    gray_img: np.ndarray,
    min_spatial_dist: float = 30.0,
    max_hamming_dist: int = 40,
    min_cluster_size: int = 15
) -> Tuple[List[Tuple[float, float, float, float]], List[Tuple[float, float]], float]:
    """
    Detect copy-move forgery using ORB keypoint extraction and shift-vector DBSCAN clustering.
    
    Args:
        gray_img: Grayscale image numpy array.
        min_spatial_dist: Minimum distance between keypoint pairs to avoid trivial local matches.
        max_hamming_dist: Max ORB descriptor distance threshold.
        min_cluster_size: Minimum number of matched keypoints with identical shift vector to constitute forgery.
        
    Returns:
        Tuple of (list of matched point pairs [(x1,y1,x2,y2)], list of bounding boxes [(x,y,w,h)], score).
    """
    if not HAS_CV2:
        return [], [], 0.0

    # Initialize ORB detector
    orb = cv2.ORB_create(nfeatures=2500, scaleFactor=1.2, nlevels=8)
    keypoints, descriptors = orb.detectAndCompute(gray_img, None)

    if keypoints is None or descriptors is None or len(keypoints) < 10:
        return [], [], 0.0

    # BFMatcher with Hamming distance for ORB
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(descriptors, descriptors, k=10)

    matched_pairs: List[Tuple[float, float, float, float]] = []
    shift_vectors: List[Tuple[float, float]] = []
    points1: List[Tuple[float, float]] = []
    points2: List[Tuple[float, float]] = []

    for match_list in matches:
        if len(match_list) < 2:
            continue
        
        # Filter out self-match (distance 0 at same keypoint index)
        valid_candidates = [m for m in match_list if m.queryIdx != m.trainIdx]
        if len(valid_candidates) < 2:
            continue

        best_m = valid_candidates[0]
        second_m = valid_candidates[1]

        # Lowe's ratio test: genuine copy-move duplicates have significantly closer best match
        if best_m.distance > max_hamming_dist or best_m.distance >= 0.75 * second_m.distance:
            continue

        pt1 = keypoints[best_m.queryIdx].pt
        pt2 = keypoints[best_m.trainIdx].pt

        # Spatial distance constraint
        dx = pt2[0] - pt1[0]
        dy = pt2[1] - pt1[1]
        dist = np.hypot(dx, dy)

        if dist < min_spatial_dist:
            continue

        # Standardize shift vector direction
        if dx < 0 or (dx == 0 and dy < 0):
            shift = (-dx, -dy)
        else:
            shift = (dx, dy)

        matched_pairs.append((pt1[0], pt1[1], pt2[0], pt2[1]))
        shift_vectors.append(shift)
        points1.append(pt1)
        points2.append(pt2)

    if not shift_vectors:
        return [], [], 0.0

    bounding_boxes: List[Tuple[float, float, float, float]] = []
    suspicious_clusters = 0

    # Perform shift-vector clustering to isolate coherent copy-move blocks
    if HAS_SKLEARN and len(shift_vectors) >= min_cluster_size:
        X_shifts = np.array(shift_vectors)
        # Cluster in shift space (eps=12 pixels tolerance in displacement vector)
        db = DBSCAN(eps=12.0, min_samples=min_cluster_size).fit(X_shifts)
        labels = db.labels_

        unique_labels = set(labels) - {-1}
        suspicious_clusters = len(unique_labels)

        for label in unique_labels:
            mask = (labels == label)
            pts_src = np.array(points1)[mask]
            pts_dst = np.array(points2)[mask]

            # Bounding box covering src and dst points of this copy-move block
            all_pts = np.vstack([pts_src, pts_dst])
            min_x, min_y = np.min(all_pts, axis=0)
            max_x, max_y = np.max(all_pts, axis=0)
            w = float(max_x - min_x)
            h = float(max_y - min_y)

            img_h, img_w = gray_img.shape[:2]
            # Genuine block copy-move forgery is localized block, not full-canvas lines or tiny single-line font matches
            if w < img_w * 0.70 and h < img_h * 0.70 and (w * h) > 1200:
                bounding_boxes.append((float(min_x), float(min_y), w, h))
    else:
        # Simple histogram binning fallback if sklearn is absent
        dx_arr = np.array([s[0] for s in shift_vectors])
        dy_arr = np.array([s[1] for s in shift_vectors])
        # Quantize shifts into 15px bins
        bins = {}
        for idx, (dx, dy) in enumerate(zip(dx_arr, dy_arr)):
            key = (int(dx // 15), int(dy // 15))
            bins.setdefault(key, []).append(idx)
        
        img_h, img_w = gray_img.shape[:2]
        for key, indices in bins.items():
            if len(indices) >= min_cluster_size:
                all_pts = []
                for i in indices:
                    all_pts.append(points1[i])
                    all_pts.append(points2[i])
                pts_arr = np.array(all_pts)
                min_x, min_y = np.min(pts_arr, axis=0)
                max_x, max_y = np.max(pts_arr, axis=0)
                w, h = float(max_x - min_x), float(max_y - min_y)
                if w < img_w * 0.70 and h < img_h * 0.70 and (w * h) > 1200:
                    suspicious_clusters += 1
                    bounding_boxes.append((float(min_x), float(min_y), w, h))

    # Compute risk score based on cluster count and match density
    score = 0.0
    if suspicious_clusters > 0:
        score = float(np.clip(0.50 + 0.15 * suspicious_clusters + 0.01 * len(matched_pairs), 0.50, 1.0))

    return matched_pairs, bounding_boxes, score


def analyze_copy_move(
    image_path: Union[str, Path],
    min_spatial_dist: float = 30.0,
    min_cluster_size: int = 15
) -> CheckResult:
    """
    Analyze image for copy-move duplication forgery.
    
    Args:
        image_path: Path to target document image file.
        min_spatial_dist: Minimum spatial distance between matched keypoint pairs.
        min_cluster_size: Minimum number of matched keypoints sharing displacement vector.
        
    Returns:
        CheckResult containing status, risk score, bounding boxes, and explanation.
    """
    start_time = time.time()
    path = Path(image_path)

    try:
        _, _, gray_arr = load_image(path)
    except Exception as e:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="copy_move",
            status=CheckStatus.INCONCLUSIVE,
            score=0.5,
            explanation=f"Failed to load image for copy-move analysis: {str(e)}",
            details={},
            execution_time_ms=exec_ms
        )

    if not HAS_CV2:
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="copy_move",
            status=CheckStatus.INCONCLUSIVE,
            score=0.5,
            explanation="OpenCV (cv2) library unavailable for keypoint extraction.",
            details={"has_cv2": False},
            execution_time_ms=exec_ms
        )

    matched_pairs, bounding_boxes, score = detect_copy_move_keypoints(
        gray_arr,
        min_spatial_dist=min_spatial_dist,
        min_cluster_size=min_cluster_size
    )

    exec_ms = (time.time() - start_time) * 1000.0

    details: Dict[str, Any] = {
        "matched_keypoint_pairs": len(matched_pairs),
        "suspicious_clusters_count": len(bounding_boxes),
        "bounding_boxes": [
            {"x": round(b[0], 1), "y": round(b[1], 1), "w": round(b[2], 1), "h": round(b[3], 1)}
            for b in bounding_boxes
        ]
    }

    if score >= 0.55 and len(bounding_boxes) > 0:
        status = CheckStatus.SUSPECTED_TAMPERING
        explanation = (
            f"Copy-move duplication detected: {len(bounding_boxes)} coherent duplicated region cluster(s) "
            f"found with {len(matched_pairs)} matched keypoint pairs."
        )
    elif len(matched_pairs) > 50:
        status = CheckStatus.INCONCLUSIVE
        explanation = (
            f"Elevated keypoint matches ({len(matched_pairs)} pairs) without coherent geometric cluster displacement."
        )
    else:
        status = CheckStatus.AUTHENTIC
        explanation = "No evidence of copy-move block duplication detected across document keypoints."

    return CheckResult(
        module_name="copy_move",
        status=status,
        score=score,
        explanation=explanation,
        details=details,
        execution_time_ms=exec_ms
    )
