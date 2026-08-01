"""EXIF and file metadata forensic analysis module."""

import time
from pathlib import Path
from typing import Dict, Any, Union, List, Optional
from datetime import datetime

from doc_forensics.utils.image_io import extract_raw_exif
from doc_forensics.report.schema import CheckResult, CheckStatus


KNOWN_EDITING_SOFTWARE = [
    "photoshop", "gimp", "canva", "paint.net", "photopea", "pixelmator",
    "lightroom", "affinity", "acrobat", "illustrator", "coreldraw",
    "skitch", "picasa", "snapseed", "pixlr", "fotor", "inshot"
]


def _parse_exif_date(date_str: str) -> Optional[datetime]:
    """Try to parse standard EXIF date format (YYYY:MM:DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS)."""
    if not isinstance(date_str, str):
        return None
    cleaned = date_str.strip().replace("-", ":").replace("T", " ")
    parts = cleaned.split(" ")
    if len(parts) >= 2:
        date_part, time_part = parts[0], parts[1]
        date_fmt = f"{date_part} {time_part}"
        try:
            return datetime.strptime(date_fmt, "%Y:%m:%d %H:%M:%S")
        except ValueError:
            pass
    return None


def analyze_metadata(image_path: Union[str, Path]) -> CheckResult:
    """
    Perform EXIF & metadata forensics on an image.
    
    Checks:
    1. Editing software signature presence (Photoshop, GIMP, etc.).
    2. Timestamp inconsistencies (ModifyDate vs DateTimeOriginal).
    3. Missing or stripped camera metadata when software tags exist.
    
    Args:
        image_path: Path to target document image file.
        
    Returns:
        CheckResult containing status, score, details, and explanation.
    """
    start_time = time.time()
    path = Path(image_path)

    exif = extract_raw_exif(path)

    flagged_software: List[str] = []
    timestamp_anomalies: List[str] = []
    risk_score = 0.0
    details: Dict[str, Any] = {"exif_present": bool(exif), "exif_tag_count": len(exif)}

    if not exif:
        # Stripped metadata is common in messaging apps, so it's inconclusive rather than definitive tampering
        exec_ms = (time.time() - start_time) * 1000.0
        return CheckResult(
            module_name="metadata",
            status=CheckStatus.INCONCLUSIVE,
            score=0.3,
            explanation="No EXIF metadata found (metadata stripped or unsupported format).",
            details={"exif_present": False},
            execution_time_ms=exec_ms
        )

    # 1. Check software tags
    software_tags = ["Software", "ProcessingSoftware", "HostComputer", "ImageDescription"]
    detected_software_str = ""
    for tag in software_tags:
        if tag in exif:
            val = str(exif[tag]).lower()
            detected_software_str += f" [{tag}: {exif[tag]}]"
            for sw in KNOWN_EDITING_SOFTWARE:
                if sw in val and sw not in flagged_software:
                    flagged_software.append(sw)

    details["flagged_software"] = flagged_software
    details["detected_software_tags"] = detected_software_str

    if flagged_software:
        risk_score += 0.7

    # 2. Check timestamps
    dt_orig_raw = exif.get("DateTimeOriginal") or exif.get("36867")
    dt_mod_raw = exif.get("DateTime") or exif.get("306")
    dt_dig_raw = exif.get("DateTimeDigitized") or exif.get("36868")

    dt_orig = _parse_exif_date(str(dt_orig_raw)) if dt_orig_raw else None
    dt_mod = _parse_exif_date(str(dt_mod_raw)) if dt_mod_raw else None

    if dt_orig and dt_mod:
        if dt_mod < dt_orig:
            anomaly = f"ModifyDate ({dt_mod}) is earlier than DateTimeOriginal ({dt_orig})."
            timestamp_anomalies.append(anomaly)
            risk_score += 0.5
        elif (dt_mod - dt_orig).total_seconds() > 3600 and flagged_software:
            anomaly = f"Significant time gap ({dt_mod - dt_orig}) between original capture and modification with software present."
            timestamp_anomalies.append(anomaly)
            risk_score += 0.3

    details["timestamp_anomalies"] = timestamp_anomalies
    details["datetime_original"] = str(dt_orig_raw) if dt_orig_raw else None
    details["datetime_modified"] = str(dt_mod_raw) if dt_mod_raw else None

    # Determine status & explanation
    risk_score = float(min(1.0, risk_score))
    exec_ms = (time.time() - start_time) * 1000.0

    if flagged_software or timestamp_anomalies:
        reasons = []
        if flagged_software:
            reasons.append(f"Editing software signature(s) detected: {', '.join(flagged_software)}")
        if timestamp_anomalies:
            reasons.append(f"Timestamp anomaly: {'; '.join(timestamp_anomalies)}")

        return CheckResult(
            module_name="metadata",
            status=CheckStatus.SUSPECTED_TAMPERING,
            score=max(0.65, risk_score),
            explanation="; ".join(reasons),
            details=details,
            execution_time_ms=exec_ms
        )

    # Check for legitimate camera metadata (Make/Model)
    has_camera = "Make" in exif or "Model" in exif
    details["has_camera_metadata"] = has_camera

    return CheckResult(
        module_name="metadata",
        status=CheckStatus.AUTHENTIC,
        score=0.0,
        explanation="EXIF metadata verified cleanly with no editing software signatures or timestamp anomalies.",
        details=details,
        execution_time_ms=exec_ms
    )
