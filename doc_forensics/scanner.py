"""High-level ForensicScanner orchestrating all document ID tampering checks."""

from pathlib import Path
from typing import Dict, Any, Union, List, Optional

from doc_forensics.config import VeritasConfig, load_config
from doc_forensics.utils.validation import validate_image_file
from doc_forensics.utils.image_io import extract_raw_exif
from doc_forensics.core.metadata import analyze_metadata
from doc_forensics.core.ela import analyze_ela
from doc_forensics.core.copy_move import analyze_copy_move
from doc_forensics.core.ocr_consistency import analyze_ocr_consistency
from doc_forensics.core.noise_analysis import analyze_noise
from doc_forensics.report.schema import CheckResult, DocumentReport
from doc_forensics.report.verdict import VerdictAggregator


class ForensicScanner:
    """
    Main programmatic engine for running document ID tampering detection checks.
    
    Usage:
        scanner = ForensicScanner(save_heatmaps=True, output_heatmap_dir="./heatmaps")
        report = scanner.scan("passport.jpg")
        print(report.verdict)
        print(report.to_json())
    """

    def __init__(
        self,
        config: Optional[VeritasConfig] = None,
        save_heatmaps: bool = False,
        output_heatmap_dir: Optional[Union[str, Path]] = None,
        ela_quality: Optional[int] = None,
        enable_metadata: bool = True,
        enable_ela: bool = True,
        enable_copy_move: bool = True,
        enable_ocr: bool = True,
        enable_noise: bool = True
    ):
        self.config = config or load_config()
        self.save_heatmaps = save_heatmaps
        self.output_heatmap_dir = Path(output_heatmap_dir) if output_heatmap_dir else None
        self.ela_quality = ela_quality if ela_quality is not None else self.config.ela_quality
        self.enable_metadata = enable_metadata
        self.enable_ela = enable_ela
        self.enable_copy_move = enable_copy_move
        self.enable_ocr = enable_ocr
        self.enable_noise = enable_noise

    def scan(self, image_path: Union[str, Path]) -> DocumentReport:
        """
        Run all enabled forensic detection modules on target document image.
        
        Args:
            image_path: Path to target document image file.
            
        Returns:
            DocumentReport containing overall verdict, individual check results, and metadata summary.
        """
        path = Path(image_path)
        
        # 0. Validate image format, size, and corruption status
        validate_image_file(path, config=self.config)

        results: List[CheckResult] = []

        # Extract metadata summary
        raw_exif = extract_raw_exif(path)
        metadata_summary = {
            "file_name": path.name,
            "file_size_kb": round(path.stat().st_size / 1024.0, 2),
            "exif_tags_count": len(raw_exif),
            "software_tag": raw_exif.get("Software"),
            "datetime_original": raw_exif.get("DateTimeOriginal"),
            "camera_make": raw_exif.get("Make"),
            "camera_model": raw_exif.get("Model"),
        }

        # 1. Metadata analysis
        if self.enable_metadata:
            results.append(analyze_metadata(path))

        # 2. Error Level Analysis (ELA)
        if self.enable_ela:
            results.append(analyze_ela(
                path,
                quality=self.ela_quality,
                save_heatmap=self.save_heatmaps,
                output_heatmap_dir=self.output_heatmap_dir
            ))

        # 3. Copy-Move Forgery Detection
        if self.enable_copy_move:
            results.append(analyze_copy_move(path))

        # 4. OCR Font/Field Consistency
        if self.enable_ocr:
            results.append(analyze_ocr_consistency(path))

        # 5. Sensor Noise Residual Analysis
        if self.enable_noise:
            results.append(analyze_noise(
                path,
                save_heatmap=self.save_heatmaps,
                output_heatmap_dir=self.output_heatmap_dir
            ))

        report = VerdictAggregator.aggregate(
            image_path=str(path),
            results=results,
            metadata_summary=metadata_summary
        )

        return report
