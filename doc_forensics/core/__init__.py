"""Forensic check modules for doc-forensics."""

from doc_forensics.core.metadata import analyze_metadata
from doc_forensics.core.ela import analyze_ela
from doc_forensics.core.copy_move import analyze_copy_move
from doc_forensics.core.ocr_consistency import analyze_ocr_consistency
from doc_forensics.core.noise_analysis import analyze_noise

__all__ = [
    "analyze_metadata",
    "analyze_ela",
    "analyze_copy_move",
    "analyze_ocr_consistency",
    "analyze_noise",
]
