# Veritas — DocumentID Tampering Detection Library & Web App

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

**Veritas** (`doc-forensics`) is a local-first Python security library, CLI tool, and interactive web application for detecting tampering in scanned identity documents and ID cards (passports, driver's licenses, national IDs, etc.). 

Unlike generic machine learning classifiers that return a single opaque confidence score, Veritas is built on **explainable, deterministic forensic checks**. Every verdict produces structured, auditable evidence traceable to specific physical and digital forgery signals.

---

## Core Features & Architecture

1. **Deterministic Core**: Standalone forensic modules for **EXIF Metadata**, **Error Level Analysis (ELA)**, **Copy-Move Forgery**, **OCR Font Consistency**, and **Sensor Noise Analysis**.
2. **Local Web Upload Interface**: Minimal FastAPI web endpoint (`POST /scan`) with a drag-and-drop web UI (`veritas serve`). Uploaded temp files are auto-cleaned after scanning to respect document privacy.
3. **Robust Input Validation**: Strict validation layer for file extensions (`.jpg`, `.jpeg`, `.png`, `.tiff`, `.bmp`), maximum file size limits (default 25 MB), and corruption verification via Pillow `verify()`.
4. **Non-JPEG ELA Graceful Adaptation**: Automatically detects image format and gracefully skips JPEG re-compression checks on PNG/TIFF/BMP files with an explicit report explanation.
5. **Fail-Closed Conservative Defaults**: Inconclusive or stripped data returns `INCONCLUSIVE` rather than false authentic verdicts.
6. **CLI-First**: Terminal UIs (`veritas scan`) formatted with `rich` panels, status badges, and visual heatmaps.

---

## Installation

### 1. Clone Repository & Install Package

```bash
git clone https://github.com/avikengineer007/Vertias-Doc-Authenticator.git
cd Vertias-Doc-Authenticator

# Install in editable mode
pip install -e .
```

### 2. Optional System Dependency: Tesseract OCR

Tesseract is optional (OpenCV contour fallback handles glyph geometric profiling if absent). For full text extraction:

- **Windows (PowerShell)**: `winget install UB-Mannheim.TesseractOCR`
- **Linux (Ubuntu/Debian)**: `sudo apt update && sudo apt install -y tesseract-ocr`
- **macOS**: `brew install tesseract`

---

## Quick Start & Usage

### 1. Interactive Web Interface (`veritas serve`)

Launch the local web server and open the interactive web UI in your browser:

```bash
veritas serve --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser to drag & drop any document image for instant forensic analysis.

---

### 2. Command Line Interface (`veritas scan`)

```bash
# Scan a document image with rich terminal table output
veritas scan data/real_samples/authentic_passport.jpg

# Scan with structured JSON export and visual heatmap overlays
veritas scan data/real_samples/tampered_ela.jpg --output-json report.json --save-heatmaps --heatmap-dir ./heatmaps
```

---

### 3. Programmatic Python API

```python
from doc_forensics import ForensicScanner

# Initialize scanner
scanner = ForensicScanner(save_heatmaps=True, output_heatmap_dir="./heatmaps")

# Scan document image
report = scanner.scan("data/real_samples/authentic_passport.jpg")

print("Verdict:", report.verdict.value)
print("Overall Risk Score:", report.overall_risk_score)
print(report.to_json(indent=2))
```

---

### 4. Precision / Recall Benchmark

```bash
# Run precision, recall, and F1-score evaluation against synthetic ground-truth dataset
veritas benchmark data/real_samples
```

---

## Configuration (`veritas.toml`)

Veritas can be customized via `veritas.toml` in your project directory:

```toml
[server]
host = "127.0.0.1"
port = 8000

[upload]
max_file_size_mb = 25.0
allowed_extensions = [".jpg", ".jpeg", ".png", ".tiff", ".bmp"]
auto_delete_temp_files = true

[forensics]
ela_quality = 90
```

---

## Detection Modules & Methodology

1. **EXIF Metadata (`doc_forensics.core.metadata`)**: Parses EXIF headers to flag editing software signatures (`Photoshop`, `GIMP`, `Canva`, `Photopea`, etc.) and timestamp anomalies.
2. **Error Level Analysis (`doc_forensics.core.ela`)**: Re-compresses JPEG images at 90% quality and measures localized pixel error variance against background mean. Non-JPEG images are gracefully skipped.
3. **Copy-Move Detection (`doc_forensics.core.copy_move`)**: Extracts keypoints using ORB, applies Lowe's ratio test, and clusters displacement vectors with DBSCAN to isolate duplicated regions while filtering background pattern noise.
4. **OCR Font Consistency (`doc_forensics.core.ocr_consistency`)**: Measures stroke width distributions (Distance Transform), glyph heights, and baseline alignment across extracted text fields.
5. **Noise Analysis (`doc_forensics.core.noise_analysis`)**: Isolates high-frequency sensor noise residuals and flags localized variance splicing anomalies.

---

## Automated Test Suite

Run `pytest` to execute all 21 unit, integration, validation, and API tests:

```bash
pytest
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
