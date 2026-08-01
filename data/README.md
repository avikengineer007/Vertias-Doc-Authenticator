# Document ID Forensic Datasets (`data/`)

This directory contains documentation and instructions for acquiring, generating, and benchmarking document ID tampering datasets for security forensics testing.

## synthetic_dataset (Built-in Self-Made Test Set)

The library includes an automated synthetic test set generator in `tests/generate_synthetic_samples.py`. It creates realistic synthetic ID cards with ground-truth tampered variants:

| Sample Name | Target Forensic Check | Description |
| :--- | :--- | :--- |
| `authentic_passport.jpg` | Baseline (All) | Authentic specimen passport with clean EXIF and uniform features |
| `tampered_metadata.jpg` | `metadata` | Injected Adobe Photoshop EXIF signature and timestamp anomaly |
| `tampered_ela.jpg` | `ela` | Localized JPEG re-compression patch (edited date/photo area) |
| `tampered_copymove.jpg` | `copy_move` | Block copy-move duplication of photo/signature block |
| `tampered_ocr.jpg` | `ocr_consistency` | Retyped date field in anomalous thick bold font/stroke width |
| `tampered_noise.jpg` | `noise_analysis` | Spliced patch containing high sensor noise residual |

To generate or refresh the synthetic test dataset, run:
```bash
python -m tests.generate_synthetic_samples
```

## Public & Academic Datasets for Document Forensics

For comprehensive evaluation on large-scale real-world document datasets, we recommend the following open datasets:

1. **MIDV-2020 (Mobile Identity Documents Dataset)**
   - **Description**: Contains 1000+ identity documents (passports, ID cards, driver's licenses) captured under varied illuminations and devices.
   - **Access**: [MIDV-2020 GitHub Repository](https://github.com/SmartEngines/midv-500)
   - **Usage**: Verify licensing constraints before benchmark runs.

2. **FindIt Document Forgery Dataset**
   - **Description**: Benchmark dataset specifically designed for document copy-move and splicing forgery detection.
   - **Access**: [FindIt Evaluation Suite](https://findit-dataset.org)

3. **CASIA Image Tampering Detection Dataset (v1.0 & v2.0)**
   - **Description**: Standard benchmark for ELA, copy-move, and splicing noise analysis.
