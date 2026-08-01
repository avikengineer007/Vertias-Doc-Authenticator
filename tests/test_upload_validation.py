"""Unit and integration tests for upload validation, non-JPEG ELA adaptation, API server, and temp file auto-cleanup."""

import pytest
from pathlib import Path
from PIL import Image  # type: ignore # pyright: ignore[reportMissingImports]

from doc_forensics.config import VeritasConfig
from doc_forensics.utils.validation import validate_image_file
from doc_forensics.scanner import ForensicScanner
from doc_forensics.report.schema import CheckStatus
from tests.generate_synthetic_samples import generate_authentic_passport, OUTPUT_DIR


@pytest.fixture(scope="module")
def sample_images(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("upload_tests")

    # 1. Valid JPG
    valid_jpg = tmp_dir / "valid_doc.jpg"
    generate_authentic_passport(valid_jpg)

    # 2. Valid PNG
    valid_png = tmp_dir / "valid_doc.png"
    img = Image.new("RGB", (200, 200), color="white")
    img.save(valid_png)

    # 3. Invalid extension TXT
    invalid_txt = tmp_dir / "invalid_doc.txt"
    invalid_txt.write_text("Not an image file")

    # 4. Corrupted JPG (zero byte file)
    corrupted_jpg = tmp_dir / "corrupted_doc.jpg"
    corrupted_jpg.write_bytes(b"Malformed binary image data garbage")

    return {
        "valid_jpg": valid_jpg,
        "valid_png": valid_png,
        "invalid_txt": invalid_txt,
        "corrupted_jpg": corrupted_jpg,
        "tmp_dir": tmp_dir
    }


def test_valid_image_upload(sample_images):
    """Test valid .jpg and .png images pass validation successfully."""
    cfg = VeritasConfig()
    img, fmt = validate_image_file(sample_images["valid_jpg"], config=cfg)
    assert img is not None
    assert fmt.upper() in ("JPEG", "JPG")

    img_png, fmt_png = validate_image_file(sample_images["valid_png"], config=cfg)
    assert img_png is not None
    assert fmt_png.upper() == "PNG"


def test_invalid_file_extension(sample_images):
    """Test invalid file formats (.txt, .pdf) are rejected with clear error message."""
    cfg = VeritasConfig()
    with pytest.raises(ValueError) as exc_info:
        validate_image_file(sample_images["invalid_txt"], config=cfg)

    assert "Invalid file format '.txt'" in str(exc_info.value)
    assert "Allowed formats:" in str(exc_info.value)


def test_oversized_file_rejection(sample_images):
    """Test files exceeding max_file_size_mb are rejected."""
    # Config with 0.001 MB (1 KB) limit
    strict_cfg = VeritasConfig(max_file_size_mb=0.001)

    with pytest.raises(ValueError) as exc_info:
        validate_image_file(sample_images["valid_jpg"], config=strict_cfg)

    assert "exceeds maximum allowed limit" in str(exc_info.value)


def test_corrupted_image_rejection(sample_images):
    """Test corrupted or unreadable images are rejected by Pillow verify()."""
    cfg = VeritasConfig()
    with pytest.raises(ValueError) as exc_info:
        validate_image_file(sample_images["corrupted_jpg"], config=cfg)

    assert "corrupted or not a valid image" in str(exc_info.value).lower()


def test_non_jpeg_ela_graceful_skip(sample_images):
    """Test non-JPEG PNG images gracefully skip ELA check with explicit note."""
    scanner = ForensicScanner(enable_metadata=False, enable_copy_move=False, enable_ocr=False, enable_noise=False)
    report = scanner.scan(sample_images["valid_png"])

    ela_check = report.checks.get("ela")
    assert ela_check is not None
    assert ela_check.status == CheckStatus.INCONCLUSIVE
    assert ela_check.score == 0.0
    assert "ELA check skipped: Image format 'PNG' does not contain JPEG re-compression artifacts" in ela_check.explanation
    assert ela_check.details.get("skipped") is True


def test_api_upload_and_temp_cleanup(sample_images):
    """Test FastAPI POST /scan upload endpoint and verify temp file cleanup."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from doc_forensics.api import create_app

    cfg = VeritasConfig(auto_delete_temp_files=True)
    app = create_app(config=cfg)
    client = TestClient(app)

    # Health check
    h_resp = client.get("/health")
    assert h_resp.status_code == 200
    assert h_resp.json()["status"] == "ok"

    # POST /scan valid image
    with open(sample_images["valid_jpg"], "rb") as f:
        resp = client.post("/scan", files={"file": ("uploaded_passport.jpg", f, "image/jpeg")})

    assert resp.status_code == 200
    report_data = resp.json()
    assert report_data["image_path"] == "uploaded_passport.jpg"
    assert "checks" in report_data

    # POST /scan invalid file extension
    with open(sample_images["invalid_txt"], "rb") as f:
        err_resp = client.post("/scan", files={"file": ("doc.txt", f, "text/plain")})

    assert err_resp.status_code == 400
    assert "Invalid file format" in err_resp.json()["detail"]
