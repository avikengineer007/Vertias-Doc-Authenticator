import os
from pathlib import Path
from typing import Dict, Any

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter, ExifTags  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

OUTPUT_DIR = Path(__file__).parent / "synthetic_dataset"


def _draw_guilloche_background(draw: ImageDraw.ImageDraw, width: int, height: int) -> None:
    """Draw non-periodic security pattern line curves to simulate ID card background."""
    for i in range(0, width, 12):
        y1 = int(np.sin(i / 15.0) * 20 + np.cos(i / 35.0) * 10 + 25)
        y2 = int(np.cos(i / 18.0) * 25 + height - 25)
        draw.line([(i, y1), (i + 8, y2)], fill=(220, 230, 245), width=1)
    
    for j in range(0, height, 14):
        x1 = int(np.sin(j / 12.0) * 15 + 20)
        x2 = int(np.cos(j / 25.0) * 20 + width - 20)
        draw.line([(x1, j), (x2, j + 10)], fill=(235, 240, 250), width=1)

    # ID Header band
    draw.rectangle([(0, 0), (width, 50)], fill=(30, 60, 120))


def _draw_id_content(draw: ImageDraw.ImageDraw, width: int, height: int) -> None:
    """Draw realistic ID card text fields and photo box."""
    # Header title
    draw.text((20, 12), "REPUBLIC OF PASSPORTS - SPECIMEN ID", fill=(255, 255, 255))

    # Photo box
    draw.rectangle([(20, 70), (140, 210)], fill=(200, 200, 200), outline=(50, 50, 50), width=2)
    draw.ellipse([(55, 95), (105, 145)], fill=(120, 130, 140))  # Head
    draw.ellipse([(35, 150), (125, 220)], fill=(90, 100, 110))   # Shoulders

    # Document text fields
    labels_and_vals = [
        ("SURNAME:", "SMITH"),
        ("GIVEN NAMES:", "JANE ALICE"),
        ("NATIONALITY:", "UTOPIA"),
        ("DOB:", "14 AUG 1988"),
        ("DOCUMENT NO:", "P987654321"),
        ("EXPIRY DATE:", "20 NOV 2030")
    ]

    y_pos = 70
    for label, val in labels_and_vals:
        draw.text((160, y_pos), label, fill=(80, 80, 80))
        draw.text((260, y_pos), val, fill=(10, 10, 10))
        y_pos += 24


def generate_authentic_passport(output_path: Path) -> Path:
    """Generate authentic synthetic passport image with clean EXIF metadata."""
    img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)

    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    # Add realistic clean EXIF metadata
    exif = img.getexif()
    exif[0x010f] = "DocumentScanner Corp"      # Make
    exif[0x0110] = "HD-Scanner 5000"          # Model
    exif[0x9003] = "2024:06:15 10:30:00"      # DateTimeOriginal
    exif[0x0132] = "2024:06:15 10:30:00"      # DateTime (ModifyDate)

    img.save(output_path, quality=95, exif=exif)
    return output_path


def generate_tampered_metadata(output_path: Path) -> Path:
    """Generate image with suspicious editing software signature in EXIF metadata."""
    img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    exif = img.getexif()
    exif[0x0131] = "Adobe Photoshop CC 2023 (Windows)" # Software tag
    exif[0x9003] = "2024:06:15 10:30:00"              # DateTimeOriginal
    exif[0x0132] = "2024:06:01 08:00:00"              # ModifyDate earlier than original

    img.save(output_path, quality=95, exif=exif)
    return output_path


def generate_tampered_ela(output_path: Path) -> Path:
    """Generate image with localized JPEG re-compression patch (ELA tampering)."""
    # 1. Base image saved at high quality 98
    base_img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(base_img)
    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    # 2. Create patch with modified text field, save at low quality 20
    patch_img = Image.new("RGB", (220, 50), color=(250, 252, 255))
    patch_draw = ImageDraw.Draw(patch_img)
    patch_draw.text((10, 15), "EXPIRED - INVALID DOCUMENT", fill=(200, 0, 0))

    import io
    buf = io.BytesIO()
    patch_img.save(buf, format="JPEG", quality=20)
    buf.seek(0)
    recomp_patch = Image.open(buf)

    # Paste low quality patch back onto high quality base image
    base_img.paste(recomp_patch, (160, 110))
    base_img.save(output_path, quality=98)
    return output_path


def generate_tampered_copymove(output_path: Path) -> Path:
    """Generate image with duplicated block region (Copy-Move forgery)."""
    img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    # Crop photo silhouette region and paste duplicate in bottom right
    photo_crop = img.crop((20, 70, 140, 210))
    img.paste(photo_crop, (340, 70))

    img.save(output_path, quality=95)
    return output_path


def generate_tampered_ocr(output_path: Path) -> Path:
    """Generate image with re-typed text field in anomalous font size/stroke width."""
    img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    # Overwrite DOB field with abnormally thick/heavy bold text box
    draw.rectangle([(255, 135), (450, 175)], fill=(250, 252, 255))
    # Simulate extra thick bold stroke glyphs
    for offset_x in range(6):
        for offset_y in range(6):
            draw.text((260 + offset_x, 138 + offset_y), "01 JAN 1960 EXTRA", fill=(0, 0, 0))

    img.save(output_path, quality=95)
    return output_path


def generate_tampered_noise(output_path: Path) -> Path:
    """Generate image with spliced noisy patch (Noise residual tampering)."""
    img = Image.new("RGB", (500, 300), color=(250, 252, 255))
    draw = ImageDraw.Draw(img)
    _draw_guilloche_background(draw, 500, 300)
    _draw_id_content(draw, 500, 300)

    img_arr = np.array(img, dtype=np.float32)
    # Inject heavy gaussian noise into rectangular patch (160, 180) to (320, 260)
    noise = np.random.normal(0, 45.0, size=(80, 160, 3))
    img_arr[180:260, 160:320, :] = np.clip(img_arr[180:260, 160:320, :] + noise, 0, 255)

    tampered = Image.fromarray(img_arr.astype(np.uint8))
    tampered.save(output_path, quality=95)
    return output_path


def generate_all_dataset_samples(target_dir: Path = OUTPUT_DIR) -> Dict[str, Path]:
    """Generate full dataset suite of synthetic authentic & tampered ID cards."""
    target_dir.mkdir(parents=True, exist_ok=True)

    dataset_files = {
        "authentic_passport": generate_authentic_passport(target_dir / "authentic_passport.jpg"),
        "tampered_metadata": generate_tampered_metadata(target_dir / "tampered_metadata.jpg"),
        "tampered_ela": generate_tampered_ela(target_dir / "tampered_ela.jpg"),
        "tampered_copymove": generate_tampered_copymove(target_dir / "tampered_copymove.jpg"),
        "tampered_ocr": generate_tampered_ocr(target_dir / "tampered_ocr.jpg"),
        "tampered_noise": generate_tampered_noise(target_dir / "tampered_noise.jpg"),
    }
    return dataset_files


if __name__ == "__main__":
    files = generate_all_dataset_samples()
    print(f"Generated {len(files)} synthetic dataset samples in: {OUTPUT_DIR}")
    for name, p in files.items():
        print(f" - {name}: {p.name}")
