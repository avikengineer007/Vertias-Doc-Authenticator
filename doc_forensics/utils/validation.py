"""Input validation engine for image uploads, file formats, size checks, and image integrity verification."""

from pathlib import Path
from typing import Tuple, Union, Optional
from PIL import Image  # type: ignore # pyright: ignore[reportMissingImports]

from doc_forensics.config import VeritasConfig, load_config


def validate_image_file(
    file_path: Union[str, Path],
    config: Optional[VeritasConfig] = None
) -> Tuple[Image.Image, str]:
    """
    Validate an input image file against configured format, size, and corruption constraints.
    
    Args:
        file_path: Path to input image file.
        config: Optional VeritasConfig instance (loads default if None).
        
    Returns:
        Tuple of (PIL Image object, image format string).
        
    Raises:
        FileNotFoundError: If file path does not exist.
        ValueError: If file extension is invalid, file exceeds size limit, or image is corrupted.
    """
    cfg = config or load_config()
    path = Path(file_path)

    # 1. Existence check
    if not path.is_file():
        raise FileNotFoundError(f"Image file not found: {path}")

    # 2. Extension format check
    ext = path.suffix.lower()
    allowed_exts = [e.lower() for e in cfg.allowed_extensions]
    if ext not in allowed_exts:
        allowed_str = ", ".join(allowed_exts)
        raise ValueError(f"Invalid file format '{ext}'. Allowed formats: {allowed_str}")

    # 3. File size check
    file_size_bytes = path.stat().st_size
    file_size_mb = file_size_bytes / (1024.0 * 1024.0)
    if file_size_mb > cfg.max_file_size_mb:
        raise ValueError(
            f"File size ({round(file_size_mb, 2)} MB) exceeds maximum allowed limit of {cfg.max_file_size_mb} MB"
        )

    # 4. Integrity verification (detect corrupted files)
    try:
        with Image.open(path) as img_verify:
            img_verify.verify()
    except Exception as e:
        raise ValueError(f"File is corrupted or not a valid image: {str(e)}")

    # Load clean PIL image instance
    try:
        pil_img = Image.open(path).convert("RGB")
        img_format = pil_img.format or (ext[1:].upper() if ext.startswith(".") else ext.upper())
        return pil_img, img_format
    except Exception as e:
        raise ValueError(f"Failed to load image file: {str(e)}")
