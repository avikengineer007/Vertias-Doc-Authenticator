from pathlib import Path
from typing import Dict, Any, Tuple, Union, Optional

try:
    from PIL import Image, ExifTags  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import cv2  # type: ignore # pyright: ignore[reportMissingImports]
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False


def load_image(image_path: Union[str, Path]) -> Tuple[Image.Image, np.ndarray, np.ndarray]:
    """
    Load an image from disk and return PIL Image, RGB numpy array, and Grayscale numpy array.
    
    Args:
        image_path: Path to the image file.
        
    Returns:
        Tuple of (PIL Image in RGB, RGB numpy array, Grayscale numpy array).
    """
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image file not found: {path}")

    pil_img = Image.open(path).convert("RGB")
    rgb_arr = np.array(pil_img, dtype=np.uint8)

    if HAS_CV2:
        gray_arr = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2GRAY)
    else:
        # Weighted luminance conversion
        gray_arr = np.dot(rgb_arr[..., :3], [0.2989, 0.5870, 0.1140]).astype(np.uint8)

    return pil_img, rgb_arr, gray_arr


def extract_raw_exif(image_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Extract EXIF metadata tags as a human-readable dictionary.
    
    Args:
        image_path: Path to the image file.
        
    Returns:
        Dictionary mapping EXIF tag names to stringified values.
    """
    path = Path(image_path)
    exif_dict: Dict[str, Any] = {}

    try:
        with Image.open(path) as img:
            getexif_fn = getattr(img, "_getexif", None)
            raw_exif = getexif_fn() if callable(getexif_fn) else None
            if not raw_exif or not hasattr(raw_exif, "items"):
                return exif_dict

            for tag_id, value in raw_exif.items():  # type: ignore # pyright: ignore[reportAttributeAccessIssue]
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                # Clean up binary/byte values for readability
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace").strip("\x00")
                    except Exception:
                        value = str(value)
                exif_dict[tag_name] = value
    except Exception:
        pass

    return exif_dict


def create_heatmap_overlay(
    original_rgb: np.ndarray,
    heatmap: np.ndarray,
    alpha: float = 0.5
) -> np.ndarray:
    """
    Overlay a 2D float heatmap (values [0.0, 1.0]) onto an RGB image.
    
    Args:
        original_rgb: Base image array (H, W, 3) in uint8.
        heatmap: 2D error array (H, W) in float or uint8.
        alpha: Blending weight of the heatmap (0.0 to 1.0).
        
    Returns:
        RGB numpy array with heatmap overlay.
    """
    h, w = original_rgb.shape[:2]

    # Normalize heatmap to 0..255
    heatmap_norm = np.clip(heatmap, 0, None)
    max_val = np.max(heatmap_norm)
    if max_val > 0:
        heatmap_norm = (heatmap_norm / max_val * 255.0).astype(np.uint8)
    else:
        heatmap_norm = heatmap_norm.astype(np.uint8)

    # Resize heatmap if shape mismatch
    if heatmap_norm.shape != (h, w):
        if HAS_CV2:
            heatmap_norm = cv2.resize(heatmap_norm, (w, h), interpolation=cv2.INTER_LINEAR)
        else:
            pil_hm = Image.fromarray(heatmap_norm).resize((w, h), Image.Resampling.BILINEAR)
            heatmap_norm = np.array(pil_hm)

    if HAS_CV2:
        # Apply JET colormap in BGR, convert to RGB
        heatmap_colored = cv2.applyColorMap(heatmap_norm, cv2.COLORMAP_JET)
        heatmap_colored_rgb = cv2.cvtColor(heatmap_colored, cv2.COLOR_BGR2RGB)
    else:
        # Manual colormap fallback (Red overlay based on intensity)
        heatmap_colored_rgb = np.zeros_like(original_rgb)
        heatmap_colored_rgb[..., 0] = heatmap_norm  # Red channel
        heatmap_colored_rgb[..., 1] = (heatmap_norm * 0.3).astype(np.uint8)

    blended = (original_rgb * (1.0 - alpha) + heatmap_colored_rgb * alpha).astype(np.uint8)
    return blended


def save_heatmap_overlay(
    original_rgb: np.ndarray,
    heatmap: np.ndarray,
    output_path: Union[str, Path],
    alpha: float = 0.5
) -> Path:
    """
    Generate and save a heatmap overlay image to disk.
    
    Args:
        original_rgb: Base image array.
        heatmap: 2D error array.
        output_path: Target save file path.
        alpha: Blending ratio.
        
    Returns:
        Path object of saved heatmap image.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    overlay = create_heatmap_overlay(original_rgb, heatmap, alpha=alpha)
    Image.fromarray(overlay).save(out)
    return out
