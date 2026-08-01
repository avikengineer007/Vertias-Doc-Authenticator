"""Configuration loader for Veritas doc-forensics."""

from pathlib import Path
from typing import List, Optional, Union
from pydantic import BaseModel, Field

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore # pyright: ignore[reportMissingImports]
    except ImportError:
        tomllib = None  # type: ignore


class VeritasConfig(BaseModel):
    """Veritas library and server configuration model."""
    host: str = Field("127.0.0.1", description="Default bind host for API server")
    port: int = Field(8000, description="Default bind port for API server")
    max_file_size_mb: float = Field(25.0, description="Maximum allowed file size in MB")
    allowed_extensions: List[str] = Field(
        default_factory=lambda: [".jpg", ".jpeg", ".png", ".tiff", ".bmp"],
        description="List of allowed image file extensions"
    )
    auto_delete_temp_files: bool = Field(True, description="Auto-delete temporary files after processing")
    ela_quality: int = Field(90, description="JPEG quality for Error Level Analysis")


def load_config(config_path: Optional[Union[str, Path]] = None) -> VeritasConfig:
    """
    Load Veritas configuration from veritas.toml file, with sane defaults.
    
    Args:
        config_path: Optional path to veritas.toml file.
        
    Returns:
        VeritasConfig instance.
    """
    path = Path(config_path) if config_path else Path("veritas.toml")

    if path.is_file() and tomllib:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            
            server_cfg = data.get("server", {})
            upload_cfg = data.get("upload", {})
            forensic_cfg = data.get("forensics", {})

            return VeritasConfig(
                host=server_cfg.get("host", "127.0.0.1"),
                port=server_cfg.get("port", 8000),
                max_file_size_mb=float(upload_cfg.get("max_file_size_mb", 25.0)),
                allowed_extensions=[
                    ext if ext.startswith(".") else f".{ext}"
                    for ext in upload_cfg.get("allowed_extensions", [".jpg", ".jpeg", ".png", ".tiff", ".bmp"])
                ],
                auto_delete_temp_files=bool(upload_cfg.get("auto_delete_temp_files", True)),
                ela_quality=int(forensic_cfg.get("ela_quality", 90))
            )
        except Exception:
            pass

    return VeritasConfig()
