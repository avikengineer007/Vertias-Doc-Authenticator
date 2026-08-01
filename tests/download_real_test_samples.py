"""Downloader script for fetching open specimen document images for real testing."""

import urllib.request
from pathlib import Path

REAL_DATASET_DIR = Path(__file__).parent.parent / "data" / "real_samples"

# Direct Wikimedia Commons public domain specimen document images
PUBLIC_SAMPLES = {
    "specimen_passport.jpg": "https://upload.wikimedia.org/wikipedia/commons/d/d4/Passport_Specimen.jpg",
    "specimen_eu_id_card.png": "https://upload.wikimedia.org/wikipedia/commons/3/3d/EU_ID_card_specimen.png",
    "specimen_driver_license.jpg": "https://upload.wikimedia.org/wikipedia/commons/e/e4/California_driver_license_specimen.jpg",
}


def download_real_samples() -> Path:
    """Download public specimen document images to data/real_samples/."""
    REAL_DATASET_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading open specimen document test images to: {REAL_DATASET_DIR}")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    for fname, url in PUBLIC_SAMPLES.items():
        out_path = REAL_DATASET_DIR / fname
        if not out_path.exists():
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req) as resp, open(out_path, "wb") as out_f:
                    out_f.write(resp.read())
                print(f" [✓] Downloaded: {fname}")
            except Exception as e:
                print(f" [!] Failed to download {fname}: {e}")
        else:
            print(f" [✓] Existing: {fname}")

    return REAL_DATASET_DIR


if __name__ == "__main__":
    download_real_samples()
