"""
©AngelaMos | 2026
download_csic.py

CSIC 2010 dataset downloader with progress display and
integrity checking

download_csic fetches normalTrafficTraining.txt, normal
TrafficTest.txt, and anomalousTrafficTest.txt from the
Universidad de la Republica GitLab mirror via httpx
streaming, writing to data/datasets/csic2010/. Skips
files that already exist above MIN_FILE_BYTES (1MB).
Shows download progress (percentage or MB), computes
SHA-256 via _compute_sha256, and warns on suspiciously
small downloads

Connects to:
  ml/data_loader  - downloaded files consumed by
                     parse_csic_file
"""

import hashlib
import logging
import sys
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

DATASET_DIR = Path("data/datasets/csic2010")

BASE_URL = ("https://gitlab.fing.edu.uy"
            "/gsi/web-application-attacks-datasets"
            "/-/raw/master/csic_2010")

FILES = [
    "normalTrafficTraining.txt",
    "normalTrafficTest.txt",
    "anomalousTrafficTest.txt",
]

MIN_FILE_BYTES = 1_000_000


def _compute_sha256(path: Path) -> str:
    """
    Compute SHA-256 hash of a file
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_csic(output_dir: Path = DATASET_DIR, ) -> None:
    """
    Download CSIC 2010 dataset files
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    for filename in FILES:
        dest = output_dir / filename

        if dest.exists() and dest.stat().st_size > MIN_FILE_BYTES:
            logger.info("Skipping %s (already exists)", filename)
            continue

        url = f"{BASE_URL}/{filename}"
        logger.info("Downloading %s", url)
        print(f"Downloading {filename}...")

        try:
            with httpx.stream(
                "GET",
                url,
                follow_redirects=True,
            ) as response:
                response.raise_for_status()
                total = int(
                    response.headers.get("content-length", 0)
                )
                downloaded = 0
                with open(dest, "wb") as f:
                    for chunk in response.iter_bytes(
                        chunk_size=65536
                    ):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            pct = min(
                                downloaded * 100 / total, 100
                            )
                            sys.stdout.write(f"\r  {pct:.0f}%")
                        else:
                            mb = downloaded / 1_048_576
                            sys.stdout.write(f"\r  {mb:.1f} MB")
                        sys.stdout.flush()
            print()
        except Exception as exc:
            logger.error(
                "Failed to download %s: %s",
                filename,
                exc,
            )
            print(f"\nError downloading {filename}: {exc}")
            continue

        size = dest.stat().st_size
        sha = _compute_sha256(dest)
        print(f"  Saved: {dest}"
              f" ({size:,} bytes, sha256={sha[:12]})")

        if size < MIN_FILE_BYTES:
            print(f"  WARNING: {filename} is suspiciously"
                  f" small ({size:,} bytes)")

    print(f"\nDataset directory: {output_dir.resolve()}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    download_csic()
