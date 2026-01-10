"""Generate PNG test images with metadata."""

import random
from pathlib import Path

from PIL import Image, PngImagePlugin


dest_dir = Path("tests/assets/test_images")

# Generate 45 PNG images with various metadata
for i in range(1, 46):
    # Create a simple colored image
    r, g, b = random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)
    img = Image.new("RGB", (100, 100), color = (r, g, b))

    # Add PNG text metadata
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("Author", f"Test Author {i}")
    pnginfo.add_text("Description", f"Test image number {i} for metadata scrubbing")
    pnginfo.add_text("Software", "Python PIL Test Generator")
    pnginfo.add_text("Copyright", f"Copyright 2024 Test {i}")
    pnginfo.add_text("Creation Time", f"2024-01-{i % 28 + 1:02d}")

    # Save with metadata
    filename = dest_dir / f"generated_test_{i:02d}.png"
    img.save(filename, pnginfo = pnginfo)

print("Generated 45 PNG images with metadata")
print(f"Total PNG count: {len(list(dest_dir.glob('*.png')))}")
