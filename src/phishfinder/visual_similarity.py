from __future__ import annotations

from pathlib import Path


def image_average_hash(path: Path, size: int = 8) -> int:
    from PIL import Image

    with Image.open(path) as image:
        pixels = list(image.convert("L").resize((size, size)).getdata())
    average = sum(pixels) / len(pixels)
    value = 0
    for pixel in pixels:
        value = (value << 1) | int(pixel >= average)
    return value


def hash_similarity(left: int, right: int, bits: int = 64) -> float:
    distance = (left ^ right).bit_count()
    return max(0.0, 1.0 - distance / bits)


def screenshot_similarity(left: Path, right: Path) -> float:
    try:
        left_hash = image_average_hash(left)
        right_hash = image_average_hash(right)
    except OSError:
        return 0.0
    return hash_similarity(left_hash, right_hash)
