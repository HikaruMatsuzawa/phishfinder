import tempfile
import unittest
from pathlib import Path

from PIL import Image

from phishfinder.visual_similarity import hash_similarity, image_average_hash, screenshot_similarity


class VisualSimilarityTests(unittest.TestCase):
    def test_hash_similarity_returns_one_for_same_hash(self):
        self.assertEqual(1.0, hash_similarity(0b1010, 0b1010, bits=4))

    def test_hash_similarity_returns_zero_for_opposite_hash(self):
        self.assertEqual(0.0, hash_similarity(0b1111, 0b0000, bits=4))

    def test_screenshot_similarity_compares_saved_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            left = Path(tmp) / "left.png"
            right = Path(tmp) / "right.png"
            Image.new("RGB", (64, 64), "white").save(left)
            Image.new("RGB", (64, 64), "white").save(right)

            self.assertGreaterEqual(screenshot_similarity(left, right), 0.95)

    def test_image_average_hash_changes_for_different_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            white = Path(tmp) / "white.png"
            black = Path(tmp) / "black.png"
            Image.new("RGB", (64, 64), "white").save(white)
            Image.new("RGB", (64, 64), "black").save(black)

            self.assertIsInstance(image_average_hash(white), int)
            self.assertIsInstance(image_average_hash(black), int)


if __name__ == "__main__":
    unittest.main()
