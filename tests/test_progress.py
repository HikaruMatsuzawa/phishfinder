import unittest
from types import SimpleNamespace
from unittest.mock import patch

from phishfinder.progress import progress_bar


class ProgressTests(unittest.TestCase):
    def test_progress_bar_can_be_disabled(self):
        items = [1, 2, 3]

        self.assertIs(items, progress_bar(items, desc="test", enabled=False))

    def test_progress_bar_is_iterable_without_callers_knowing_implementation(self):
        items = [1, 2, 3]

        self.assertEqual([1, 2, 3], list(progress_bar(items, desc="test", enabled=False)))

    def test_progress_bar_uses_stdout_to_keep_logs_ordered(self):
        calls = []

        def fake_tqdm(items, **kwargs):
            calls.append(kwargs)
            return items

        with patch.dict("sys.modules", {"tqdm": SimpleNamespace(tqdm=fake_tqdm)}):
            self.assertEqual([1, 2, 3], list(progress_bar([1, 2, 3], desc="DNS test")))

        self.assertEqual("件", calls[0]["unit"])
        self.assertIsNotNone(calls[0]["file"])
        self.assertTrue(calls[0]["dynamic_ncols"])


if __name__ == "__main__":
    unittest.main()
