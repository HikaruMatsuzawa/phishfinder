import unittest
from pathlib import Path


class DockerConfigTests(unittest.TestCase):
    def test_dockerfile_runs_through_run_py_as_low_privilege_user(self):
        text = Path("Dockerfile").read_text(encoding="utf-8")

        self.assertIn("FROM mcr.microsoft.com/playwright/python:", text)
        self.assertIn("USER pwuser", text)
        self.assertIn('ENTRYPOINT ["python", "run.py"]', text)

    def test_compose_mounts_data_and_reports(self):
        text = Path("docker-compose.yml").read_text(encoding="utf-8")

        self.assertIn("./config.json:/app/config.json", text)
        self.assertIn("./data:/app/data", text)
        self.assertIn("./reports:/app/reports", text)
        self.assertIn("user: pwuser", text)

    def test_dockerignore_excludes_local_virtual_environment(self):
        text = Path(".dockerignore").read_text(encoding="utf-8")

        self.assertIn(".venv/", text)
        self.assertIn("reports/", text)


if __name__ == "__main__":
    unittest.main()
