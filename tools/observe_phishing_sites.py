from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishfinder.phishing_observer import load_observer_config, observe_urls


DEFAULT_CONFIG = ROOT / "phishing_capture" / "config.json"


def configure_text_output() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")


def main() -> int:
    configure_text_output()
    parser = argparse.ArgumentParser(
        description="公開フィッシングURLをDocker内ブラウザで開き、スクリーンショットと確認用CSVを保存します。"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="観察用の設定ファイルです。通常は指定不要です。",
    )
    args = parser.parse_args()

    config = load_observer_config(args.config)
    run_dir = observe_urls(config)
    print("")
    print("出力ファイル")
    print(f"- {run_dir / 'review.csv'}")
    print(f"- {run_dir / 'observation_report.json'}")
    print(f"- {run_dir / 'screenshots'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
