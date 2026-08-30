from __future__ import annotations

import argparse
import sys
from dataclasses import replace
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
        description=(
            "\u516c\u958b\u30d5\u30a3\u30c3\u30b7\u30f3\u30b0URL\u3092Docker\u5185"
            "\u30d6\u30e9\u30a6\u30b6\u3067\u958b\u304d\u3001\u30b9\u30af\u30ea\u30fc\u30f3"
            "\u30b7\u30e7\u30c3\u30c8\u3068\u78ba\u8a8d\u7528CSV\u3092\u4fdd\u5b58"
            "\u3057\u307e\u3059\u3002"
        )
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="\u89b3\u5bdf\u7528\u306e\u8a2d\u5b9a\u30d5\u30a1\u30a4\u30eb\u3067\u3059\u3002"
        "\u901a\u5e38\u306f\u6307\u5b9a\u4e0d\u8981\u3067\u3059\u3002",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="\u9032\u6357\u30d0\u30fc\u3092\u8868\u793a\u3057\u307e\u305b\u3093\u3002",
    )
    args = parser.parse_args()

    config = load_observer_config(args.config)
    if args.no_progress:
        config = replace(config, progress=False)
    run_dir = observe_urls(config)
    print("")
    print("\u51fa\u529b\u30d5\u30a1\u30a4\u30eb")
    print(f"- {run_dir / 'review.csv'}")
    print(f"- {run_dir / 'observation_report.json'}")
    print(f"- {run_dir / 'screenshots'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
