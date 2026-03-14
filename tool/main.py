import argparse
from pathlib import Path

from tool.engine.runner import run_scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Run API security scan")
    parser.add_argument(
        "--config",
        default="configs/targets.yaml",
        help="Path to target configuration YAML",
    )
    args = parser.parse_args()

    report = run_scan(Path(args.config))
    print(f"Scan completed. Findings: {len(report.get('findings', []))}")
    print(f"Report: {report.get('meta', {}).get('report_path', 'N/A')}")


if __name__ == "__main__":
    main()
