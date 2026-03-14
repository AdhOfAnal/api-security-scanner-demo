from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

import httpx

from tool.engine.runner import run_scan
from tool.report.compare_reports import summarize_report_diff


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def _is_port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def _wait_until_server_ready(base_url: str, timeout_sec: float = 10.0) -> None:
    deadline = time.time() + timeout_sec
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            response = httpx.get(f"{base_url}/openapi.json", timeout=1.0)
            if response.status_code == 200:
                return
        except Exception as exc:  # pragma: no cover - network timing path
            last_error = exc
        time.sleep(0.25)

    raise RuntimeError(f"Testbed did not start in time. Last error: {last_error}")


def run_scan_with_managed_testbed(
    config_path: str | Path,
    fix_users_auth: bool,
    fix_admin_role: bool,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> Dict[str, Any]:
    config_file = Path(config_path)
    if not config_file.is_absolute():
        config_file = PROJECT_ROOT / config_file
    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_file}")

    if _is_port_in_use(host, port):
        raise RuntimeError(
            f"Port {port} is already in use. Stop existing service on {host}:{port} and retry."
        )

    env = os.environ.copy()
    env["FIX_USERS_AUTH"] = "1" if fix_users_auth else "0"
    env["FIX_ADMIN_ROLE"] = "1" if fix_admin_role else "0"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "testbed.app:app",
            "--host",
            host,
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_until_server_ready(f"http://{host}:{port}")
        return run_scan(config_file)
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:  # pragma: no cover - OS timing path
            process.kill()


def load_report(path: str | Path) -> Dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = PROJECT_ROOT / file_path
    if not file_path.exists():
        raise FileNotFoundError(f"Report not found: {file_path}")
    import json

    return json.loads(file_path.read_text(encoding="utf-8"))


def get_diff_summary(
    vulnerable_path: str | Path = "samples/reports/vulnerable_report.json",
    fixed_path: str | Path = "samples/reports/fixed_report.json",
) -> Dict[str, Any]:
    vulnerable = load_report(vulnerable_path)
    fixed = load_report(fixed_path)
    return summarize_report_diff(vulnerable, fixed)
