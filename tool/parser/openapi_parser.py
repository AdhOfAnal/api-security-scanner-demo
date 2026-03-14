from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import yaml


class OpenAPIParser:
    """Load OpenAPI documents from JSON or YAML."""

    @staticmethod
    def load(path: str | Path) -> Dict[str, Any]:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"OpenAPI file not found: {file_path}")

        suffix = file_path.suffix.lower()
        # Use utf-8-sig to tolerate BOM-prefixed files exported by some tools/editors.
        text = file_path.read_text(encoding="utf-8-sig")

        if suffix == ".json":
            data = json.loads(text)
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text)
        else:
            raise ValueError(f"Unsupported OpenAPI file type: {suffix}")

        if not isinstance(data, dict) or "paths" not in data:
            raise ValueError("Invalid OpenAPI document: missing 'paths'")

        return data


def list_endpoints(openapi_doc: Dict[str, Any]) -> list[dict[str, str]]:
    endpoints: list[dict[str, str]] = []
    for path, methods in openapi_doc.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method in methods.keys():
            endpoints.append({"method": method.upper(), "path": path})
    return endpoints
