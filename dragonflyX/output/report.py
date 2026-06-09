"""Report generation and case management."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

type ReportFormat = Literal["json", "txt"]

CASES_DIR = Path.home() / ".dragonflyX" / "cases"
REPORTS_DIR = Path.home() / ".dragonflyX" / "reports"


def _serialize(result: Any) -> dict:
    """Serialize a result to dict."""
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")
    if isinstance(result, dict):
        return result
    return {"data": str(result)}


def _add_metadata(data: dict) -> dict:
    """Add tool metadata to report."""
    data["_meta"] = {
        "tool": "DragonflyX",
        "version": "3.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
    }
    return data


def _flatten(data: dict, prefix: str = "") -> list[tuple[str, str]]:
    """
    Recursively flatten nested dict for TXT format.

    Args:
        data: Dictionary to flatten
        prefix: Key path prefix for nested values

    Returns:
        List of (key_path, str_value) pairs
    """
    items: list[tuple[str, str]] = []

    # Skip metadata in flattened output
    if "_meta" in data and prefix == "":
        data = {k: v for k, v in data.items() if k != "_meta"}

    for key, value in data.items():
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            items.extend(_flatten(value, full_key))
        elif isinstance(value, list):
            if not value:
                items.append((full_key, "(empty)"))
            else:
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        items.extend(_flatten(item, f"{full_key}[{i}]"))
                    else:
                        items.append((f"{full_key}[{i}]", str(item)))
        elif value is None:
            items.append((full_key, "N/A"))
        else:
            items.append((full_key, str(value)))

    return items


def save_report(result: Any, path: Path, fmt: ReportFormat = "json") -> Path:
    """
    Save a result to a report file.

    Args:
        result: Result object to save
        path: Output file path
        fmt: Format - "json" or "txt"

    Returns:
        Path to saved file
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _add_metadata(_serialize(result))

    if fmt == "json":
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    else:
        lines = ["DragonflyX Report", "=" * 40]
        for key, val in _flatten(data):
            lines.append(f"{key}: {val}")
        lines.extend(["", "=" * 40])
        path.write_text("\n".join(lines), encoding="utf-8")

    return path


class CaseManager:
    """Manage investigation cases with multiple results."""

    def __init__(self) -> None:
        CASES_DIR.mkdir(parents=True, exist_ok=True)
        self._active: dict[str, list[dict]] = {}

    def open_case(self, case_id: str | None = None) -> str:
        """
        Open a new case or resume existing.

        Args:
            case_id: Optional case ID (auto-generated if None)

        Returns:
            The case ID
        """
        if case_id is None:
            case_id = f"case_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"
        self._active[case_id] = self._active.get(case_id, [])
        return case_id

    def add_result(self, case_id: str, result: Any) -> None:
        """
        Add a result to a case.

        Args:
            case_id: Case ID
            result: Result to add
        """
        if case_id not in self._active:
            self.open_case(case_id)
        self._active[case_id].append(_serialize(result))

    def save_case(self, case_id: str, fmt: ReportFormat = "json") -> Path:
        """
        Save a case to file.

        Args:
            case_id: Case ID to save
            fmt: Format - "json" or "txt"

        Returns:
            Path to saved file
        """
        data = {
            "case_id": case_id,
            "total_results": len(self._active.get(case_id, [])),
            "results": self._active.get(case_id, []),
        }
        _add_metadata(data)

        ext = "json" if fmt == "json" else "txt"
        path = CASES_DIR / f"{case_id}.{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        else:
            lines = [f"Case: {case_id}", "=" * 40]
            lines.append(f"Total Results: {data['total_results']}")
            lines.append("")
            for i, result in enumerate(data["results"], 1):
                lines.append(f"--- Result {i} ---")
                for key, val in _flatten(result):
                    lines.append(f"  {key}: {val}")
                lines.append("")
            path.write_text("\n".join(lines), encoding="utf-8")

        return path

    def list_cases(self) -> list[Path]:
        """
        List all saved cases.

        Returns:
            List of case file paths
        """
        return sorted(CASES_DIR.glob("*.json")) + sorted(CASES_DIR.glob("*.txt"))
