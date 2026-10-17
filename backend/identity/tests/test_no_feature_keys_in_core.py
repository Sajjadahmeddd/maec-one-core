"""Core never names an application's features. OPEN-DECISIONS #23.

An app's feature keys live in the app's own code, and Core learns them only
from the app's report (PUT /api/gate/features). So none may appear in Core's
code — backend or frontend, comments included — outside the tests. Keys are
lowercase by rule ([a-z][a-z0-9_]{0,39}), so the match is exact: an app's
description that names its products in prose ("HAPExt, AirSizer Pro") is not
a key.
"""

from __future__ import annotations

import re
from pathlib import Path

import backend.identity as _identity

REPO = Path(_identity.__file__).resolve().parents[2]
ROOTS = [REPO / "backend", REPO / "frontend" / "src"]
SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".css", ".html", ".json", ".ini", ".mako"}

# Engineering Tools' keys, Project Management's old single permission, and the
# convention for every new feature.
KEYS = re.compile(r"\b(hapext|airsizer|hapaudit|rebadge)\b|app:use\b|\btask\d+\b")


def _is_test(path: Path) -> bool:
    parts = set(path.parts)
    return ("tests" in parts or path.name.startswith("test_")
            or path.name.endswith((".test.js", ".test.jsx")))


def _code_files():
    for root in ROOTS:
        for path in root.rglob("*"):
            if (path.is_file() and path.suffix in SUFFIXES and not _is_test(path)
                    and "node_modules" not in path.parts and "__pycache__" not in path.parts):
                yield path


def test_no_application_feature_key_appears_in_cores_code():
    found = []
    for path in _code_files():
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace")
                                      .splitlines(), start=1):
            if KEYS.search(line):
                found.append(f"{path.relative_to(REPO)}:{number}: {line.strip()[:100]}")
    assert not found, "Core must not name an app's features:\n" + "\n".join(found)


def test_the_scan_would_see_one():
    """The pattern catches what it must — so a pass means something."""
    for text in ('ENGINEERING_MODULES = ["hapext"]', '"projects:app:use"', "F.task71",
                 "key='rebadge'", "engineering:airsizer:view"):
        assert KEYS.search(text), text
    for text in ("HAPExt, AirSizer Pro, HAPAudit & more", "tasks", "taskbar", "application"):
        assert not KEYS.search(text), text
