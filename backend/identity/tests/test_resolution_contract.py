"""resolution.py's portability, and the hash a vendored copy checks against.

test_resolution.py proves the engine imports and runs with every database, web
and crypto package made unimportable — the runtime half. These are the static
half, and the publication: nothing outside the standard library may be imported,
and the SHA-256 in resolution.sha256 must describe the file as it is now.
"""

from __future__ import annotations

import ast
import re
import sys

from backend.identity import resolution, resolution_hash


def _non_stdlib_imports(source: str) -> list[str]:
    """Every import in this source that is not the standard library.

    Parsed, not grepped: resolution.py's docstring has a line beginning "from
    the claims of a token", which a line scan reads as an import. Relative
    imports are refused outright — anything under backend is off limits.
    """
    offenders = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                offenders.append(f"line {node.lineno}: from {'.' * node.level}{node.module or ''}")
                continue
            names = [node.module or ""]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            continue
        for name in names:
            if name.split(".")[0] not in sys.stdlib_module_names:
                offenders.append(f"line {node.lineno}: {name}")
    return offenders


def test_resolution_imports_only_the_standard_library():
    offenders = _non_stdlib_imports(resolution_hash.ENGINE.read_text(encoding="utf-8"))
    assert not offenders, (
        "resolution.py must import only the standard library — a product imports "
        "it with no database in sight: " + "; ".join(offenders))


def test_the_import_check_catches_what_it_exists_for():
    source = "\n".join([
        '"""from the claims of a token — prose, not an import"""',
        "import json",
        "from collections.abc import Mapping",
        "from sqlalchemy import select",
        "import fastapi.responses",
        "from backend.identity import config",
        "from .db import get_db",
        "from . import models",
    ])
    assert len(_non_stdlib_imports(source)) == 5


def test_the_contract_version_is_declared():
    assert isinstance(resolution.RESOLUTION_CONTRACT, str)
    assert resolution.RESOLUTION_CONTRACT.strip()


def test_resolution_hash_matches():
    """If this fails, resolution.py changed and its published hash did not.
    Regenerate with `python -m backend.identity.resolution_hash`, and bump
    RESOLUTION_CONTRACT if what the engine decides or produces changed."""
    assert re.fullmatch(r"[0-9a-f]{64}", resolution_hash.published())
    assert resolution_hash.published() == resolution_hash.digest()


def test_the_hash_is_the_same_whatever_the_line_endings(tmp_path):
    lf, crlf, other = tmp_path / "lf.py", tmp_path / "crlf.py", tmp_path / "other.py"
    lf.write_bytes(b"a = 1\nb = 2\n")
    crlf.write_bytes(b"a = 1\r\nb = 2\r\n")
    other.write_bytes(b"a = 1\nb = 3\n")
    assert resolution_hash.digest(lf) == resolution_hash.digest(crlf)
    assert resolution_hash.digest(lf) != resolution_hash.digest(other)


def test_the_check_command_fails_on_a_stale_hash(tmp_path, monkeypatch, capsys):
    stale = tmp_path / "resolution.sha256"
    stale.write_text("0" * 64 + "\n", encoding="ascii")
    monkeypatch.setattr(resolution_hash, "PUBLISHED", stale)
    monkeypatch.setattr(resolution_hash, "published",
                        lambda path=stale: path.read_text(encoding="ascii").strip())
    assert resolution_hash.main(["--check"]) == 1
    assert "stale" in capsys.readouterr().err
