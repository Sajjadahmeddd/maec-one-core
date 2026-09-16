"""The published SHA-256 of resolution.py, for a vendored copy to check against.

    python -m backend.identity.resolution_hash            rewrite resolution.sha256
    python -m backend.identity.resolution_hash --check    exit 1 if it is stale

A product carries a copy of resolution.py — the engine has to run where there
is no database — and checks that copy against this hash, so the two can never
drift unnoticed. Core's own suite fails if the engine changes without this file
being regenerated (test_resolution_hash_matches), so the published hash cannot
fall behind the file it describes.

The hash is taken over the file with line endings normalised to LF. That is the
form git stores, and it keeps the hash stable on a checkout that converts to
CRLF — which this repository's Windows machine does (core.autocrlf=true, set
system-wide). .gitattributes also pins both files to LF, so a plain `sha256sum`
of a fresh checkout agrees with it.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ENGINE = Path(__file__).with_name("resolution.py")
PUBLISHED = Path(__file__).with_name("resolution.sha256")


def digest(path: Path = ENGINE) -> str:
    """SHA-256 of the file, CRLF normalised to LF."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def published(path: Path = PUBLISHED) -> str:
    return path.read_text(encoding="ascii").strip()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    current = digest()
    if "--check" in args:
        if published() != current:
            print(f"resolution.sha256 is stale: it says {published()}, but "
                  f"resolution.py is {current}. Regenerate with "
                  "`python -m backend.identity.resolution_hash`.", file=sys.stderr)
            return 1
        print(current)
        return 0
    PUBLISHED.write_text(current + "\n", encoding="ascii", newline="\n")
    print(current)
    return 0


if __name__ == "__main__":
    sys.exit(main())
