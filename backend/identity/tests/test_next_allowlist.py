"""The sign-in page's `next` allowlist, run as part of this suite.

The rule lives in the frontend, where the redirect happens
(frontend/src/maecone/next.js), and its near-misses are tested there under
Node's built-in runner. Running that file from here keeps the open-redirect
tests inside the one green-or-red answer `pytest` gives, rather than in a
second command someone has to remember.

Node is required to build the frontend at all, so its absence fails this test
rather than skipping it: a skip here would be a green suite that never asked
where the sign-in page may send people.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import backend.identity as _identity

REPO = Path(_identity.__file__).resolve().parents[2]
TESTS = REPO / "frontend" / "src" / "maecone" / "next.test.js"


def test_the_next_allowlist_refuses_every_near_miss():
    node = shutil.which("node")
    assert node, "Node is needed to build the frontend and to run these tests"
    assert TESTS.is_file(), TESTS
    run = subprocess.run([node, "--test", str(TESTS)], cwd=REPO,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-2000:]
    assert "# fail 0" in run.stdout or "fail 0" in run.stdout
