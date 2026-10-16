"""The launcher's rules, run as part of this suite.

Where sign-in lands, what each launcher tile does and who is offered the Admin
panel live in the frontend (frontend/src/maecone/launcher.js and next.js),
tested there under Node's built-in runner. Running that file from here keeps
them inside the one green-or-red answer `pytest` gives, as
test_next_allowlist.py does for the redirect rules. Node's absence fails this
rather than skipping it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import backend.identity as _identity

REPO = Path(_identity.__file__).resolve().parents[2]
TESTS = REPO / "frontend" / "src" / "maecone" / "launcher.test.js"


def test_the_launcher_rules():
    node = shutil.which("node")
    assert node, "Node is needed to build the frontend and to run these tests"
    assert TESTS.is_file(), TESTS
    run = subprocess.run([node, "--test", str(TESTS)], cwd=REPO,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-2000:]
    assert "fail 0" in run.stdout
