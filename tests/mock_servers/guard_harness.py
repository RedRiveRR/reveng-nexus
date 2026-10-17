"""Test harness around ``_stdio_guard.main()``; never used by Nexus.

``python guard_harness.py <path to _stdio_guard.py> -- <server argv>`` runs the real guard code
with two test hooks, both in the guard process only:

* ``GUARD_HARNESS_SERVER_PID``: file that receives the server's PID (its process-group id), so a
  test can verify and clean up the server's group even if the guard is killed;
* ``GUARD_HARNESS_EARLY_SIGNAL``: signal name the guard sends itself just before it starts the
  server, to exercise a termination request that arrives during start-up.
"""

from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("_stdio_guard", sys.argv[1])
assert spec is not None and spec.loader is not None
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
_real_popen = subprocess.Popen


def _popen(*args, **kwargs):
    early = os.environ.get("GUARD_HARNESS_EARLY_SIGNAL")
    if early:
        os.kill(os.getpid(), getattr(signal, early))
    proc = _real_popen(*args, **kwargs)
    target = os.environ.get("GUARD_HARNESS_SERVER_PID")
    if target:
        tmp = Path(target + ".tmp")
        tmp.write_text(str(proc.pid), encoding="utf-8")
        tmp.replace(target)
    return proc


guard.subprocess.Popen = _popen
sys.exit(guard.main(sys.argv[2:]))
