"""Shared fixtures for the MemGuard test suite.

Run from the repository root:  py -3.13 -m pytest
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memguard import scorer  # noqa: E402


def make_record(**overrides) -> dict:
    """A minimal ProcessRecord; PID 999999 avoids colliding with a live PID."""
    record = {
        "pid": 999999, "ppid": 0, "name": "sample.exe", "exe": "N/A", "user": "tester",
        "rss_mb": 1.0, "cpu_percent": 0.0, "cmdline": "", "start_time": "",
    }
    record.update(overrides)
    return record


@pytest.fixture
def windows_env(monkeypatch):
    """Pin the Windows folder layout so path rules are deterministic."""
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")


@pytest.fixture
def isolated_scorer(monkeypatch, windows_env):
    """Cut the scorer off from live system state.

    Parent lookups, listening ports, token elevation and Authenticode are
    replaced with neutral answers; individual tests override what they need.
    """
    monkeypatch.setattr(scorer, "_get_ephemeral_listening_addresses", lambda pid: set())
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: (None, "gone"))
    monkeypatch.setattr(scorer, "_is_process_elevated", lambda pid, user: False)
    monkeypatch.setattr(scorer, "_get_signature_info", lambda exe: ("", ""))
    return scorer
