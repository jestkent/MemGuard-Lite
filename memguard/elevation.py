"""Opt-in privilege elevation for fuller read visibility.

Windows cannot raise the privilege of a process that is already running, so
elevation means relaunching MemGuard through the UAC consent prompt and
letting the original instance exit.

Scope note: elevation grants additional READ access only. It exists because a
non-elevated token makes Windows deny cmdline/user on SYSTEM-owned processes,
which silently removes evidence from scoring (see data_confidence in
collector.py). MemGuard's read-only model is unchanged — it performs no
process, service, registry, or firewall modification at any privilege level.

Elevation is never automatic. It happens only on an explicit user action.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

from .collector import is_elevated

logger = logging.getLogger(__name__)

__all__ = ["is_elevated", "build_relaunch_command", "relaunch_as_admin"]

# ShellExecuteW returns a value <= 32 to signal failure.
_SHELL_EXECUTE_MIN_SUCCESS = 32
_SE_ERR_ACCESSDENIED = 5
_SHOW_NORMAL = 1


def build_relaunch_command(argv: list[str] | None = None) -> tuple[str, str]:
    """Return (executable, argument_string) that re-runs this app as-is.

    Kept separate from the ShellExecuteW call so the command can be verified
    without raising a UAC prompt.

    Three launch shapes are handled:
      - PyInstaller frozen build: the executable is the app itself.
      - `py -m memguard`: argv[0] is .../memguard/__main__.py, which cannot be
        re-run as a plain script because its relative imports need the package
        context, so `-m memguard` is reconstructed.
      - A plain script such as launch_gui.py: re-run that script.
    """
    argv = list(sys.argv if argv is None else argv)
    args = argv[1:]

    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(args)

    script = argv[0] if argv else ""
    normalized = script.replace("\\", "/").lower()
    if normalized.endswith("/memguard/__main__.py") or normalized.endswith("__main__.py"):
        return sys.executable, subprocess.list2cmdline(["-m", "memguard", *args])

    return sys.executable, subprocess.list2cmdline([script, *args])


def relaunch_as_admin(argv: list[str] | None = None) -> tuple[bool, str]:
    """Relaunch MemGuard elevated via the UAC prompt.

    Returns:
        (started, message). `started` is True only when a new elevated process
        was actually launched — the caller should then close the current
        instance. A declined UAC prompt returns (False, reason) and the current
        instance must keep running unchanged.
    """
    if os.name != "nt":
        return False, "Elevation is only supported on Windows."

    if is_elevated():
        return False, "Already running as Administrator."

    executable, params = build_relaunch_command(argv)
    working_dir = os.getcwd()

    try:
        import ctypes

        result = int(
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", executable, params, working_dir, _SHOW_NORMAL
            )
        )
    except Exception as exc:  # pragma: no cover - platform/runtime safety
        logger.warning("Elevation request failed: %s", exc)
        return False, f"Could not request elevation: {exc}"

    if result > _SHELL_EXECUTE_MIN_SUCCESS:
        logger.info("Elevated instance launched (%s %s)", executable, params)
        return True, "Elevated instance started."

    if result == _SE_ERR_ACCESSDENIED:
        return False, "Elevation was declined at the UAC prompt."

    return False, f"Elevation failed (ShellExecute code {result})."
