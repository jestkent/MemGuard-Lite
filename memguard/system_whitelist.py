"""Logic-only whitelist checks for trusted Windows system processes."""

SYSTEM_PROCESS_NAMES = {
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "svchost.exe",
    "spoolsv.exe",
    "MsMpEng.exe",
}

_SYSTEM_PROCESS_NAMES_LOWER = {process_name.lower() for process_name in SYSTEM_PROCESS_NAMES}


def is_system_process(name: str, exe_path: str) -> bool:
    """Return True when a process matches trusted system name and location."""
    if exe_path is None:
        return False

    normalized_name = name.lower()
    normalized_path = exe_path.lower()

    return normalized_name in _SYSTEM_PROCESS_NAMES_LOWER and (
        normalized_path.startswith("c:\\windows")
        or normalized_path.startswith("c:\\programdata\\microsoft")
    )
