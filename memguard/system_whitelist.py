"""Logic-only whitelist checks for trusted Windows system processes."""

from memguard.masquerade import is_in_expected_location

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
    """Return True when a process matches a trusted system name AND its real folder.

    The location check used to be ``path.startswith("c:\\windows")``, which
    also accepted look-alike folders such as ``C:\\Windows2\\svchost.exe`` or
    ``C:\\WindowsUpdate\\lsass.exe``. Standard users may create folders in the
    root of C:\\ on a default Windows install, so that prefix test was a
    no-admin-needed bypass of the port-score reduction. The check now
    requires the exact folder each binary ships in (see masquerade.py).
    """
    if exe_path is None or not name:
        return False
    if name.lower() not in _SYSTEM_PROCESS_NAMES_LOWER:
        return False
    return is_in_expected_location(name, exe_path) is True
