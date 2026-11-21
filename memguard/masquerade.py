"""Process-identity checks: is this really the Windows process it claims to be?

Read-only. Every function here inspects strings (process name, executable
path, signer subject, parent name) that collector.py / scorer.py already
gathered. Nothing opens, signals or modifies a process.

Masquerading (MITRE ATT&CK T1036.005) is the most common way malware hides
in a process list: it names itself after a trusted Windows binary such as
``svchost.exe`` and relies on the analyst glancing at the name only. Four
independent checks catch the variants:

1. Wrong location   - a protected name running outside its real folder
                      (``C:\\Users\\bob\\AppData\\svchost.exe``).
2. Lookalike name   - one keystroke or homoglyph away from a protected name
                      (``svch0st.exe``, ``scvhost.exe``, Cyrillic ``svсhost``).
3. Wrong signer     - a protected name that is validly signed, but not by
                      Microsoft (a cheap or stolen certificate).
4. Wrong parent     - core processes have exactly one legitimate parent
                      (``lsass.exe`` is always started by ``wininit.exe``).

Paths are resolved against %SystemRoot% rather than a hard-coded ``C:\\``
so the checks stay correct on machines where Windows is on another drive.
"""

from __future__ import annotations

import os
import unicodedata
from typing import Final

# ── Expected locations ───────────────────────────────────────────────────────

_SYS32: Final[tuple[str, ...]] = ("system32",)
_SYS32_WOW: Final[tuple[str, ...]] = ("system32", "syswow64")

# Folder(s) each protected binary may legitimately run from, relative to
# %SystemRoot%. "" means %SystemRoot% itself. Verified against a live
# Windows 11 host: every instance of every name below ran from these folders.
PROTECTED_BINARIES: Final[dict[str, tuple[str, ...]]] = {
    # Core boot / session processes
    "smss.exe": _SYS32,
    "csrss.exe": _SYS32,
    "wininit.exe": _SYS32,
    "winlogon.exe": _SYS32,
    "services.exe": _SYS32,
    "lsass.exe": _SYS32,
    "lsaiso.exe": _SYS32,
    "userinit.exe": _SYS32,
    # Service and shell hosts that malware commonly impersonates
    "svchost.exe": _SYS32_WOW,
    "spoolsv.exe": _SYS32,
    "taskhostw.exe": _SYS32,
    "sihost.exe": _SYS32,
    "fontdrvhost.exe": _SYS32,
    "dwm.exe": _SYS32,
    "ctfmon.exe": _SYS32_WOW,
    "runtimebroker.exe": _SYS32,
    "conhost.exe": _SYS32,
    "dllhost.exe": _SYS32_WOW,
    "searchindexer.exe": _SYS32,
    "audiodg.exe": _SYS32,
    "taskmgr.exe": _SYS32_WOW,
    "wmiprvse.exe": ("system32\\wbem", "syswow64\\wbem"),
    "explorer.exe": ("", "syswow64"),
    # Living-off-the-land binaries: a copy outside System32 is a known way to
    # dodge rules that key on the original path (renamed/relocated LOLBin).
    "cmd.exe": _SYS32_WOW,
    "powershell.exe": ("system32\\windowspowershell\\v1.0", "syswow64\\windowspowershell\\v1.0"),
    "rundll32.exe": _SYS32_WOW,
    "regsvr32.exe": _SYS32_WOW,
    "mshta.exe": _SYS32_WOW,
}

# Binaries whose real location is outside %SystemRoot% (versioned folders).
# Values are absolute prefixes built from environment variables at runtime.
_PREFIX_LOCATED: Final[dict[str, tuple[tuple[str, str], ...]]] = {
    "msmpeng.exe": (
        ("ProgramData", "microsoft\\windows defender\\platform\\"),
        ("ProgramFiles", "windows defender\\"),
    ),
}

ALL_PROTECTED_NAMES: Final[frozenset[str]] = frozenset(PROTECTED_BINARIES) | frozenset(_PREFIX_LOCATED)

# Deterministic order for look-alike matching. When a name is one edit from
# two protected names ("svhost" -> svchost AND sihost), the earlier entry
# wins, so the most commonly impersonated binaries are listed first.
_MOST_IMPERSONATED: Final[tuple[str, ...]] = (
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "services.exe", "winlogon.exe",
    "wininit.exe", "smss.exe", "rundll32.exe", "regsvr32.exe", "powershell.exe", "conhost.exe",
    "dllhost.exe", "spoolsv.exe", "taskhostw.exe", "runtimebroker.exe",
)
_LOOKALIKE_PRIORITY: Final[tuple[str, ...]] = _MOST_IMPERSONATED + tuple(
    sorted(ALL_PROTECTED_NAMES - set(_MOST_IMPERSONATED))
)


def _system_root() -> str:
    return normalize_path(os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows")


def normalize_path(path: str) -> str:
    """Lower-case, backslash-separated, no ``\\\\?\\`` prefix, no trailing slash."""
    text = (path or "").strip().replace("/", "\\").lower()
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return text.rstrip("\\")


def is_in_expected_location(name: str, exe_path: str) -> bool | None:
    """Check a protected binary's folder.

    Returns:
        True  - name is protected and runs from a legitimate folder.
        False - name is protected and runs from somewhere else (masquerading).
        None  - not applicable: name is not protected, or the path is unknown.
                Unknown is NOT reported as clean; the caller decides.
    """
    lname = (name or "").lower()
    # Check for the "N/A" placeholder BEFORE normalising: normalize_path turns
    # "/" into "\", which would make it look like a real (wrong) path.
    if lname not in ALL_PROTECTED_NAMES or not exe_path or exe_path.strip().lower() == "n/a":
        return None
    path = normalize_path(exe_path)
    if not path:
        return None

    # Judged by folder only. If the file on disk has a different name from
    # the process (renamed after launch), the name the analyst sees is still
    # the protected one, so the folder is what decides.
    folder = path.rpartition("\\")[0]

    if lname in PROTECTED_BINARIES:
        root = _system_root()
        allowed = {normalize_path(f"{root}\\{rel}") if rel else root for rel in PROTECTED_BINARIES[lname]}
        return folder in allowed

    for env_var, suffix in _PREFIX_LOCATED[lname]:
        base = os.environ.get(env_var)
        if base and (folder + "\\").startswith(normalize_path(base) + "\\" + suffix):
            return True
    return False


# ── Lookalike names ──────────────────────────────────────────────────────────

# Characters that render (nearly) identically to ASCII letters. Cyrillic and
# Greek homoglyphs let "svсhost.exe" (Cyrillic с) pass a visual check while
# being a different string. Digits cover the classic "svch0st" substitutions.
_CONFUSABLES: Final[dict[str, str]] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ӏ": "l", "һ": "h", "к": "k",
    "м": "m", "т": "t", "в": "b", "н": "h",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "χ": "x",
    # Digit / symbol substitutions
    "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a",
}

# Real Windows binaries that sit one edit away from a protected name.
_LEGITIMATE_NEAR_NAMES: Final[frozenset[str]] = frozenset({
    "taskhost.exe",    # Windows 7 predecessor of taskhostw.exe
    "taskhostex.exe",  # Windows 8 variant
})


def _skeleton(text: str) -> str:
    """Map look-alike characters to ASCII so visual twins compare equal."""
    text = unicodedata.normalize("NFKC", text.lower())
    text = text.replace("rn", "m").replace("vv", "w")
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


# (raw stem, folded stem, protected name) in priority order. Both sides of a
# comparison are folded, so a digit inside a real name ("rundll32") cannot
# cause a mismatch.
_PROTECTED_STEMS: Final[tuple[tuple[str, str, str], ...]] = tuple(
    (stem, _skeleton(stem), name)
    for name in _LOOKALIKE_PRIORITY
    for stem in (name.rsplit(".", 1)[0],)
)


def _osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: edits incl. adjacent transposition.

    "scvhost" vs "svchost" is ONE edit (swap), not two - the swap is the most
    common deliberate typo in masquerading names.
    """
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def find_lookalike(name: str) -> str | None:
    """Return the protected name that ``name`` imitates, or None.

    A name matches when, after homoglyph folding, it is identical to a
    protected name, or exactly one edit away from one. Stems shorter than 5
    characters are skipped (too many legitimate 1-edit neighbours), as are
    the real Windows binaries listed in _LEGITIMATE_NEAR_NAMES.
    """
    lname = (name or "").lower()
    if not lname or lname in ALL_PROTECTED_NAMES or lname in _LEGITIMATE_NEAR_NAMES:
        return None

    stem = lname.rsplit(".", 1)[0] if "." in lname else lname
    folded = _skeleton(stem)

    # Exact visual twins beat one-edit neighbours; priority order breaks ties.
    for _target_stem, target_folded, target_name in _PROTECTED_STEMS:
        if folded == target_folded:
            return target_name  # homoglyph / digit twin
    for target_stem, target_folded, target_name in _PROTECTED_STEMS:
        if len(target_stem) >= 5 and len(stem) >= 4 and _osa_distance(folded, target_folded) == 1:
            return target_name
    return None


# ── Signer ───────────────────────────────────────────────────────────────────

_MICROSOFT_ORGANIZATION: Final[str] = "microsoft corporation"


def parse_subject(subject: str) -> list[tuple[str, str]]:
    """Split an X.500 subject ("CN=x, O=y") into (KEY, value) pairs.

    Honours double-quoted values, so 'O="Contoso, Ltd"' stays one field.
    """
    fields: list[tuple[str, str]] = []
    current, in_quotes = "", False
    for ch in (subject or "") + ",":
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            key, sep, value = current.partition("=")
            if sep:
                fields.append((key.strip().upper(), value.strip()))
            current = ""
            continue
        current += ch
    return fields


def is_microsoft_signer(signer_subject: str) -> bool:
    """True when the certificate's Organization field is exactly Microsoft.

    Parsed field-by-field rather than by substring: a substring test would
    accept a certificate whose Common Name merely CONTAINS the text
    "O=Microsoft Corporation".
    """
    return any(
        key == "O" and value.strip('"').strip().lower() == _MICROSOFT_ORGANIZATION
        for key, value in parse_subject(signer_subject)
    )


# ── Expected parents ─────────────────────────────────────────────────────────

# Each core process has one legitimate launcher. Sourced from the SANS
# "Hunt Evil" reference and verified on a live Windows 11 host (98/98
# svchost.exe -> services.exe, lsass.exe -> wininit.exe, ...).
#
# wininit / csrss / winlogon are started by a temporary smss.exe instance that
# exits immediately, so on a running system their parent is normally GONE.
# A missing parent is therefore not evidence; only a live, wrong parent is.
EXPECTED_PARENTS: Final[dict[str, frozenset[str]]] = {
    "smss.exe": frozenset({"system", "smss.exe"}),
    "wininit.exe": frozenset({"smss.exe"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "winlogon.exe": frozenset({"smss.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "lsaiso.exe": frozenset({"wininit.exe"}),
    "svchost.exe": frozenset({"services.exe"}),
    "spoolsv.exe": frozenset({"services.exe"}),
    "searchindexer.exe": frozenset({"services.exe"}),
    "taskhostw.exe": frozenset({"svchost.exe"}),
    "runtimebroker.exe": frozenset({"svchost.exe"}),
    "sihost.exe": frozenset({"svchost.exe"}),
}


def unexpected_parent(child_name: str, parent_name: str | None) -> frozenset[str] | None:
    """Return the expected parent set when ``parent_name`` is wrong, else None.

    None is returned when the child has no rule, or the parent is unknown
    (gone / unreadable / PID reused) - unknown is never treated as wrong.
    """
    expected = EXPECTED_PARENTS.get((child_name or "").lower())
    if not expected or not parent_name:
        return None
    return None if parent_name.lower() in expected else expected


# Processes that must exist exactly once per boot. A second lsass.exe is a
# well-known sign of an impostor even when it sits in the right folder.
SINGLETON_PROCESSES: Final[frozenset[str]] = frozenset({
    "lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe",
})
