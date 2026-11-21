# MemGuard stress tests (opt-in)

Two scripts that go beyond the unit tests in `tests/`. Unit tests prove a rule
matches a string; these prove MemGuard detects **real processes**, survives a
**busy machine**, and cannot be **stalled or crashed by attacker-controlled
input**. Neither runs as part of `pytest`.

| Script | What it does | Time | Spawns processes? |
|---|---|---|---|
| `stress_fuzz.py` | Scan-stall (ReDoS-style) inputs, 25,000 fuzz cases, malformed records, repeat-scan determinism, hostile export fields | ~1-2 min (`--skip-live`: seconds) | No |
| `stress_live.py --run` | Benign adversary emulation + ~300 fillers + continuous spawn/exit churn, then a real CLI scan checked by PID | ~3 min | Yes (all cleaned up) |

```powershell
py -3.13 scripts/stress/stress_fuzz.py --skip-live
py -3.13 scripts/stress/stress_fuzz.py
py -3.13 scripts/stress/stress_live.py --run
```

Both exit `0` on success and `1` on any miss, false positive, crash or slow input.

## Safety of the live emulation

The "threats" are harmless programs that only **look** malicious:

- `PING.EXE` copied into `%LOCALAPPDATA%\MemGuardStress` as `svchost.exe`, `lsass.exe`, `scvhost.exe`, `expl0rer.exe` and `svchost.exe` spelled with a Cyrillic `с`
- `node.exe` (if installed) copied as `dllhost.exe` to exercise the wrong-signer rule
- a relocated copy of `cmd.exe` running `ping`
- PowerShell that only runs `Start-Sleep`, passed encoded (`-EncodedCommand`, `-ec`, en-dash) or obfuscated (carets, backticks)
- download cradles wrapped in `if ($false) { ... }`, so they never execute

Credential dumping, backup deletion and Defender tampering are **never executed**;
they are covered by text-only cases in `tests/test_cmdline_rules.py`.

Every spawned process is the script's own child and is killed at the end (also on
error or Ctrl+C), and the copy folder is deleted. The CLI scan runs in a temporary
folder, so `processes.json` and `memguard_history.jsonl` never touch the repo or
your real history. Microsoft Defender may notice a renamed system binary; that is
expected.

## Reference results (2026-11-20, Windows 11, ~520 processes)

- Live: **14/14 detected, 0/6 false positives, 0 collateral**, with ~1,175 live
  processes and ~2,700 spawn/exit events during the scan.
- Fuzz: 0 exceptions; worst adversarial 32,767-char command line ~12 ms
  (was 708 ms before the head/tail rewrite); 3 scoring passes identical.
