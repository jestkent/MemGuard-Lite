# MemGuard

MemGuard is a read-only process intelligence CLI with heuristic scoring and local blocklist matching.

## Run

From project root:

```powershell
py -3.13 -m pip install -r memguard/requirements.txt
py -3.13 -m memguard
```

Optional VirusTotal enrichment:

```powershell
py -3.13 -m memguard --vt
```

## Local Blocklist Usage

Blocklist file path:

- `data/blocklist.txt`

Format:

- One SHA256 hash per line
- Empty lines are ignored
- Lines starting with `#` are comments

When a process executable hash matches an entry in `data/blocklist.txt`, MemGuard:

- Adds `+70` threat score
- Adds triggered rule: `Matched local blocklist`

## VirusTotal Enrichment (Optional)

Set API key via environment variable:

```powershell
$env:VT_API_KEY="your_api_key_here"
```

Persistent Windows user environment example:

```powershell
setx VT_API_KEY "your_api_key_here"
```

Run with VT enabled:

```powershell
py -3.13 -m memguard --vt
```

Fast VT mode (recommended for daily use):

```powershell
py -3.13 -m memguard --vt --vt-suspicious-only --vt-max-requests 3
```

Tune VT scope:

```powershell
py -3.13 -m memguard --vt --vt-max-requests 5 --vt-min-score 25
```

Behavior:

- Queries VirusTotal v3 for process SHA256 values
- Queries only hashes that meet the VT threat score threshold (`--vt-min-score`, default `20`)
- Adds `vt_malicious`, `vt_suspicious`, `vt_harmless` fields to exported JSON
- Adds `+50` score and rule `VirusTotal malicious detections >= 5` when `vt_malicious >= 5`

Rate-limit notes:

- MemGuard sleeps 15 seconds between VirusTotal requests (public API friendly)
- Request timeout is 5 seconds
- Handles HTTP `404`, `429`, and network errors without crashing
- If `--vt` is used without `VT_API_KEY`, MemGuard prints a warning and continues without VT data

## Notes

- Hashing is skipped when executable path is unavailable.
- File read/hash errors are skipped silently for process hashing.
- Blocklist is loaded once at startup.
