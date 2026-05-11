# check-http-knocks

Audit new HTTP honeypot entries and extend the exploit classifier.

## What this does

Looks at HTTP knocks recorded since the last review, identifies paths/methods/bodies
that aren't yet classified by the exploit database or honeypot heuristics, researches
what they are, and adds named entries to `honeypots/http_exploits.json` (and adjusts
`honeypots/http_honeypot.py` heuristics when the JSON can't capture the pattern).

## Step 1 — Determine the review window

Read `data/http_knocks_last_checked_id.txt` to get the last reviewed knock ID.
If the file doesn't exist, default to reviewing the last 500 entries.

```bash
cat data/http_knocks_last_checked_id.txt 2>/dev/null || echo "0"
```

## Step 2 — Fetch new entries

Query all knocks with id > last_id (or the last 500 if no checkpoint exists):

```bash
sqlite3 data/knock_knock.db \
  "SELECT id, http_method, http_path, http_user_agent, http_body
   FROM knocks_http
   WHERE id > <last_id>
   ORDER BY id ASC;"
```

Note the maximum id seen — you'll write this back at the end.

## Step 3 — Run the classifier

Load and compile `honeypots/http_exploits.json` (sorted by priority ascending —
lower number = checked first). For each distinct (method, path, body, ua) tuple,
check whether it matches any compiled entry. Also apply the inline heuristics from
`honeypots/http_honeypot.py` (`_RE_CONFIG_PATH`, `_RE_TRAVERSAL`, `_RE_RCE_PATH`,
`_RE_CRED_PATH`, `_RE_DEVICE_PATH`) to avoid flagging things already handled there.

Paths/methods to silently skip (noise with no exploit value):
- Method `<cryptic binary>` or path `<cryptic binary>`
- Plain `/`, `/robots.txt`, `/sitemap.xml`, `/favicon.*`, `/.well-known/security.txt`
- Random-looking alphanumeric beacon paths (8–20 chars, no slashes after root)
- Short generic PHP probes (e.g. `/a.php`, `/1.php`) — already handled heuristically

## Step 4 — Triage unmatched entries

For each genuinely unmatched distinct path/method:

**Ask: is this a named exploit, CVE, or known attack tool?**
- If yes → add a JSON entry with `name`, `cve` (if known), `priority`, `purpose`,
  and whichever of `path_pattern`/`method_pattern`/`ua_pattern`/`body_pattern` apply.
- If it's a config/credential file exposure not yet covered → add a `config_exposure`
  entry at priority 185–260.
- If it's pure noise (generic test paths, favicon variants, scanner bots already
  covered by a broad UA pattern) → skip.

**Priority ranges to follow:**
- 100–110 : specific named RCE/exploit CVEs
- 120–150 : path traversal, device infiltration with CVE
- 175–185 : config/credential file exposures (specific)
- 200–220 : credential theft / app discovery / device infiltration (no CVE)
- 225–260 : broader config exposure, API probes, generic app discovery
- 650–800 : mass scanners, research scanners

**Purpose values (use existing set):**
`rce`, `credential_theft`, `config_exposure`, `app_discovery`, `device_infiltration`,
`proxy_abuse`, `api_probe`, `malware_comm`, `crypto_mining`, `open_redirect`,
`mass_scanner`, `research_scanner`, `protocol_probe`

## Step 5 — Consider honeypot code changes

If a pattern is better expressed as a heuristic regex in `http_honeypot.py` than
as a JSON entry (e.g. a broad structural rule, a URL-encoding variant of an existing
heuristic, or a new HTTP method that needs a code-path change), edit the relevant
`_RE_*` constant or the `_classify_purpose` function directly.

Key locations in `http_honeypot.py`:
- `_RE_CONFIG_PATH` (~line 294) — credential/config file heuristics
- `_RE_RCE_PATH` — path-based RCE signals
- `_RE_CRED_PATH` — credential theft path signals
- `_RE_DEVICE_PATH` — IoT/device infiltration signals
- `_classify_purpose` (~line 405) — overall classification flow; exploit DB is
  checked at step 1 (after the binary-method guard), before all heuristics

## Step 6 — Validate

After any edits:

```bash
python3 -c "
import json, re
with open('honeypots/http_exploits.json') as f:
    data = json.load(f)
print(f'{len(data)} entries')
errors = []
for e in data:
    for field in ('path_pattern','body_pattern','ua_pattern','method_pattern'):
        if e.get(field):
            try: re.compile(e[field], re.IGNORECASE)
            except re.error as ex: errors.append(f'{e[\"name\"]}/{field}: {ex}')
print('Patterns:', 'all OK' if not errors else errors)
"
python3 -m py_compile honeypots/http_honeypot.py && echo "http_honeypot.py OK"
```

Run a spot-check smoke test confirming each new pattern matches the actual path
that triggered it (construct a small Python test inline).

## Step 7 — Update the checkpoint

Write the maximum knock ID seen in step 2 to `data/http_knocks_last_checked_id.txt`:

```bash
echo "<max_id>" > data/http_knocks_last_checked_id.txt
```

## Step 8 — Report

Summarise what was added: a table of new entries (name, CVE if any, purpose) and
any `http_honeypot.py` changes. Note how many total entries the JSON now has.
If nothing new was found, say so — that's a good result.
