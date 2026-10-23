# Development plan: records, alerts, and a dashboard

Written: 23 October 2026. Approved by the user on the same day. Progress is recorded in section "Progress" at the end.

## Context

1. The rule part is finished: all CRS 4.30.0 request rules at paranoia levels 1–4, on offline requests. Today `ids-offline` prints its results and forgets them.
2. In the user's order (12 October 2026), step 1 is now "records, alerts, and a dashboard", built as one step. On 23 October 2026 the user decided R1–R7 (R4 revised) and V1–V7; they are recorded in main plan section 11.22.
3. **Goal:** `ids-offline` writes records and alerts as decided. A separate `ids-dashboard` shows them behind a login over HTTPS. The `ids` service that comes with the proxy will later write the same files, and the dashboard will not change.
4. **Rhythm:** the user wants this done "in one move". The stages run in a row, with a short entry in the progress section after each and one report at the end. Work stops only for a new decision or a result that looks wrong.

```
now:    request files ──▶ ids-offline ──writes──▶ records/*.jsonl ──reads──▶ ids-dashboard ──HTTPS──▶ browser
later:  proxy copies  ──▶ ids (service) ─writes─▶ (same files)      (same dashboard)
```

## The record format: the contract between the programs

There is one JSON object per line, and every line has `"type"` and `"schema": 1`. There are three types.

1. **`start`:** written each time `ids-offline` (or later `ids`) starts. It holds:
   - the run ID and the time;
   - the engine version and the VCS revision when known;
   - the CRS signature, the paranoia level and the config fingerprint;
   - every rule's status: ID, file, line, phase, level, active or excluded, and the reason. The rules page and the engine page come from this.
2. **`request`:** written for a request with a finding or an incomplete analysis (R1). It holds:
   - `id`, `run`, `time`;
   - `alert` (score ≥ threshold) with `"decided_by": "rule layer only"` (R2);
   - `client {ip, port}` and `server {host, ip, port}`;
   - `request {method, path, query, version, user_agent, referer, content_type, body_length, header_names}`;
   - `analysis` (as in today's output);
   - `findings[] {rule_id, severity, message, location, matched, data, tags}`;
   - `score {total, threshold, categories}`;
   - `engine {version, crs, paranoia_level, config}` (R7).
   - Only when the setting is on, and only for alerts: `full {headers, body}`.
3. **`counts`:** written once a minute and at the end of a run. It holds `run`, `from`, `to`, `analysed`, `recorded`, `alerts` and `incomplete`. This is how requests without a record are still counted (R1).

The client address comes only from the connection: today the offline input's `remote_addr`, later the trusted proxy. It is never taken from `X-Forwarded-For` or any other header the client sends.

## Masking (revised R4)

1. **Headers:**
   - `Cookie`, `Authorization` and `Proxy-Authorization` values are never stored, not even in full mode.
   - Each cookie value becomes an HMAC-SHA256 hash (first 12 hex characters). The key is a random installation key in `records/hash.key` (file permission 0600), created on the first run. The same session then gives the same hash, and the value can't be recovered.
2. **Secret-looking names:** a parameter whose name contains `pass`, `pwd`, `secret`, `token`, `session`, `auth`, `apikey`/`api_key`, `card` or `cvv` (any case) is masked. This covers the query, the form, JSON (the last part of the path, e.g. `json.user.password`) and multipart fields. The config can add names.
3. **Clean-up pass over everything recorded:** the values found in steps 1–2 are collected per request. Their raw, percent-decoded and lower-case forms are then replaced by `[masked]` in every recorded string: the query, the matched part, `data`, the message, and `full`. This also catches a password that shows up inside `QUERY_STRING`, `REQUEST_LINE` or `REQUEST_BODY` matches.
4. **A finding in a masked place** (e.g. `ARGS:password` or `REQUEST_COOKIES:sid`) keeps its rule and location. `matched` and `data` become `[masked]`, and a message that can carry content gets today's placeholder (`result.Hidden`).
5. **Fixed maximum lengths:**

   | Field | Maximum |
   | --- | --- |
   | `matched`, `data` | 200 bytes |
   | path, query | 2 kB each |
   | User-Agent | 512 bytes |
   | Referer | 1 kB |
   | full body | 64 kB |

   All text goes through today's `printable` escaping.
6. **Known limit, to be written down:**
   - A secret inside the path itself, e.g. `/reset/8f3a…`, is recorded. Profiles (A04) can mask it later.
   - A secret that a rule has transformed beyond lower-casing or percent-decoding may slip past step 3.

## Configuration

1. **Product config `configs/crs-first-engine.json`** gets an optional section:

   ```json
   "records": {"dir": "../records", "max_file_mb": 10, "keep_files": 10, "full_requests": false, "secret_names": []}
   ```

   - The config file is read by a new small loader, `internal/config`. It decodes the engine fields and `records` with unknown fields still rejected, then reuses the engine's path resolution and validation from `internal/engine/config.go`. To make that possible, the engine's `LoadConfig` is split.
   - Without a `records` section nothing is written. The CRS test config `testdata/crs-tests.json` and all existing tests therefore stay unchanged.
2. **Dashboard config `configs/dashboard.json`:**

   ```json
   {"listen": "127.0.0.1:8443", "records_dir": "../records", "state_dir": "../dashboard-state",
    "tls_cert": "", "tls_key": "", "session_idle_minutes": 60}
   ```

   - Startup errors (M15 style) for: a missing records folder, a bad address, or only one of the certificate and key given.
3. **`.gitignore`** gets `records/` and `dashboard-state/`.

## Stages

### Stage 1: records (`internal/record`)

1. Types for the three record kinds and the builder for request records.
   - It reuses `result.NewScore` and `result.NewAnalysis`, today's `newScore`/`newAnalysis` exported from `internal/result/result.go`.
   - It reuses `printable` (exported) and `MessageSensitive` from `engine.Match` (`internal/engine/transaction.go`).
2. Masking, as above.
3. **Writer:**
   - one `Write` per whole line, under a mutex, so it can serve many goroutines later;
   - rotation by size: rename the current file to `records-<UTC time>.jsonl` and keep the newest `keep_files`;
   - the folder has permission 0700 and the files 0600;
   - it writes the `start` line when opened and `counts` lines each minute and on close.
4. **IDs:** `crypto/rand.Text()`.
5. **Fingerprint:** SHA-256 over the config file bytes, the bytes of each rule file in load order, and the paranoia level actually used. This way the `-paranoia-level` flag shows up too.
6. **Version:** a new `internal/version` with `Version = "0.1.0-dev"`, plus the VCS revision from `runtime/debug.ReadBuildInfo` when it is there.
7. **Addresses:**
   - `httpmodel.Received` (`internal/httpmodel/request.go`) gets `RemotePort`, `LocalAddr` and `LocalPort`.
   - The offline input (`internal/offline/offline.go`) gets optional `remote_port`, `server_addr` and `server_port`, checked the way `remote_addr` is today.

### Stage 2: alerts in `ids-offline`

1. `cmd/ids-offline/main.go` writes records when the config has a `records` section. A `-records DIR` flag replaces the folder for a run.
2. The text output says `ALERT (rule layer only)` where it now says `THRESHOLD EXCEEDED`.
3. The terminal output keeps today's strict M11 rule and `-show-values`. Records always follow R4, never `-show-values`.

### Stage 3: the dashboard (`cmd/ids-dashboard`, `internal/dashboard`)

1. **Reader:**
   - It reads every record file and then follows the current one every 2 s.
   - It copes with rotation and ignores a last line that hasn't been finished yet.
   - It keeps a small index in memory: time, ID, run, alert, score, IP, method, path, rule IDs, attack groups, locations, incomplete, and the file and offset of the line.
   - The detail page reads the whole line from disk.
   - The attack group comes from the rule file name, e.g. `REQUEST-942-APPLICATION-ATTACK-SQLI` gives SQLi.
2. **Read-only JSON API** (Go 1.22 `ServeMux` patterns). All of them filter by time range (last hour, 24 h, 7 days, all).

   | Route | What it returns |
   | --- | --- |
   | `GET /api/overview` | Counts, time series, and the top rules, groups, locations and client IPs |
   | `GET /api/alerts` | The list. Filters: rule, group, IP, minimum score, and alerts only / all records / incomplete only. 50 per page |
   | `GET /api/records/{id}` | One whole record |
   | `GET /api/rules` | Statuses from the latest `start`, plus how often each rule fired |
   | `GET /api/engine` | The latest `start`, the history of `start` records (when the config changed), and the record files (how many, their size, the oldest kept record) |

3. **Pages (V1):** overview, alerts, alert detail, rules, engine, login.
   - Built with `html/template` and `embed`, with one CSS file and one JS file.
   - JS asks the API for new data every 5 s (V6) and draws the charts as SVG.
4. **Defence against attack content.** Records hold attacker text (User-Agent, query, matched parts), so a careless page would run an attacker's `<script>`.
   - JS inserts values only with `textContent`, never `innerHTML`.
   - There is no inline script.
   - Headers: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on the API.

### Stage 4: login and HTTPS (V5)

1. **Users:**
   - They live in `state_dir/users.json` (permission 0600) as name, a 16-byte random salt, and PBKDF2-HMAC-SHA256 with 600,000 iterations (the OWASP recommendation, checked) giving a 32-byte key, using `crypto/pbkdf2`.
   - `ids-dashboard -add-user NAME` creates a user with a random password (`crypto/rand.Text()`) that is printed once. This needs no library for hidden typing, so V3 (no dependency) holds.
   - `-reset-password NAME` and `-remove-user NAME` complete the set.
2. **Login (`POST /login`):**
   - The password check is constant-time.
   - An unknown user name costs the same hash work, so nobody learns which names exist.
   - After 5 failed tries for a user name, each further try waits: 30 s at first, doubling up to 15 min. A successful login resets it.
3. **Sessions:**
   - a random token kept in memory;
   - cookie `__Host-ids-session` with `Secure`, `HttpOnly`, `SameSite=Strict` and `Path=/`;
   - an idle limit (setting, default 60 min), a total limit of 12 h, and `POST /logout`;
   - sessions end when the dashboard restarts (a known limit).
4. **Every route except `/login` and the static files needs a session.** The API answers 401 without one, and a page redirects to login. `http.CrossOriginProtection` wraps the whole handler.
5. **Login log:** `state_dir/auth.jsonl` records the time, the user name, the result and the browser's IP, never a password.
6. **HTTPS always, with no plain-HTTP listener:**
   - If `tls_cert`/`tls_key` are given, they are used.
   - Otherwise the dashboard makes its own ECDSA P-256 certificate for `localhost`, `127.0.0.1`, `::1` and the listen host. It is stored in `state_dir` (key with permission 0600), reused, and replaced when it expires. Its SHA-256 fingerprint is printed at startup.
   - TLS 1.2 is the minimum (Go's default, checked) and server timeouts are set.

### Stage 5: checks and documents

1. **Secrets test (R4/M11):** a request file with a password field, `Cookie`, `Authorization`, a `token` parameter, a JSON password and a multipart password, each carrying an attack so that rules match right there. None of these secrets may appear in the record files, the API answers or the pages.
2. **Attack content test:** records with `<script>` in the User-Agent, the query and the matched part. The API returns escaped JSON, pages show them as text, and the CSP header is present.
3. **Login tests:**
   - a table of every route without a session gives 401 or a redirect;
   - the wait after wrong passwords works;
   - sessions expire (tested with a fake clock);
   - a cross-origin POST is rejected;
   - the cookie flags are set.
4. **HTTPS test:** the server with its own certificate answers over HTTPS, and plain HTTP to the same port fails.
5. **Writer tests:**
   - rotation (with a small size and `keep_files: 3`, exactly 3 files remain);
   - many goroutines writing under `-race` give only whole lines;
   - the fingerprint changes when a rule file or the level changes;
   - a golden test for the line format.
6. **Demo:**
   - `ids-offline` on the 5,072 CRS tests at level 1. The dashboard's alert and incomplete counts must equal the numbers of `-summary`.
   - The 1,000 CSIC records as well.
   - I open each page in a browser and check it.
7. **Speed:** the cost of writing records next to `Evaluate` is measured and reported.
8. **The usual checks:** `go vet`, `go test`, `go test -race`, and fuzzing of the record builder and the reader, the reader with broken lines included.
9. **Documents:**
   - a new `docs/records-format.md`: the record contract, also for webhook, syslog and MCP later;
   - the main plan: A09, the M11 note, and history 11.23;
   - `context.md` and `docs/project-history.md`.

## Small choices made inside the decisions (open to change)

1. Users get a random password printed once, instead of typing one.
2. Sessions are kept in memory and lost when the dashboard restarts.
3. Default port 8443, refresh every 5 s, default idle limit 60 min.
4. Record files of 10 MB, 10 kept; the maximum lengths in the table above.
5. The list of secret-looking names; cookie hashes with an installation key.
6. Version `0.1.0-dev` and record schema version 1.

## Rules for the work

1. Behaviour is checked against a source. Expected test values are never guessed.
2. **No new dependency.** Everything is Go's standard library: `net/http`, `html/template`, `embed`, `crypto/{pbkdf2,rand,tls,x509,ecdsa,hmac,sha256,subtle}`, `encoding/json`. CRS files stay unmodified.
3. Stop only for a new decision or a result that looks wrong. No commit unless the user asks.

## Not in this plan

- Webhook and syslog (after the proxy).
- The live `ids` service and the proxy (step 3).
- Marking alerts (V7), changing settings (V2), roles, GeoIP.
- Block records (K4), a database.
- Masking paths per application (profiles).
- Fixing the CSIC false positives (I2).

## Verification

```
go vet ./... && go test ./... && go test -race ./...
go run ./cmd/ids-offline -requests testdata/requests/crs -summary         # writes records/
go run ./cmd/ids-dashboard -add-user admin                               # prints the password once
go run ./cmd/ids-dashboard -config configs/dashboard.json                # https://127.0.0.1:8443
```

The dashboard's numbers must match `-summary`. The secrets and attack content tests must pass, and every route must refuse access without a session.

## Progress

| Stage | Content | Status |
| --- | --- | --- |
| 1 | Records (`internal/record`) | Done 23 October 2026 |
| 2 | Alerts in `ids-offline` | Done 23 October 2026 |
| 3 | Dashboard | Done 23 October 2026 |
| 4 | Login and HTTPS | Done 23 October 2026 |
| 5 | Checks and documents | Done 23 October 2026 |

Notes on stages 3 and 4:

1. `cmd/ids-dashboard` and `internal/dashboard` as planned, with `configs/dashboard.json`. All five pages poll the JSON API every 5 s. The chart is drawn as SVG, with a table view.
2. Two small additions inside the decisions:
   - A new password (`-reset-password`) also ends that user's current logins, as removing a user does. A session keeps the salt of the password it logged in with.
   - Chart bars have round widths (1 min, 2 min … 30 days, at most 48 bars), so they start on round times.
3. Found while testing: the alerts list showed a rule twice when it matched in two places, and the score rule 949110 counted `TX:BLOCKING_INBOUND_ANOMALY_SCORE` as a place in the request. Each rule is now listed once, and only attack rules give locations.
4. Tests: the store (rotation, an unfinished last line, a replaced file, broken lines), filters, counts, every route without a session, cookie flags, the wait after wrong passwords, session limits with a fake clock, cross-origin posts, HTTPS only (plain HTTP and TLS 1.1 refused), the certificate, and the command.

Notes on stage 5:

1. All checks of the plan ran; the results are in main plan section 11.23.
2. Two faults were found and fixed:
   - The engine package's tests read the product configuration with the strict engine loader, which refuses the `records` section added in stage 2. Stage 2 had run only the command's tests.
   - Secret values under four characters (a card code) were not removed from findings that hold the whole query or body.
3. New documents:
   - `docs/records-format.md`;
   - main plan A09 and section 11.23;
   - `context.md`, `docs/project-history.md`, and the README of `testdata/requests/`.
