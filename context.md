# IDS — Current Working Context

Last updated: 20 November 2026  
Product directory: this repository (`/home/esip/Documents/ids-system` on the first development machine)  
Main architecture reference: [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md)

## 1. What is the project?

A general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. Phase 1 started with SQLi, request-borne XSS, and path traversal; since 12 October 2026 the rule part is being extended to all request rules of CRS (decision K6). It produces alerts and does not block requests.

Planned product: a Go core, our own SecLang rule engine running CRS 4.30.0 at a configurable paranoia level, an ML layer, manually defined application profiles, and a decision mechanism that combines them. HTTPS traffic arrives as request copies from an existing reverse proxy. **Of these, the rule layer and hand-written application profiles exist**, working on offline requests and on live copies from Caddy, with records, alerts, and a read-only dashboard (records and dashboard since 23 October 2026, UI reworked on 24 October, profiles since 25 October, live traffic through Caddy since 18 November). The rest is approved design (M01–M21), not working features.

## 2. What we have made

**The rule layer runs every CRS 4.30.0 request rule file, at all four paranoia levels:** 905 (common exceptions), 911 (method enforcement), 913 (scanner detection), 920 (protocol enforcement), 921 (protocol attacks), 922 (multipart attacks), 930 (path traversal and file access), 931 (remote file inclusion), 932 (remote command execution), 933 (PHP), 934 (generic attacks), 941 (XSS), 942 (SQL injection), 943 (session fixation), and 944 (Java attacks), 286 detection rules in all, from the unmodified CRS files, with the setup, gate, and scoring rules they depend on. The rule part is finished; response rules wait for the proxy decision. See section 3.

**Records, alerts, and a dashboard (23 October 2026):** `ids-offline` writes a JSON Lines record for every request with a finding or an incomplete analysis, with secrets masked (R4), and marks alerts (score at or above the CRS threshold, "rule layer only"). `ids-dashboard` shows them behind a login over HTTPS. Format and masking: [docs/records-format.md](docs/records-format.md).

**Dashboard UI (24 October 2026):** after a browser check of every page, 37 UI problems were fixed following [docs/development-plan-dashboard-ui.md](docs/development-plan-dashboard-ui.md), with decisions U1–U8 (main plan section 11.24). Among them:
- the period is kept between pages, and updates can be paused;
- a failed update no longer wipes the page;
- after logging in, the user returns to the page they were on;
- a chart bar opens the records of its period;
- one-line alert rows, sorting by score, and a bar for new alerts;
- the alert page has named categories, findings grouped by rule, copy buttons and the record as JSON;
- the rules page is grouped by file, shows rule descriptions (new optional `msg` in the `start` record) and three statuses;
- a theme switch.

**Application profiles (25 October 2026):** built following [docs/development-plan-profiles.md](docs/development-plan-profiles.md), decisions F1–F11 (main plan sections 11.25 and 11.26); the contract is [docs/profile-format.md](docs/profile-format.md).
- A JSON profile per application, listed under `applications` in the product configuration and chosen by Host and path prefix, never by a client header.
- An allow list of endpoints, parameters, cookies and headers; findings are recorded (`monitor`) or alerts (`alert`), apart from the rule score.
- Rule exceptions per application (a CRS setting, a rule skipping variables, a rule off) and a paranoia level per application, applied per request on one shared rule set (option B).
- Records carry `application`, `profile` and `alert_by`; the dashboard filters by application and shows each application's exceptions and level.
- The CSIC shop's profile (`profiles/csic-shop.json`, `configs/csic-shop.json`), written from the training records only, level 2, three exceptions accepted by the user. Test records: false alarms 30 → 3 of 100; Coraza gives the same rule results.

**Live traffic through Caddy (18 November 2026, closed 19 November):** built following [docs/development-plan-proxy.md](docs/development-plan-proxy.md), decisions T1–T12 (main plan sections 11.27 and 11.28); the contracts are [docs/copy-format.md](docs/copy-format.md) and [docs/records-format.md](docs/records-format.md).
- The Caddy module `ids_copy` copies each request and its response while they pass, and sends the copies over a Unix socket to `ids-live`, which analyses them with the same engine, profiles and records as `ids-offline`.
- The site never waits for the IDS: queues with limits on both sides; a copy that does not fit, or can't be sent, is dropped and counted in a `gap` record.
- Records carry the proxy's request ID, the connection, TLS and the response; the dashboard shows gaps, unknown application names, the copier status and a warning when `ids-live` stops writing. The dashboard follows IBM Carbon since the same day.
- The lab (`lab/`): the 396 CSIC requests give the same records live as offline; the copier adds about 0.02–0.2 ms at the median; every dropped copy is counted.

**Test a request (19 November 2026):** a "Test" tab in the dashboard, built following [docs/development-plan-test-tab.md](docs/development-plan-test-tab.md), decisions S1–S4 (main plan sections 11.29 and 11.30).
- Write a request as raw HTTP text, or load a built-in example or one of CRS's own tests by rule; choose the configuration (`test_configs` in `dashboard.json`), the paranoia level, the application and a client address; see every rule finding with its matched value, the score, the profile's findings and what the engine read.
- The dashboard runs the IDS's own engine and profiles through `internal/analysis`, the one analysis that `ids-offline` and `ids-live` also run, and keeps nothing: no record, no setting, no log line with the request.
- Its answers equal `ids-offline -json -show-values` for all 5,066 CRS tests that raw text can hold and the 1,000 CSIC requests.

**Navigation panel (21 November 2026):** the pages are in a panel on the left, in groups (Monitor, Rules, System, Administration), folded behind a Menu button below 1312 px; details in the dashboard UI plan, "The side navigation".

**A dashboard that controls the IDS (21 November 2026):** built following [docs/development-plan-dashboard-control.md](docs/development-plan-dashboard-control.md), decisions W1–W26 (main plan sections 11.34 and 11.35), in seven committed stages.
- Pages per application (Summary, Rules, Profile, Settings, History) and per rule; Settings for every application; Clients, Endpoints, Records, Analyse files, Proposed changes and Dashboard settings.
- Changes to the IDS wait as pending changes with a preview from the records, are applied as one version that can be undone, and are written into the IDS's own configuration and profiles (`ids_config` in `dashboard.json`); analysts propose, admins apply.
- `ids-live` reads its configuration every 3 seconds and takes a change without stopping (`-watch`); `scripts/ids-live-ctl` starts and stops it.
- Each stage's note in the plan lists the choices made that the decisions did not settle; they wait for the user's approval.

**The dashboard on IBM Carbon's own components (21 November 2026):** built following [docs/development-plan-dashboard-carbon.md](docs/development-plan-dashboard-carbon.md), decisions Y1–Y10 (main plan sections 11.36 and 11.37), in five committed stages.
- IBM's Carbon web components 2.68.0, its themes and icons are in `internal/dashboard/web/static/carbon/`, made by `tools/carbon-fetch.sh VERSION` (with `tools/carbonprep`); do not edit them by hand. `carbon.js` loads the components; `app.js` builds the pages with them.
- Static files are served under `/static/<version>/` and kept by the browser; the policy allows inline style attributes only (`style-src-attr 'unsafe-inline'`).
- Fields, selects and buttons are HTML controls drawn as Carbon's (app.css); tables are HTML tables in Carbon's look.

**Marks, users with roles and a change log (20 November 2026):** built following [docs/development-plan-marks-users.md](docs/development-plan-marks-users.md), decisions G1–G6 (main plan sections 11.31 and 11.32); the state files are described in [docs/dashboard-state.md](docs/dashboard-state.md).
- A verdict per alert (not reviewed, real attack, expected, false positive, undetermined) with a note, set on one record, the chosen ones or all that match the list's filter (at most 10,000); a Review column and filter; "not reviewed" on the overview; false positives per rule on the Rules page, also of records that rotated away.
- Three roles as a ladder: viewer, analyst (also marks and tests), admin (also Users and Log). Users, roles and passwords on the Users page, each change after the admin's password; everyone can change their own password (at least 15 characters).
- An append-only change log, shown with the logins on the Log page to admins. Until 21 November the dashboard wrote only its state folder; since then it also writes the IDS's settings (W12) and, on an admin's request, deletes records (W19).

Run it:

```
go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json      # also writes records/ (gitignored)
go run ./cmd/ids-offline -config testdata/crs-tests.json -requests testdata/requests/crs -summary
go run ./cmd/ids-offline -config configs/csic-shop.json                     # the CSIC shop's applications and exceptions
go run ./cmd/ids-offline -endpoints -requests FILE                            # endpoints and parameters of a file, for writing a profile
go run ./cmd/ids-offline -requests FILE -replay                               # records at the requests' own "time", in time order (a replay)
go run ./cmd/ids-dashboard -add-user admin                                    # prints the password once; -role viewer|analyst|admin (default admin)
go run ./cmd/ids-dashboard                                                    # https://127.0.0.1:8443
go run ./cmd/ids-live -config FILE                                            # needs a live section, or -socket; see docs/copy-format.md, section 6; takes changed settings by itself
IDS_LIVE_CONFIG=FILE scripts/ids-live-ctl start                               # ids-live in the background: start, stop, restart, status
lab/lab.sh build && lab/lab.sh equality                                       # the lab: Caddy with ids_copy, ids-live, the CSIC requests; outputs in /tmp/ids-lab
```

The dashboard makes its own certificate on first start and prints its SHA-256 fingerprint; the browser warns once until it is accepted. `testdata/crs-tests.json` has no `records` section, so CRS test runs write records only with `-records DIR`.

### 2.1. Code

Go module `github.com/EfeSipahi/ids-system`. One dependency: `github.com/corazawaf/libinjection-go`. The Caddy copier is a module of its own in `caddy-module/`, the only place Caddy is a dependency (T11).

| Package | What it does |
| --- | --- |
| `internal/seclang` | Parses CRS rule files into Go values. Six directives are supported; any other is an error |
| `internal/httpmodel` | The common request (M03, M16): received content, parsed view, analysis status (M05). Reads the query, cookies, and form, JSON, multipart, and XML bodies |
| `internal/offline` | Reads example requests from JSON, with optional `expect_ids` / `no_expect_ids`; reads and writes a request as raw HTTP text (`ParseRaw`, `Raw`) for the test tab |
| `internal/analysis` | `Run`: the one analysis of a request (the rules with the application's exceptions and level, then the profile) that `ids-offline`, `ids-live` and the test tab run; own rules for some applications only are off for the others |
| `internal/engine/transform` | 17 transformations. 12 are ports of the ModSecurity v2 functions, `length` counts bytes; `normalizePath`, `normalizePathWin`, `htmlEntityDecode`, and `base64Decode` follow Coraza (main plan sections 11.15 and 11.18); `normalizePathWin` leaves out Coraza's cut at a colon, which could hide a file name |
| `internal/engine/operator` | `@rx`, `@pm`, `@pmFromFile`, `@detectSQLi`, `@detectXSS`, `@contains`, `@streq`, `@within`, `@beginsWith`, `@endsWith`, `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`, `@eq`, `@lt`, `@ge`, `@gt`, `@unconditionalMatch` |
| `internal/engine` | `Load` prepares a read-only rule set and refuses to start on anything unsupported (M15). `Evaluate` runs phases 1 and 2 for one request with its own state (M21). `NewTuning` and `EvaluateWith` apply one application's exceptions and level per request (`tuning.go`). Own rules (`own_rules`, `own.go`, since 23 November 2026): a file of rules people write, checked to detect only and loaded right before CRS's 949 file ([docs/development-plan-own-rules.md](docs/development-plan-own-rules.md)) |
| `internal/profile` | Application profiles: strict reading, the choice of application, the allow-list checks, secrets, the exception policy, and the `-endpoints` survey |
| `internal/result` | Output records: analysis status, findings, score, and `Analysed` (with the application and profile result). Request content is left out of the terminal output by default (M11). The startup report's text, shared by `ids-offline` and `ids-live` |
| `internal/config` | The product configuration: engine settings plus the optional `request_body_limit` (default 13,107,200 bytes, as Coraza), `records`, `applications`, `require_profile` and `live` sections, the `own_rules` file, and the configuration fingerprint (R7), which covers the profiles and the own rules |
| `internal/record` | Record files (R1–R7): building and masking request records, `start`, `counts` and `gap` records, the live fields (proxy, connection, TLS, response), rotation, file permissions, cookie hashes, the folder's lock |
| `internal/copyframe` | The copy frames between a proxy's copier and `ids-live` (`docs/copy-format.md`) |
| `internal/live` | The live input (A01): the Unix socket, hello frames, a queue with limits, workers, gap counts, the stop; turns a copy into the common request and analyses it as `ids-offline` does |
| `internal/dashboard` | The dashboard: reader of the record files (also gaps and the live fields), JSON API, pages (embedded HTML, CSS, JS) built with IBM Carbon's web components, themes and icons (`web/static/carbon/`, Apache-2.0, made by `tools/carbon-fetch.sh`) and IBM Plex fonts (`web/static/fonts/`, OFL-1.1), users with roles, login, sessions, its own certificate, the test tab (`tester.go`, built-in examples in `web/examples.json`), marks (`marks.go`), the Users, Account and Log pages and the change log (`admin.go`), and the lock of its state folder |
| `internal/version` | The program version `0.1.0-dev` and the Git revision of the build |
| `cmd/ids-offline` | Command-line tool: `-config`, `-requests` (file or directory), `-summary`, `-json`, `-show-values`, `-paranoia-level`, `-records DIR`, `-application NAME`, `-endpoints`, `-replay` (records at each request's own `time`, decided 20 November 2026, main plan 11.33) |
| `cmd/ids-live` | The live input as a service: `-config`, `-socket`, `-records`; stops on SIGTERM. Needs a `live` and a `records` section, or the flags |
| `caddy-module/` | The Caddy module `ids_copy` (its own `go.mod`, Caddy v2.11.9): copies each request and response while they pass, and sends the copies to `ids-live`; counts what it can't send. Build: `xcaddy build v2.11.9 --with github.com/EfeSipahi/ids-system/caddy-module=./caddy-module --replace github.com/EfeSipahi/ids-system=.` (xcaddy v0.4.7) |
| `cmd/ids-dashboard` | The dashboard: `-config` (default `configs/dashboard.json`), `-add-user` with `-role`, `-reset-password`, `-remove-user` |

Other files:

| Path | Content |
| --- | --- |
| `configs/crs-first-engine.json` | The product configuration. Loads nineteen CRS files; 456 of 460 rules active, 4 excluded with a written reason each (all in file 901). Optional `paranoia_level`, 1 to 4, default 1. Its `records` section writes records to `records/` |
| `configs/csic-shop.json`, `profiles/csic-shop.json` | The product configuration with the CSIC shop as an application, and its profile |
| `configs/dashboard.json` | The dashboard configuration: listen address `127.0.0.1:8443`, records folder, state folder `dashboard-state/` (users, certificate, login log), optional certificate files, idle limit, and the test tab's configurations and CRS test folder |
| `docs/records-format.md` | The record format: the contract between the IDS and its readers, masking rules, known limits |
| `docs/copy-format.md` | The copy frames between a proxy's copier and `ids-live`, and how to set up both (section 6) |
| `docs/development-plan-proxy.md` | The plan for live traffic through Caddy (finished 19 November 2026): research, decisions T1–T12, notes 1–8 with every lab measurement |
| `docs/development-plan-marks-users.md` | The plan for marking alerts, users with roles and a change log (finished 20 November 2026): decisions G1–G6, consequences C1–C8, notes 1–5 with the checks |
| `docs/dashboard-state.md` | The dashboard's state files: users, lock files, the log of logins, the change log, the marks |
| `docs/dashboard-roadmap.md` | What the dashboard still needs, in parts with their decisions and a suggested order (21 November 2026) |
| `docs/development-plan-test-tab.md` | The plan for the dashboard's test tab (finished 19 November 2026): decisions S1–S4, notes 1–5 with the checks and the time of 1 MiB requests |
| `lab/` | The lab: `testapp`, `replay`, `compare`, `Caddyfile` and `lab.sh` (development plan, note 7) |
| `docs/development-plan-records-dashboard.md` | The plan for records, alerts, and the dashboard (finished 23 October 2026), with notes per stage |
| `docs/development-plan-dashboard-ui.md` | The dashboard UI plan (finished 24 October 2026): problems P1–P37, decisions U1–U8, notes and checks |
| `docs/development-plan-profiles.md` | The profile plan (finished 25 October 2026): decisions F1–F11, stages, notes 1–18 with every measurement and the CSIC results |
| `docs/profile-format.md` | The profile format: applications, endpoints, values, exceptions, findings, known limits |
| `testdata/requests/` | Example requests: starter file, all 5,072 converted CRS request tests (`crs/`), examples for file 905, 1,300 generated variants (`generated/`); see its README |
| `testdata/crs-tests.json`, `testdata/crs-test-setup.conf` | The configuration the CRS tests are written for: the product configuration plus CRS's test setup rule 900005, at level 4 |
| `testdata/reference/` | What Coraza found for those requests; see its README |
| `tools/` | Python scripts that generate the test data; `coraza-reference/`, a separate Go module that runs Coraza (Coraza is not a dependency of the IDS); `carbon-fetch.sh` and `carbonprep/`, which put IBM Carbon's files into the dashboard |
| `docs/development-plan-all-request-rules.md` | The plan for all request rules (finished 16 October 2026): plans A to F, with results after each |
| `docs/development-plan-rule-layer.md` | The earlier plan (finished 11 October), with results per stage in its section 8 |
| `docs/project-history.md` | What was done and how, 27 September to 19 November 2026, written for the project report |
| `docs/crs-4.30.0-ruleset.md` | Reference for the CRS files and our scope |
| `docs/go-learning-plan.md` | The user's Go learning plan |

### 2.2. What was checked (16 October 2026, records and dashboard on 23 October, dashboard UI on 24 October, profiles on 25 October, live traffic on 18–19 November)

**20 November, marks, users with roles and the change log** (details in its plan, notes 2–5):

1. Every route as no login, viewer, analyst and admin; the last admin stays; a role change, a reset and a removal end the user's sessions; five wrong passwords at a change make the login wait too.
2. Two programs changing `users.json` at once lose nothing (31 of 31 users; without the lock, 16 of 31).
3. One change log entry per action; no password in any file of the state folder; the records folder unchanged.
4. Marks: by IDs and by filter, history in order, after a restart, after the record rotated away, 10,000 records in 27 ms and 10,001 refused; `FuzzStoreReadsAnyFile` also reads marks.
5. Four browser rounds as admin, analyst and viewer, light and dark; two defects fixed.

**19 November, the test tab** (details in its plan, notes 2–5):

1. Raw text: 6,384 of the 6,391 example requests are written as text and read back the same; 7 can't be (six with spaces around a header value, which Go's server removes too, and one body that is not UTF-8 text).
2. The tab's answers equal `ids-offline -json -show-values`, through the real API: 5,066 CRS tests with `testdata/crs-tests.json` (every expectation met), and the 1,000 CSIC requests with `configs/csic-shop.json` and with `configs/crs-first-engine.json`.
3. `ids-offline`'s output is byte for byte the same as before the shared analysis, in 8 runs; its records too.
4. Browser: three Playwright rounds at 1440 and 1024 px, light and dark; four layout defects fixed.
5. A 1 MiB request takes 0.3–3.8 s at level 1 and 2.1–9.8 s at level 4; at most two run at once.

**18–19 November, live traffic through Caddy** (details in the proxy plan, notes 4–8):

1. Live equals offline: 1,318 example requests give the same 850 records (Go test), and the 396 CSIC requests through a real Caddy the same 162 records (lab).
2. The site never waits: with `ids-live` hung or stopped, the times equal those without the copier; the copier adds about 0.02–0.2 ms at the median.
3. Every copy that is not analysed is counted: 7,920 = 235 analysed + 2,429 + 5,256 dropped under overload; a stop of `ids-live` gave a gap of exactly the 132 requests sent meanwhile.
4. TLS 1.3, HTTP/2 and HTTP/3, trusted proxies, response types and limits, slow responses and WebSockets.
5. No secret reaches the records through the live input (a new fuzz test).
6. The close on 19 November: `gofmt`, `go vet`, `go test` and the race detector in both modules, seven fuzz tests, and unchanged numbers (CRS 2,916 of 5,072; CSIC 96 / 176; the CSIC profile's validation and test numbers).

**25 October, application profiles** (details in the profile plan, notes 4, 7, 10, 13, 16 and 18):

1. Per-application exceptions equal the same changes written in SecLang on all 5,072 CRS tests at levels 1–4; one application's exceptions never change another's results (8 goroutines); about 0.2–0.3 % slower.
2. Without applications nothing changed: CRS summary 2,916 alerts at level 1; CSIC 96 / 176 flagged; the old golden record is unchanged.
3. No profile secret reaches records, API answers or pages; a fuzz test found and closed an older gap with JSON-escaped secrets in full JSON bodies.
4. The dashboard was checked in two browser rounds on demo records with two applications; four bugs found and fixed.
5. The CSIC profile was measured once on validation and test, and compared with Coraza on all 396 of those records at levels 1–4: the same rule results.
6. `gofmt`, `go vet ./...`, `go test ./...` and the race tests pass.

**24 October, dashboard UI:**

1. **Go checks.** `gofmt`, `go vet ./...` and `go test ./...` pass. `go test -race` passes for the dashboard, engine and record packages.
2. **New tests:**
   - the 404 page;
   - the kept login name;
   - `next` against open redirects;
   - `sort` and `from`/`to`;
   - counts per run;
   - rule descriptions checked against the CRS files.
3. **Numbers.** The dashboard still equals `-summary` on the CRS records: 5,072 analysed, 2,967 records, 2,916 alerts, 154 incomplete.
4. **Browser.** browser-use went through every page and action at 1440 px, dark and light: no sideways overflow and no script errors. The full list is in the plan's Progress section.
5. **Second check.** Screenshots of every page found cut chips, two-row filters, rules filters missing from the address, jumping rule columns, uneven chart labels and categories not adding up to the score. All fixed and checked again in the browser; dashboard tests pass.

**23 October, records and dashboard:**

1. No secret appears in record files, API answers, or pages:
   - the real CRS configuration on `testdata/requests/secrets.json`;
   - a fuzz test with any secret.
2. Attack text such as `<script>` is never served as HTML.
3. Login and HTTPS:
   - every route needs a login;
   - the wait after wrong passwords and the session limits work;
   - cross-origin posts are refused;
   - plain HTTP and TLS 1.1 are refused.
4. The dashboard's numbers equal `ids-offline -summary`:
   - 5,072 CRS tests at level 1: 2,916 alerts, 154 incomplete;
   - 1,000 CSIC records: 272 alerts.
5. A record costs about 0.04 ms, next to about 0.6 ms of analysis.
6. `go vet ./...`, `go test ./...`, and `go test -race ./...` pass for all packages. Details: main plan section 11.23.

**16 October, rule layer:**

1. `go vet ./...`, `go test ./...`, and `go test -race ./...` pass for all eight packages.
2. **CRS regression tests:** all 5,072 convertible tests of the request rule files pass with the CRS test setup at paranoia level 4, the level the CRS project runs them at. At levels 1 to 3 a test passes when its rule belongs to the level, and a rule above the level never matches.
3. **Against Coraza v3.8.1:** 6,372 requests compared at level 1 (3,813 with a match) and at level 4 (5,994 with a match). Rules, match places, match counts, and scores are identical, with five explained classes, each checked by its own rule: invalid UTF-8 (`utf8toUnicode`), bodies without a reader (Coraza splits them into parameters; we, like ModSecurity, do not), targets that Go's URL parser changes (Coraza re-encodes `REQUEST_URI`; ModSecurity and we use it as sent), HTTP/0.9 request lines, and the order of multipart headers. The reference is produced with Coraza's build option `coraza.rule.no_regex_multiline`; see `testdata/reference/README.md` for why.
4. **Transformations:** 12 agree with 10,829 results recorded from the ModSecurity v2 C code; the 4 that follow Coraza agree with 4,901 results recorded from Coraza's Go code.
5. **M21:** attack and normal requests alternate against one rule set, in sequence and in eight goroutines, without affecting each other.
6. **M11:** the default text and JSON output contain none of the payloads of the example file.
7. **Fuzzing** (16 October 2026) of the whole rule layer, the prefilter, the transformations, and the body parsers found no crash.

### 2.3. Two measurements, and what they do not show

1. **Pilot records:** of the 1,000 CSIC records of the ML pilot, flagged normal / anomalous: level 1: 96 / 176; levels 2 to 4: 500 / 500. At level 1 rule 920250 flags Latin-1 text, which is not valid UTF-8 (CRS checks UTF-8 by default); with CRS's setting for non-UTF-8 applications level 1 flags 0 / 116. At level 2 rule 920451 flags the `Accept-Charset` header that every 2010 record carries. Coraza flags the same numbers at every level. These are settings for one application (profiles, K10), not engine errors; the data is also far from today's traffic. This is not a false-positive rate or a detection rate for real traffic: the data is old and synthetic, and "anomalous" there includes many requests outside our three attack types.
2. **Speed** on the development laptop, with all request rule files: 0.55 ms for an ordinary GET and 19 ms for a request with a 9.4 kB field on one core; on 12 threads one ordinary request every 0.12 ms, about 8,000 per second. Plan F made it two to three times faster without changing a result (word prefilter for patterns, values built once per request).

### 2.4. What it does not do

1. Live traffic works through Caddy only; the Nginx input is planned later (T1). It was measured in the lab on this machine with replayed CSIC requests, not on a real site. Response bodies are copied but not analysed until the response rules (K8).
2. There is no ML layer, learned profile, or decision mechanism. An alert is the rule layer's score at the CRS threshold, or a profile finding of an application in `alert` mode, not the planned decision. The dashboard only reads; alerts cannot be marked yet (V7), and there is one user role.
3. Request rules only; no response rules (they need a copy of each response, K8).
4. A `text/plain` body is not split into fields. Since plan B the rules that read `REQUEST_BODY` inspect it as one text; it is still reported as not inspected.
5. Passing the CRS tests is not full CRS compatibility, and no request has been run through ModSecurity itself.

### 2.5. Other facts

- The Python Random Forest pilot is in the separate [ids-model](../ids-model/) directory and is not integrated. Its test set has already been observed.
- Go version last verified: `go version go1.26.10-X:nodwarf5 linux/amd64` (17 November 2026). `go.mod` needs Go 1.26.8 or newer. Fedora's packaged Go is set to `GOTOOLCHAIN=local` and never downloads a newer Go itself, so the distribution must ship one that is new enough.
- Setting up another machine: clone the ML repository (GitHub `EfeSipahi/Lorica`) as `../ids-model`, next to this one, because `tools/csic_to_examples.py` reads it from there; the Go tests don't need it. `.gitattributes` keeps LF line endings on every system, because tests compare files byte for byte. In WSL2, keep the clone in the Linux file system (`~/...`), not under `/mnt/c`, as Microsoft recommends for speed.
- Git: everything up to the notes for setting up another machine (17 November 2026) is on `main` and pushed to GitHub, including stages 1–3 of the proxy plan (commits `659a0f1`, `2be0781`, `5fba3dc`, 30 October 2026). Stages 4 to 7 of the proxy plan (18 November 2026) are committed and pushed: stage 4 `6c376ce`, stage 5 `353d63e`, stage 6 `a378c5b`, stage 7 `f1bc32f`. Stage 8, the close (19 November 2026), the test tab (the same day), and marks, users and the change log (20 November 2026) are committed and pushed as `2e46365`; the replay of request files (20 November 2026, main plan 11.33) in the commit after it. `proje_oneri_formu.docx` holds personal data and is deliberately left uncommitted. The local branches `rule-layer` and `first-offline-engine` point to commits that are on `main` and can be deleted.

## 3. What we are going to do

### 3.1. Finished: all CRS request rules, all paranoia levels

On 12 October 2026 the user decided to finish the rule part before any other layer (decisions K1–K11, main plan section 11.16). The work follows [docs/development-plan-all-request-rules.md](docs/development-plan-all-request-rules.md). **The user wants one plan at a time: do it, report, stop.**

| Plan | Content | Tests to pass | Status |
| --- | --- | --- | --- |
| A | Paranoia levels, test base, files 913, 930, 941, 942 | 1,388 | **Done 12 October 2026** |
| B | Request variables, small operators, engine items; files 911, 931, 943, 944 | 1,273 | **Done 12 October 2026** |
| C | `normalizePath`, `escapeSeqDecode`, `base64Decode`; files 932, 933, 934 | 1,818 | **Done 16 October 2026** |
| D | Protocol rules; files 920, 921, 905, and the tests of 901 and 949 | 546 | **Done 16 October 2026** |
| E | Multipart rules; file 922 | 47 | **Done 16 October 2026** |
| F | Checks on the whole set: Coraza, normal traffic, speed, documents | all 5,072 | **Done 16 October 2026** |

The plan is finished. Records, alerts, and the dashboard followed on 23 October (section 3.3).

Response rules (CRS files 950–980) are not part of this; they wait for the proxy decision (K8).

### 3.2. Other open points

| # | Point | Why it matters |
| --- | --- | --- |
| 1 | Speed on long values | 19 ms for 9.4 kB after plan F. Most of the rest is in patterns without a fixed word, mostly the command-evasion rules of file 932 |
| 2 | Realistic normal traffic (A07) | The only normal traffic so far is the 500 CSIC records from 2010, which CRS flags heavily for reasons of that one application (Latin-1 text, an old header). False-alarm numbers need recent, real traffic of a target application |
| 3 | User review | The user has not read the code. Reading order: [docs/go-learning-plan.md](docs/go-learning-plan.md), then `internal/engine/transaction.go` |

### 3.3. After the rule part (order decided by the user, 12 October 2026)

1. Records, alerts, and a dashboard (A09), built as one step. **All its decisions were made on 23 October 2026** (main plan section 11.22):
   - R1–R7: a record for each request with a finding or an incomplete analysis; an alert is a score at or above the CRS threshold, labelled "rule layer only"; JSON Lines files rotated by size; each record carries an ID, time, versions, paranoia level, and configuration fingerprint; alerts are shown in a dashboard.
   - Revised R4: records hold the client IP and port (trusted address only), target, method, path, query, User-Agent, Referer, header names, and the matched part of each finding; `Cookie`, `Authorization`, and secret-looking parameters are masked; full headers and body only with a setting that is off by default.
   - V1–V7: a separate read-only program `ids-dashboard` that reads the record files; six pages; Go standard library; pages poll a read-only JSON API; login with PBKDF2 password hashes; HTTPS built in and always on; alert marking later.
   - The user's direction for prevention (K4): let requests through, then block the IP or other identifiers after an abnormal request.

   **Done on 23 October 2026** following [docs/development-plan-records-dashboard.md](docs/development-plan-records-dashboard.md); results in main plan section 11.23. The UI was reworked on 24 October ([docs/development-plan-dashboard-ui.md](docs/development-plan-dashboard-ui.md), main plan section 11.24).
   - **Decided 24 October:** the rules page's file sections all start closed (the user changed U2). A second browser check the same day fixed cut chips, the filter row, rules filters in the address, chart labels and the category sum (UI plan, note 5).
2. Hand-written application profiles (A04). **Decided and built on 25 October 2026** (F1–F11, main plan sections 11.25 and 11.26) following [docs/development-plan-profiles.md](docs/development-plan-profiles.md).
   - JSON profiles, one per application, chosen by host and path prefix (later the proxy route), never by a client header.
   - An allow list of endpoints, parameters, cookies and headers; findings are recorded (`monitor`) or alerts (`alert`).
   - Rule exceptions per application (a CRS setting, a rule skipping targets, a rule off), applied per request on one shared rule set (option B, measured against one copy per application). Rules of files 901 and 949 can't be excepted.
   - A paranoia level per application.
   - The CSIC profile is the first one (I2), written from the training records only.
   - All eight stages were done on 25 October 2026, including the CSIC profile (`profiles/csic-shop.json`, `configs/csic-shop.json`; results in the plan's notes 17–18).
3. **Done:** live traffic through Caddy (A01, A08). **Decided on 26 October 2026** (T1–T12, main plan section 11.27), built following [docs/development-plan-proxy.md](docs/development-plan-proxy.md); all eight stages are done (main plan section 11.28).
   - Done and pushed: stage 1 (the plan), stage 2 (the copy frame format, `internal/copyframe`), stage 3 (the request body limit of 13,107,200 bytes and partly inspected bodies).
   - Done, committed and pushed 18 November 2026 (`6c376ce`): stage 4, the live input and its records (`internal/live`, `cmd/ids-live`, the `live` section, the record fields, `gap`, the lock); the plan's note 4 has the details and checks. The user decided that live records keep the proxy's request ID and receive time (`proxy`).
   - Done, committed and pushed 18 November 2026 (`353d63e`): stage 5, the Caddy copier (`caddy-module/`), and the format amendment the user decided (revised option A: `ids-live`'s hello gives `max_frame`, and the copier fits each copy into it). The plan's note 5 has the details and checks.
   - Done, committed and pushed 18 November 2026: stage 6, the dashboard (gaps, not-analysed totals, unknown names, the copier status and the user's option A, a warning when `ids-live` stops writing; the live fields on the detail and Engine pages), and the dashboard's new look, IBM Carbon, chosen by the user the same day (UI plan, section "The Carbon look"). The plan's note 6 has the checks.
   - Done, committed and pushed 18 November 2026: stage 7, the lab (`lab/`) and its measurements; every check of verification item 5 passed, the numbers are in the plan's note 7. In short: the 396 CSIC requests give the same records live as offline; the copier adds about 0.02–0.2 ms at the median and the site never waits for `ids-live`; every dropped copy is counted.
   - Done 19 November 2026: stage 8, the close: the format documents (`docs/copy-format.md` gained section 6, how to set up `ids-live` and the copier), the project history (section 4.9), the main plan's history 11.28, and the full checks (the plan's note 8). Committed and pushed as `2e46365`.
   - Caddy with our own Go copier module (`caddy-module/`, its own `go.mod`, the only new dependency); later an Nginx `mirror` input, then an Nginx module.
   - Copies over a two-way Unix socket in our own frame format (`docs/copy-format.md`) to a new program, `ids-live`, which runs the same engine and profiles as `ids-offline` and writes the records.
   - Request bodies up to 12.5 MB and text responses up to 512 KB (Coraza's limits), partial past that; the client IP only from Caddy; the application named in the Caddy configuration; bounded queues, drops counted; fail-open with gap records; Caddy terminates TLS.
   - Decided by the user on 19 November 2026: `ids-offline` keeps its name.

   **Done 19 November 2026 (the user's choice):** a request test tab in the dashboard, decisions S1–S4 (main plan sections 11.29 and 11.30), following [docs/development-plan-test-tab.md](docs/development-plan-test-tab.md); all five stages are done, committed and pushed as `2e46365`.

   **Done 20 November 2026:** extending the dashboard beyond reading, first part: marking alerts, users with roles and a change log (G1–G6, main plan sections 11.31 and 11.32), following [docs/development-plan-marks-users.md](docs/development-plan-marks-users.md); all five stages done, committed and pushed as `2e46365`.

   **Next:** the dashboard's further parts, listed with their dependencies and a suggested order in [docs/dashboard-roadmap.md](docs/dashboard-roadmap.md) (21 November 2026): an application selector that every page follows (the user's idea), a safe change path with a preview and undo, a reload of `ids-live`, exceptions from false positives, application settings and a profile editor, a page per rule, own rules, more views, and system control last. Each part needs its own decisions first; then the response rules (K8) and alerts by webhook and syslog. Then response rules, and alerts sent by webhook and syslog (decided 23 October 2026). Each needs its own decisions first.
4. Transfer of the ML model, which the user improves in the separate project, and the decision mechanism (A10, A05, A07, A06).
5. Prevention, learned profiles, other protocols.

Each still needs its own decisions before work starts.

**Ideas from the user, not yet placed exactly** (main plan section 6.15):

1. **I1:** one MCP server through which an AI assistant configures the IDS and corrects false positives (confirmed by the user on 23 October 2026). The user places it after the dashboard and a usable IDS.
2. **I2:** correct the false positives found on the CSIC 2010 normal records. **Done on 25 October 2026** by hand, with the profile work (item 2, F10). The training records no longer measure false positives independently; validation and test are reported separately (A07).
3. **I3 (26 October 2026):** an installer, plus setup from the dashboard, once everything else is done. Nothing decided; it needs roles, permissions and a change history first, because a dashboard that changes the proxy controls all the traffic.

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
3. Working mode for code: small packages with tests and an explanation of each. For the request-rule plan the user asked for one plan at a time, then for E and F together; that plan is finished, so return to one step at a time with a pause for review unless told otherwise. The user knows Python and finished a Go course.
4. Check behaviour against a source before writing it down. Expected values in tests must come from the rule files, a reference implementation, or an independent count, not from a guess. Several times in this project a guessed value or a remembered behaviour was wrong and only a reference caught it.
5. Approved Go dependencies may be downloaded by the assistant. Propose a new dependency first.
6. Do not commit unless the user asks.
7. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
8. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
9. `configs/crs-first-engine.json` and `configs/csic-shop.json` write records to the repository's `records/` folder, which holds the user's own records for the dashboard. For a check run, pass `-records` with a temporary folder.
10. Browser checks on this machine (WSL distro ids-fedora) use Playwright MCP in local scope, headless, with Fedora's Chromium (`npx -y @playwright/mcp@0.0.85 --headless --isolated --executable-path /usr/bin/chromium-browser`). A whole check round fits one `browser_run_code_unsafe` call. browser-use does not run here (no `uv`).
