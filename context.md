# IDS — Current Working Context

Last updated: 24 October 2026  
Product directory: `/home/esip/Documents/ids-system`  
Main architecture reference: [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md)

## 1. What is the project?

A general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. Phase 1 started with SQLi, request-borne XSS, and path traversal; since 12 October 2026 the rule part is being extended to all request rules of CRS (decision K6). It produces alerts and does not block requests.

Planned product: a Go core, our own SecLang rule engine running CRS 4.30.0 at a configurable paranoia level, an ML layer, manually defined application profiles, and a decision mechanism that combines them. HTTPS traffic arrives as request copies from an existing reverse proxy. **Of these, the rule layer exists**, working on offline requests, with records, alerts, and a read-only dashboard (since 23 October 2026, its UI reworked on 24 October). The rest is approved design (M01–M21), not working features.

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

Run it:

```
go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json      # also writes records/ (gitignored)
go run ./cmd/ids-offline -config testdata/crs-tests.json -requests testdata/requests/crs -summary
go run ./cmd/ids-dashboard -add-user admin                                    # prints the password once
go run ./cmd/ids-dashboard                                                    # https://127.0.0.1:8443
```

The dashboard makes its own certificate on first start and prints its SHA-256 fingerprint; the browser warns once until it is accepted. `testdata/crs-tests.json` has no `records` section, so CRS test runs write records only with `-records DIR`.

### 2.1. Code

Go module `github.com/EfeSipahi/ids-system`. One dependency: `github.com/corazawaf/libinjection-go`.

| Package | What it does |
| --- | --- |
| `internal/seclang` | Parses CRS rule files into Go values. Six directives are supported; any other is an error |
| `internal/httpmodel` | The common request (M03, M16): received content, parsed view, analysis status (M05). Reads the query, cookies, and form, JSON, multipart, and XML bodies |
| `internal/offline` | Reads example requests from JSON, with optional `expect_ids` / `no_expect_ids` |
| `internal/engine/transform` | 17 transformations. 12 are ports of the ModSecurity v2 functions, `length` counts bytes; `normalizePath`, `normalizePathWin`, `htmlEntityDecode`, and `base64Decode` follow Coraza (main plan sections 11.15 and 11.18); `normalizePathWin` leaves out Coraza's cut at a colon, which could hide a file name |
| `internal/engine/operator` | `@rx`, `@pm`, `@pmFromFile`, `@detectSQLi`, `@detectXSS`, `@contains`, `@streq`, `@within`, `@beginsWith`, `@endsWith`, `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`, `@eq`, `@lt`, `@ge`, `@gt`, `@unconditionalMatch` |
| `internal/engine` | `Load` prepares a read-only rule set and refuses to start on anything unsupported (M15). `Evaluate` runs phases 1 and 2 for one request with its own state (M21) |
| `internal/result` | Output records: analysis status, findings, score. Request content is left out of the terminal output by default (M11) |
| `internal/config` | The product configuration: engine settings plus the optional `records` section, and the configuration fingerprint (R7) |
| `internal/record` | Record files (R1–R7): building and masking request records, `start` and `counts` records, rotation, file permissions, cookie hashes |
| `internal/dashboard` | The dashboard: reader of the record files, JSON API, pages (embedded HTML, CSS, JS), users, login, sessions, its own certificate |
| `internal/version` | The program version `0.1.0-dev` and the Git revision of the build |
| `cmd/ids-offline` | Command-line tool: `-config`, `-requests` (file or directory), `-summary`, `-json`, `-show-values`, `-paranoia-level`, `-records DIR` |
| `cmd/ids-dashboard` | The dashboard: `-config` (default `configs/dashboard.json`), `-add-user`, `-reset-password`, `-remove-user` |

Other files:

| Path | Content |
| --- | --- |
| `configs/crs-first-engine.json` | The product configuration. Loads nineteen CRS files; 456 of 460 rules active, 4 excluded with a written reason each (all in file 901). Optional `paranoia_level`, 1 to 4, default 1. Its `records` section writes records to `records/` |
| `configs/dashboard.json` | The dashboard configuration: listen address `127.0.0.1:8443`, records folder, state folder `dashboard-state/` (users, certificate, login log), optional certificate files, idle limit |
| `docs/records-format.md` | The record format: the contract between the IDS and its readers, masking rules, known limits |
| `docs/development-plan-records-dashboard.md` | The plan for records, alerts, and the dashboard (finished 23 October 2026), with notes per stage |
| `docs/development-plan-dashboard-ui.md` | The dashboard UI plan (finished 24 October 2026): problems P1–P37, decisions U1–U8, notes and checks |
| `testdata/requests/` | Example requests: starter file, all 5,072 converted CRS request tests (`crs/`), examples for file 905, 1,300 generated variants (`generated/`); see its README |
| `testdata/crs-tests.json`, `testdata/crs-test-setup.conf` | The configuration the CRS tests are written for: the product configuration plus CRS's test setup rule 900005, at level 4 |
| `testdata/reference/` | What Coraza found for those requests; see its README |
| `tools/` | Python scripts that generate the test data, and `coraza-reference/`, a separate Go module that runs Coraza. Coraza is not a dependency of the IDS |
| `docs/development-plan-all-request-rules.md` | The plan for all request rules (finished 16 October 2026): plans A to F, with results after each |
| `docs/development-plan-rule-layer.md` | The earlier plan (finished 11 October), with results per stage in its section 8 |
| `docs/project-history.md` | What was done and how, 27 September to 24 October 2026, written for the project report |
| `docs/crs-4.30.0-ruleset.md` | Reference for the CRS files and our scope |
| `docs/go-learning-plan.md` | The user's Go learning plan |

### 2.2. What was checked (16 October 2026, records and dashboard on 23 October, dashboard UI on 24 October)

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

1. It reads requests from files only. There is no proxy integration.
2. There is no ML layer, profile layer, or decision mechanism. An alert is the rule layer's score at the CRS threshold ("rule layer only"), not the planned decision. The dashboard only reads; alerts cannot be marked yet (V7), and there is one user role.
3. Request rules only; no response rules (they need a copy of each response, K8).
4. A `text/plain` body is not split into fields. Since plan B the rules that read `REQUEST_BODY` inspect it as one text; it is still reported as not inspected.
5. Passing the CRS tests is not full CRS compatibility, and no request has been run through ModSecurity itself.

### 2.5. Other facts

- The Python Random Forest pilot is in the separate [ids-model](../ids-model/) directory and is not integrated. Its test set has already been observed.
- Go version last verified: `go version go1.26.8-X:nodwarf5 linux/amd64`.
- Git: everything up to and including the records and dashboard of 23 October is on `main` and pushed to GitHub (commit `df0ecdc`). The UI work of 24 October is **not committed yet**; the user decides when. `proje_oneri_formu.docx` holds personal data and is deliberately left uncommitted. The local branches `rule-layer` and `first-offline-engine` point to commits that are on `main` and can be deleted.

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
2. **Now:** hand-written application profiles (A04). **Decided on 25 October 2026** (F1–F11, main plan section 11.25) and being built following [docs/development-plan-profiles.md](docs/development-plan-profiles.md); its Progress section says which stage is done.
   - JSON profiles, one per application, chosen by host and path prefix (later the proxy route), never by a client header.
   - An allow list of endpoints, parameters, cookies and headers; findings are recorded (`monitor`) or alerts (`alert`).
   - Rule exceptions per application (a CRS setting, a rule skipping targets, a rule off), applied per request on one shared rule set (option B, measured against one copy per application). Rules of files 901 and 949 can't be excepted.
   - A paranoia level per application.
   - The CSIC profile is the first one (I2), written from the training records only.
   - Stages 1–7 were done on 25 October 2026, including the CSIC profile (`profiles/csic-shop.json`, `configs/csic-shop.json`; results in the plan's notes 17–18). Left: stage 8, the project history and the main plan's results.
3. Proxy and TLS (A01, A08), then response rules, and alerts sent by webhook and syslog (decided 23 October 2026).
4. Transfer of the ML model, which the user improves in the separate project, and the decision mechanism (A10, A05, A07, A06).
5. Prevention, learned profiles, other protocols.

Each still needs its own decisions before work starts.

**Two ideas from the user (16 October 2026), not yet placed exactly** (main plan section 6.15):

1. **I1:** one MCP server through which an AI assistant configures the IDS and corrects false positives (confirmed by the user on 23 October 2026). The user places it after the dashboard and a usable IDS.
2. **I2:** correct the false positives found on the CSIC 2010 normal records. Decided on 25 October 2026: by hand, with the profile work (item 2, F10). Afterwards the training records no longer measure false positives independently; validation and test are reported separately (A07).

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
3. Working mode for code: small packages with tests and an explanation of each. For the request-rule plan the user asked for one plan at a time, then for E and F together; that plan is finished, so return to one step at a time with a pause for review unless told otherwise. The user knows Python and finished a Go course.
4. Check behaviour against a source before writing it down. Expected values in tests must come from the rule files, a reference implementation, or an independent count, not from a guess. Several times in this project a guessed value or a remembered behaviour was wrong and only a reference caught it.
5. Approved Go dependencies may be downloaded by the assistant. Propose a new dependency first.
6. Do not commit unless the user asks.
7. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
8. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
