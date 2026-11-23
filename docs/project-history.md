# Project history: what was done and how

Written: 16 October 2026, for the project report; updated 25 October, 19, 20 and 23 November 2026  
Covers: 27 September 2026 (ML pilot) to 23 November 2026 (live traffic through Caddy; the dashboard's test tab, marks, users and change log; a dashboard that controls the IDS; own rules)  
Sources: the main plan [ids-system-plan-phaze1.md](../ids-system-plan-phaze1.md) (history in section 11), the development plans in this folder, [context.md](../context.md), the git history, and the README of the separate ML project `ids-model`. Every number below comes from one of these or from a run of the code on 16, 23, 24, 25 or 26 October, or 18 or 19 November 2026.

## 1. The project in short

1. **Title** (from the project proposal form): an open-source HTTP intrusion detection system (IDS) based on rules and machine learning, which can be customized with application profiles.
2. **Aim:** inspect the HTTP requests that reach a web application, detect attack attempts, and produce alerts. Phase 1 only detects; it does not block requests.
3. **Planned design:**
   - a rule layer: our own rule engine in Go that runs the OWASP Core Rule Set (CRS) 4.30.0 unchanged;
   - an ML layer: a model trained in Python and run inside Go through ONNX;
   - an application-profile layer: hand-written expectations for one application;
   - a decision mechanism that turns the layers' separate findings into an alert decision;
   - HTTPS traffic arriving as request copies from an existing reverse proxy.
4. **Design points named in the proposal:** each layer's findings stay separate; a request that could not be fully inspected is reported as incomplete, never counted as normal; training and live use share one feature extractor; sensitive fields are masked in stored records.

What exists on 19 November 2026:

| Part | State |
| --- | --- |
| Rule layer (Go) | **Done for the request side of CRS.** Runs every CRS 4.30.0 request rule file at paranoia levels 1 to 4, on requests read from files |
| Records and alerts (Go) | **Done.** Every request with a finding or an incomplete analysis is written to a record file, with secrets masked; an alert is a score at the CRS threshold, or a profile finding of an application in `alert` mode |
| Dashboard (Go) | **Done, read-only.** A separate program shows the records in a browser, behind a login, over HTTPS only. Its UI was reworked on 24 October after a check of every page, and restyled in the IBM Carbon design system on 18 November, when it also started to show the live input. Since 19 November a test tab analyses a request written by hand, with the IDS's own rules and profiles; since 20 November people mark alerts (real attack, expected, false positive), with three roles and a change log |
| ML layer | A pilot in the separate Python project `ids-model` (Random Forest and logistic regression on 1,000 CSIC 2010 records). Not yet moved into Go |
| Application profiles (Go) | **Done, written by hand.** A JSON profile per application: an allow list of endpoints and parameters with types, rule exceptions, and a paranoia level of its own. The first profile is for the CSIC 2010 shop |
| Live traffic (Go, Caddy) | Done for Caddy. A Caddy module copies each request and its response, while they pass, to a separate program, `ids-live`, which analyses them as the file input does. The site never waits for the IDS, and every copy that is not analysed is counted. Measured in a lab on one machine; an Nginx input is planned later |
| Decision mechanism | Designed and approved (decisions M01–M21), not built yet |

## 2. Final numbers at a glance

| What | Result |
| --- | --- |
| CRS rule files run | All 18 request files of CRS 4.30.0, unmodified: 14 detection files, setup (901), exceptions (905, 999), and scoring (949) |
| Rules | 460 loaded, 456 active, 4 left out with a written reason; 286 detection rules (160 at level 1, 85 at level 2, 32 at level 3, 9 at level 4) |
| Attack groups | Method enforcement, scanner detection, protocol enforcement and attacks, multipart attacks, path traversal and file access, remote file inclusion, remote command execution, PHP, generic attacks, XSS, SQL injection, session fixation, Java attacks |
| CRS regression tests | **5,072 of 5,072 pass** (290 test files; 22 tests left out, each with a reason) |
| Comparison with Coraza v3.8.1 | 6,372 requests at level 1 and at level 4, **0 unexplained differences** |
| Transformations | 17; 12 agree with 10,829 results recorded from ModSecurity's C code, 4 with 4,901 results recorded from Coraza's Go code, `length` counts bytes |
| Operators | 19 |
| Speed (one laptop core) | 0.55 ms for an ordinary request; about 8,000 requests per second on 12 threads |
| Records and dashboard | Dashboard counts equal the command line (5,072 CRS tests: 2,916 alerts, 154 incomplete); no secret in record files, API answers, or pages; a record costs about 0.04 ms next to 0.6 ms of analysis |
| Application profiles | Per-application exceptions give the same results as the same changes written in SecLang, on all 5,072 CRS tests at levels 1–4; they cost about 0.2–0.3 % of the time |
| CSIC shop with its profile (test records) | False alarms 3 of 100, against 30 of 100 with the rules alone at level 1; 74 of 99 anomalous records flagged by the rules or the profile; Coraza gives the same rule results |
| Live traffic (lab, one machine, HTTPS) | The 396 CSIC validation and test requests sent through Caddy give the same 162 records live as from files. The copier adds about 0.02 ms (one request at a time) to 0.2 ms (eight at a time) at the median, and the site's times do not change when `ids-live` hangs or stops. Under overload, 7,920 requests = 235 analysed + 2,429 + 5,256 counted as dropped |
| Code | About 18,200 lines of Go code and 15,200 lines of Go tests (319 test functions, 10 fuzz tests, 6 benchmarks), of which the Caddy copier is 1,040 and 830 and the lab's tools 620 and 40; 2,880 lines of dashboard HTML, CSS, and JavaScript; 733 lines of Python tools; Go dependencies: `libinjection-go`, and Caddy in the copier's own module only. On 25 October: 12,400 and 10,300 lines; on 24 October: 9,700 and 8,200; on 16 October: 6,100 and 5,350 |

## 3. Timeline

| Date (2026) | What happened | Result |
| --- | --- | --- |
| 27 September | ML pilot in `ids-model`: 21 features from 1,000 CSIC 2010 requests, first Random Forest | Test F1 66.32 %, false-alarm rate 28.00 % on 199 records |
| 2–3 October | Main architecture plan written (2 October) and restructured (3 October) | Approved decisions M01–M20 and open topics A01–A11 in one document |
| 4 October | Product moved to its own directory `ids-system`; documents switched to English; GitHub repository created | Initial commits |
| 5 October | Decision M21 (rules prepared once at start, separate state per request); Go module created; CRS file parser written | Parser reads the original CRS files |
| 11 October | First offline engine: request model, input reader, 4 transformations, 4 operators, rule engine, output and command-line tool | Rules 930100 and 930110 run; 14 of 18 CRS tests pass, 4 bodies not readable yet |
| 11 October | Rule-layer plan, 8 stages, decisions D1–D6 | 51 level-1 rules for path traversal, XSS, and SQLi; 687 of 687 CRS tests pass |
| 11 October | Two transformations changed to Coraza's behaviour | Comparison with Coraza: 0 unexplained differences on 1,993 requests |
| 12 October | Decision to finish the whole rule part first (K1–K11); plan A–F written; plan A | Paranoia levels 1–4; 1,388 of 1,388 tests |
| 12 October | Plan B: request variables and operators | 2,661 of 2,661 tests |
| 13 October | (In `ids-model`, separately) logistic regression and tuned v2 models | Best test result: Random Forest v2, F1 70.05 % |
| 16 October | Plan C: three transformations, command execution, PHP, generic rules | 4,479 of 4,479 tests |
| 16 October | Plan D: protocol rules | 5,025 of 5,025 tests |
| 16 October | Plans E and F: multipart rules; checks and speed on the whole set | **5,072 of 5,072 tests**; two to three times faster |
| 16 October | Two ideas added: an MCP server (I1), correcting the CSIC false positives (I2) | Placed after the dashboard |
| 23 October | Decisions for records, alerts, and the dashboard (R1–R7, V1–V7), after a comparison of what other IDSs record | Development plan in five stages |
| 23 October | Records, alerts, and the dashboard built | Dashboard counts equal the command line; no secret leaks in any test |
| 24 October | Dashboard checked in a browser page by page; UI plan with decisions U1–U8, done the same day | 37 problems fixed, among them one bug that wiped the page on a failed update |
| 25 October | Decisions on application profiles (F1–F11); a measured choice between one rule copy per application and one shared copy | Shared copy chosen (option B): same results, about 0.2–0.3 % slower |
| 25 October | Profiles built in eight stages; the CSIC shop's profile written from its training records | Test records: false alarms 30 → 3 of 100; Coraza agrees |
| 26 October | Decisions on live traffic through Caddy (T1–T12); stages 1–3 of its plan built: the plan, the copy frame format, the request body limit | CRS and CSIC results unchanged; `FuzzReadFrame` ran 6.1 million inputs without a failure |
| 17 November | Repository prepared for a second machine; the work moved to Fedora 44 in WSL2 | Notes for setting up another machine; LF line endings kept everywhere |
| 18 November | Stages 4 and 5: `ids-live`, the live records, and the Caddy copier | 1,318 example requests give the same 850 records live as from files; a real Caddy sent copies to `ids-live` |
| 18 November | Stage 6: the dashboard shows gaps, the copier status and the live fields; restyled in IBM Carbon | Three browser rounds in light and dark, defects fixed |
| 18 November | Stage 7: a lab on this machine | Same 162 records live and offline for 396 CSIC requests; the copier adds 0.02–0.2 ms at the median; every dropped copy counted |
| 19 November | Stage 8: documents and the full checks | CRS and CSIC numbers unchanged |
| 19 November | A test tab in the dashboard: a request written by hand, analysed with the IDS's own rules and profiles (S1–S4) | Same answers as `ids-offline` for 5,066 CRS tests and 1,000 CSIC requests |
| 20 November | Marks on alerts, users with three roles, a change log (G1–G6) | Every route tested as each role; no password in any state file; 10,000 records marked in 27 ms |
| 21 November | A dashboard that controls the IDS (W1–W26), then built on IBM Carbon's own components (Y1–Y10) | Every route as each role; Analyse files gives `ids-offline`'s 2,916 of 5,072 CRS tests flagged at level 1 |
| 23 November | Own rules (N1–N8): written with a form in the dashboard, checked to only detect, for chosen applications | Without own rules the same outputs and fingerprints for the CRS tests, the CSIC requests and the attack variants |

## 4. What was done, step by step

### 4.1. Groundwork: ML pilot and architecture plan (27 September – 4 October)

1. **ML pilot** (separate project `ids-model`, Python). 1,000 requests were chosen from the CSIC 2010 data set (500 normal, 500 anomalous) and split by content groups into 604 training, 197 validation, and 199 test records, so that similar requests stay on one side. 21 numeric features were extracted. A Random Forest scored F1 72.53 % on validation and 66.32 % on test, with a false-alarm rate of 28.00 % on test. On 13 October a logistic regression and tuned versions of both models were added there; the best on test was the tuned Random Forest (F1 70.05 %, false-alarm rate 29.00 %). The test set has now been seen, so it cannot be presented as an unseen test again.
2. **Architecture plan** (`ids-system-plan-phaze1.md`). Twenty decisions (M01–M20) were made one at a time, each with its reason and an example. Some examples: M02, HTTPS through an existing reverse proxy; M05, an incomplete analysis is reported as incomplete; M11, analysis may use sensitive values but stored records do not keep them; M15, our own CRS engine rather than an existing one; M18, CRS pinned to version 4.30.0; M19 and M20, start with SQLi, XSS, and path traversal at paranoia level 1. Eleven topics were left open (A01–A11).
3. **Separation.** Product code and plans went into `ids-system`; data, training code, and models stayed in `ids-model`.

### 4.2. First offline engine (5–11 October)

Built one package at a time, each with tests, in the order the main plan fixed (section 7.4):

| Step | Package | What it does |
| --- | --- | --- |
| 1 | `internal/seclang` | Reads the CRS rule files (SecLang language) into Go values |
| 2 | `internal/httpmodel`, `internal/offline` | The common request: what was received, the parsed view (path, query, form fields, raw and decoded), and the analysis status; example requests read from JSON files |
| 3 | `internal/engine/transform` | Transformations such as URL decoding, written as ports of ModSecurity's C functions |
| 4 | `internal/engine/operator` | `@rx` (regular expressions) and number comparisons |
| 5 | `internal/engine` | Loads and prepares the rules once; runs phase 1 and phase 2 for each request with its own state (M21) |
| 6 | `internal/result`, `cmd/ids-offline` | Output records without request content by default (M11), and the command-line tool |

Result: the two path-traversal rules 930100 and 930110 ran from the real CRS files, with their setup and scoring rules. 14 of their 18 CRS tests passed; the other 4 carried the attack in XML or multipart bodies, which the engine could not read yet, and the output said so (M05).

### 4.3. Rule layer for the Phase 1 scope (11 October)

A plan of eight stages ([development-plan-rule-layer.md](development-plan-rule-layer.md)). The team made six decisions first:

| # | Decision |
| --- | --- |
| D1 | Coraza is the reference engine for comparing results, run by a separate helper so the IDS does not depend on it |
| D2 | `@detectSQLi` and `@detectXSS` use the Go library `libinjection-go`, the only dependency of the IDS |
| D3 | XML bodies are read in Phase 1 (M17 amended) |
| D4 | Rules 930120, 930130, 930140 are in scope |
| D5 | The AI coding assistant writes the code; the team reviews it |
| D6 | The converter for CRS tests is a Python script |

The stages: a test harness that converts CRS's own regression tests; the Coraza comparison; more request variables (cookies, argument names, file name); the rest of file 930; JSON, multipart, and XML bodies; then the SQLi (942) and XSS (941) files, with eight more transformations and the libinjection operators; finally a check on normal traffic and speed.

Result: all 51 level-1 rules for path traversal, SQLi, and XSS ran, and **687 of 687** CRS tests passed. On the 1,000 CSIC records, 0 of 500 normal and 80 of 500 anomalous records were flagged. An ordinary request took about 0.4 ms.

### 4.4. Following Coraza in two transformations (11 October)

The comparison found two places where ModSecurity's behaviour, which we had copied, lets a disguised attack through and Coraza does not:

| Function | Input | ModSecurity | Coraza |
| --- | --- | --- | --- |
| `normalizePathWin` | `a/win.ini..` | `a` (the file name is lost) | `a/win.ini` |
| `htmlEntityDecode` | `&LTscript` | unchanged | `<script` |

The team decided to follow Coraza in both. Two details were left to the assistant: entities are read as a browser reads them, and one step of Coraza's `normalizePathWin` (cutting a name at a colon) is left out, because it could hide a file name (`ab: boot.ini` would become `ab`).

### 4.5. All CRS request rules, all paranoia levels (12–16 October)

On 12 October the team decided to finish the whole rule part before any other layer (decisions K1–K11). K6 extends the scope to all request attack groups, K7 to all four paranoia levels with level 1 as default; response rules wait for the proxy (K8). All 28 CRS rule files were loaded into the engine to see what each lacked, and the work was split into six plans ([development-plan-all-request-rules.md](development-plan-all-request-rules.md)):

| Plan | Content | Tests passing after it | Main points |
| --- | --- | --- | --- |
| A | Paranoia levels; test base; files 913, 930, 941, 942 at all levels | 1,388 of 1,388 | The CRS project runs its tests at level 4, found in its own setup files. Coraza silently adds a multi-line flag to every pattern, which ModSecurity does not; the reference is built with Coraza's option to turn it off |
| B | 13 request variables, 5 operators, `length`; macros and patterns on TX; files 911, 931, 943, 944 | 2,661 of 2,661 | A body without a reader (such as `text/plain`) is given to the rules as one text, as in ModSecurity; Coraza splits it into fields. The team chose the ModSecurity way |
| C | `escapeSeqDecode`, `base64Decode`, `normalizePath`; files 932, 933, 934 | 4,479 of 4,479 | `base64Decode` and `normalizePath` follow Coraza, because ModSecurity's versions stop at a line break or drop `passwd..` |
| D | Operators `@validateUrlEncoding`, `@validateUtf8Encoding`, `@ipMatch`; client address; body reader chosen by rules (`ctl`); files 905, 920, 921 | 5,025 of 5,025 | The tests need CRS's test setup rule and what the web server does before the rules (message length by RFC 9112, HTTP/0.9). A bug was found and fixed: a `#fragment` reached the last query parameter |
| E | Header lines of multipart parts; file 922 | 5,072 of 5,072 | Coraza numbers multipart headers in random order; ours keep the order received |
| F | Checks on the whole set, speed, documents | 5,072 of 5,072 | 0 unexplained differences from Coraza; two to three times faster; prefilter tested on about 4 million skipped values |

How the false alarms on the CSIC normal records changed as rules were added (500 normal, 500 anomalous):

| After | Level 1 | Level 2 | Level 3 | Level 4 |
| --- | --- | --- | --- | --- |
| Rule layer (930, 941, 942, level 1 only) | 0 / 80 | – | – | – |
| Plan A (913, 930, 941, 942) | 0 / 80 | 0 / 98 | 0 / 100 | 1 / 102 |
| Plan C (+ command execution, PHP, generic) | 0 / 80 | 18 / 120 | 221 / 246 | 222 / 247 |
| Plans D–F (+ protocol and multipart rules) | 96 / 176 | 500 / 500 | 500 / 500 | 500 / 500 |

Each cell is normal flagged / anomalous flagged. Coraza flags exactly the same numbers. The causes belong to this one application: Spanish text in the old Latin-1 encoding (rule 920250, level 1), an old browser header `Accept-Charset` (rule 920451, level 2), and parameters named `pwd` and `id`, which are also Unix commands (rule 932350, level 3). With the one setting CRS documents for non-UTF-8 applications, level 1 flags 0 normal and 116 anomalous records. This is the job application profiles are meant to do.

Speed over the same period (one core of the development laptop, AMD Ryzen 5 7530U):

| After | Ordinary GET | POST with a 9.4 kB field |
| --- | --- | --- |
| Rule layer (3 detection files) | 0.42 ms | 18.5 ms |
| Plan D (all rules but 922) | 1.2–2.1 ms | 57 ms |
| Plan F | **0.55 ms** | **19 ms** |

### 4.6. Records, alerts, and a dashboard (23 October)

Until then `ids-offline` printed its findings and forgot them. On 23 October the team decided how records and alerts work (R1–R7) and what the dashboard is (V1–V7); see main plan section 11.22.

1. **What to record.** The assistant compared what Suricata, Zeek, ModSecurity and Coraza, and CrowdSec record, and the OWASP Logging Cheat Sheet.
   - The team chose to keep what later blocking needs: the client address and port (only from the connection, never from a header such as `X-Forwarded-For`, which an attacker can fake), the target, the request line, some headers, and the matched part of each finding.
   - Secrets are always masked: cookies, `Authorization`, and parameters with names such as `password` or `token`. Cookies are kept as a keyed hash, so one session's requests can still be linked.
2. **Alerts.** For now an alert is a rule-layer score at the CRS threshold, labelled "rule layer only", until the decision mechanism exists.
3. **Dashboard.** It is a separate program that only reads the record files, so the IDS and the dashboard can fail or restart separately. It is written with Go's standard library only.
   - Six pages: login, overview, alerts, alert detail, rules, engine.
   - A small JSON API that the pages ask every 5 seconds.
   - HTTPS always on, with its own certificate if none is given.
   - Users with PBKDF2 password hashes.
   - A growing wait after five wrong passwords.
   - Protection against requests from other sites.

The work followed a five-stage plan ([development-plan-records-dashboard.md](development-plan-records-dashboard.md)), done in one day. The record format is described in [records-format.md](records-format.md).

**How it was checked:**

1. A request file with a secret in every place a secret can be, each carrying an attack, was run with the real CRS rules. None of the secrets appeared in the record files, the API answers, or the pages. The test was also run with masking switched off, to see that it then fails. A fuzz test tried about a million other secrets and requests.
2. Records with `<script>` in them are never served as HTML. The pages insert record text only as text, and the browser is told to run no other script.
3. Every route refuses access without a login. The login limits, session limits, and HTTPS-only rule are tested.
4. The dashboard's counts were compared with the command line's on the 5,072 CRS tests and the 1,000 CSIC records. They are equal. Each page was opened in a headless browser, in light and dark mode and at phone width, and corrected where it looked wrong.

### 4.7. Dashboard UI and user experience (24 October)

The team then used the dashboard the way an analyst would. The assistant drove a browser with browser-use, opened every page in light and dark mode, and listed 37 problems.

1. **One real bug.** A single failed update wiped the page the analyst was reading.
2. **Usability problems.** Examples:
   - The chosen period was lost between pages.
   - Times came in three styles.
   - The last chart bar looked like a drop in traffic, though its period had not ended.
   - Alert rows took two lines.
   - The attack categories used internal names such as `lfi`.
   - The rules page was 22,000 pixels long, and level-2 rules were shown as "active" at level 1, where they never run.

The team decided eight points (U1–U8, main plan section 11.24) and the work followed a seven-stage plan ([development-plan-dashboard-ui.md](development-plan-dashboard-ui.md)).

1. **Rule descriptions (U1).** These needed a small change outside the dashboard: every rule in the record file's `start` line now carries its description, taken unchanged from the CRS file. The record format stays at version 1, because it allows new optional fields.
2. **Login return (U8).** After logging in, the user returns to the page they were on. The return address is checked to be a local path, so a link can't use the login to send someone to another site (an "open redirect").
3. **Category names.** Names such as "Path traversal and file access" were checked against the CRS files: which file raises which score.

**How it was checked:**

1. New Go tests cover the return address, the kept login name, the 404 page, sorting, periods, and counts per run.
2. All tests, including the race detector, pass.
3. The dashboard's numbers still equal the command line's.
4. A second browser pass went through every page and action and found two more bugs, both fixed:
   - filter chips that showed "[object HTMLButtonElement]";
   - a table wider than its card.
5. The user then reported that problems persisted. A third pass took screenshots of every page and found more, all fixed the same day:
   - attack-group names cut short in the alert lists (now only whole names, the rest as "+N");
   - filters on two rows;
   - rule search not kept in the address;
   - chart labels on uneven times;
   - per-category scores that did not add up to the total. The CRS files explain it: protocol rules (files 911, 913, 920 and 922) raise only the total. The page now shows the difference as "No category".

   The user also decided that the rules page starts with every file section closed, which shortened it from 17,325 to 1,581 pixels.

### 4.8. Application profiles (25 October)

Until then every request got the same rules at the same level. The CSIC results of section 4.5 showed why that is not enough: one application's normal habits, such as Latin-1 text, set off rules that are right for other sites.

1. **Decisions (F1–F11, main plan section 11.25).** Examples:
   - a profile is a JSON file per application (F1, F2);
   - the application is chosen by the address that receives the request, never by a header the client could set (F3);
   - an allow list of endpoints and parameters, where anything unknown is a finding (F4);
   - rule exceptions with a written reason (F5);
   - profile findings kept apart from the rule score, and alerts only in `alert` mode (F6);
   - a paranoia level per application (F11).
2. **A measured choice (5e).** The team first preferred one copy of the rules per application, so that one profile's mistake could never touch another application. A prototype measured both ways: same results; one copy costs 13.4 MB and 217 ms to build; the shared copy with exceptions applied per request costs about 13 KB per application and no measurable time. The user chose the shared copy, and the plan gave it the same safety through tests.
3. **The work** followed an eight-stage plan ([development-plan-profiles.md](development-plan-profiles.md)): the engine part, the profile package, the configuration and command line, records, the dashboard, the CSIC profile, and the close. The profile contract is [profile-format.md](profile-format.md).

**How it was checked:**

1. **Same as SecLang.** On all 5,072 CRS tests at levels 1–4, exceptions applied per request gave exactly the matches, values and scores of the same changes written in SecLang. The exceptions changed 577–999 tests per level, so the comparison could see a difference.
2. **Isolation.** Eight goroutines mixed requests of an application with exceptions, one without, and requests of no application; each got exactly its own result.
3. **Nothing changed without profiles.** The CRS summary and the CSIC numbers stayed the same, and so did the old golden record.
4. **Secrets.** The secret fields a profile names reach no record, API answer, or page. A fuzz test also found an older gap: a JSON body written in full could keep a secret that the client had written with JSON escapes, which the masking pass did not recognise. Such a body is now written again with the secret field replaced.
5. **Dashboard.** Two browser rounds on demo records with two applications found four bugs, all fixed; one was an application filter that did nothing when it came from a link.

**The CSIC shop's profile (I2).** It was written by hand from the 301 normal records of the training split only:

- the 13 endpoints those records use;
- one value of `modo` per page;
- the formats of the national ID number, the postal code, the card number and the session cookie;
- a length limit on free text;
- passwords, card number and ID number marked secret.

The user accepted three exceptions, each with a reason in the file:

- the CRS setting for sites that do not send UTF-8 text;
- allowing the `Accept-Charset` header;
- rule 932350 not reading the shop's parameter names `pwd` and `id`.

Three rules the plan asked to examine (932200, 932236, 932240) were kept: they match an address that the data set's conversion damaged, two names, and a password, and skipping them would hide command injection in those fields. The shop runs at level 2.

Validation and test were run once, after the profile was final:

| Test records (100 normal, 99 anomalous) | Rules alone, level 1 | With the profile, level 2 |
| --- | --- | --- |
| False alarms (normal records flagged by the rules) | 30 | 3 |
| Anomalous records flagged by the rules | 37 | 30 |
| Anomalous records flagged by the rules or with a profile finding | 37 | 74 |

Without a profile, every level from 2 up flags every record, normal or not. On validation the numbers are similar (13 → 5 false alarms; 33 → 73 anomalous). Coraza, given the same exceptions in SecLang, found the same rule results on all 396 records at levels 1–4. Levels 3 and 4 stay unsuitable for this shop: their rules 920272 and 920273 allow only plain ASCII or a very small character set, so Spanish letters, spaces, `@` and `/` in ordinary forms set them off. The profile does that strict checking per field instead.

### 4.9. Live traffic through Caddy (26 October – 19 November)

Until then the IDS read requests only from files. This step lets it analyse the live traffic of a site without ever making the site wait for it (M09).

1. Research (25–26 October). Five proxies were compared from their documentation: Nginx, HAProxy, Envoy, Caddy and Traefik. Only a Caddy module and Envoy's `ext_proc` copy responses as well as requests without making the client wait; Nginx's `mirror` copies no responses, HAProxy's agent protocol makes each request wait for the agent, and Traefik skips large bodies without notice. Response copies matter because the response rules come next. Two measurements: one more local proxy hop costs 0.14–0.32 ms; a round trip over a Unix socket about 0.02–0.03 ms.
2. Decisions (T1–T12, main plan section 11.27). Examples:
   - Caddy with our own Go copier module first, Nginx later (T1);
   - copies go over a two-way Unix socket, in our own frame format, to a separate program, `ids-live` (T2, T12), so that a crash of the analysis can't stop the site;
   - bodies up to Coraza's limits, 12.5 MB of a request and 512 KB of a text response, with the first part analysed past them (T3, T4);
   - the client's address only from Caddy, never from a header the client sends (T5); the application named in Caddy's configuration (T6);
   - queues with a size limit: a copy that does not fit is dropped and counted, never lost silently (T7, T8);
   - a lab that shows live results equal offline ones (T9).
3. The work followed an eight-stage plan ([development-plan-proxy.md](development-plan-proxy.md)). On 26 October: the plan, the frame format ([copy-format.md](copy-format.md)) and the request body limit. On 18 November: the live input and its records, the Caddy copier, the dashboard and the lab. The close followed on 19 November.
4. Decided by the team during the work:
   - live records keep Caddy's ID of the request and the time Caddy received it, so a record can be found in Caddy's logs;
   - the team asked whether a body over 15 MB would go unanalysed. It does not: the copier copies its first 12.5 MB. The question showed another gap, though: a copy longer than `ids-live`'s frame limit, possible when the copier's limits are raised, would have been refused whole. Now `ids-live` tells the copier its limit when they connect, and the copier shortens a copy to fit;
   - the dashboard warns when `ids-live` has written nothing for two minutes, so that a crashed IDS can't look like a quiet site;
   - the dashboard follows IBM's Carbon design system, chosen from free design systems, with its open-licensed IBM Plex fonts.

How it was checked, in a lab on one machine, all requests over HTTPS:

1. Same results live as from files. The 396 CSIC validation and test requests, sent one at a time through Caddy, gave the same 162 records in `ids-live` as in `ids-offline`: the same findings, matched values, scores and profile findings; 396 analysed in both. Go's HTTP server, which Caddy uses, changes the case and order of header names; all 162 header lists differed, and no rule result changed. Before the lab, a Go test had given the same 850 records live and offline for 1,318 example requests.
2. The site never waits. Each condition ran 3,960 requests:

   | Median time per request, `ids-live` on its own CPU | One at a time | Eight at a time |
   | --- | --- | --- |
   | Without the copier | 0.87 ms | 1.08 ms |
   | With the copier, `ids-live` analysing | 0.89 ms | 1.28 ms |
   | With the copier, `ids-live` hung | 0.89 ms | 1.15 ms |
   | With the copier, `ids-live` stopped | 0.86 ms | 1.19 ms |

   Without pinning the programs to CPUs, the analysis took CPU from the site on the four shared CPUs (0.91 and 1.66 ms).
3. Nothing is lost without a count. Overload: of 7,920 requests in a burst, against a deliberately small queue, every one was answered; 235 were analysed, 2,429 counted as dropped by the copier and 5,256 by `ids-live`, which adds up to 7,920. Stopping `ids-live` for 132 requests gave one gap record of exactly 132.
4. TLS 1.3, HTTP/2 and HTTP/3 worked through the copier; the client's address followed Caddy's trusted proxies; response types, the 512 KB limit, a slow response and a WebSocket were copied as designed.
5. Secrets: a new fuzz test sends a secret through a frame, the analysis and the records; 3.6 million inputs found none in the records. The file input's results stayed the same throughout.

### 4.10. A test tab in the dashboard (19 November)

The team wanted to see how the rules behave on requests they write themselves, before the dashboard learns to change anything. The CRS project's public sandbox, Coraza's Playground and Cloudflare's Trace offer the same kind of tool.

1. Decisions (S1–S4, main plan section 11.29): the dashboard runs the analysis itself, with the IDS's own engine and profiles; a list of configurations to choose from; the request written as raw HTTP text; ten built-in examples and a picker of CRS's own tests by rule.
2. The tab keeps nothing: no record, no setting, and the request is sent nowhere. A request is at most 1 MiB, and at most two are analysed at once.
3. The analysis of one request moved into one function that `ids-offline`, `ids-live` and the tab all call, so the three can't drift apart. `ids-offline`'s output stayed byte for byte the same.

How it was checked:

1. Raw text holds 6,384 of the 6,391 example requests exactly. The seven others are named: six have spaces around a header value, which HTTP servers (Go's included, so Caddy too) remove, and one has a body that is not text.
2. Posted to the running dashboard, every one of those requests gave exactly what `ids-offline` prints for it: 5,066 CRS tests with the CRS test setup, every expectation met, and the 1,000 CSIC requests with two configurations.
3. Three browser rounds found four layout defects, all fixed.


### 4.11. Marks, users with roles, and a change log (20 November)

The first step of a dashboard that does more than read. Before deciding, the team looked at what others do: Elastic Security gives alerts a workflow status, Microsoft Sentinel closes incidents as true positive, benign positive (real but expected), false positive or undetermined, and has three roles as a ladder (Reader, Responder, Contributor); NIST SP 800-63B-4 asks for passwords of at least 15 characters without composition rules.

1. Decisions (G1–G6, main plan section 11.31): a verdict per alert, not a workflow (not reviewed, real attack, expected, false positive, undetermined); marks on existing records only, one, the chosen ones or all that match a filter; three roles, viewer, analyst and admin (per-user permissions were weighed and left aside: they turn back into roles and multiply what must be tested); a Users page, with each change asking the admin's password again; an append-only change log for admins; the data in JSON Lines files of the dashboard's own state folder.
2. The dashboard writes only that folder. The record files stay exactly as the IDS wrote them, and a mark keeps a short summary of its alert, so that the count of false positives per rule survives the records' rotation. That count is the evidence for the next step: turning a false positive into an exception.
3. Two programs now write the users file, the dashboard and its commands, so every change takes a file lock. A test makes two of them add users at the same moment: with the lock all 31 users stay; with the lock taken out for a trial, only 16 did.

How it was checked: every page and answer as no login, viewer, analyst and admin; the last admin can't be removed; a role change ends the user's sessions; no password, temporary or chosen, appears in any file of the state folder; four browser rounds as each role found two layout defects, both fixed.


### 4.12. A dashboard that controls the IDS (21 November)

The user asked for everything the command line and the configuration files can do to be done from the dashboard as well, "without confusing its users". An inventory found 18 things the dashboard could not do; 26 decisions (W1–W26, main plan section 11.34) shaped the answer, which was built in seven stages in one run, each with its tests, a browser round and a commit.

1. The organisation: a visible application filter on the pages that show what happened, instead of a hidden selector; a page per application (Summary, Rules, Profile, Settings, History) and per rule; settings for every application on one page; every control names its reach ("Switch off for csic-shop").
2. Changing safely: changes wait as pending changes per object, with a preview worked out from the records (a record's score is the sum of its findings' weights, which held for all 844 of the user's records), are applied together as one version that keeps the old files, and can be undone byte for byte. Analysts propose, admins apply; the widest changes ask for the password again. The dashboard writes the IDS's own files in place, and `ids-live` takes them within seconds without stopping, starting a new run.
3. The command line's abilities: request files analysed from the dashboard with `ids-offline`'s numbers (the summary moved to `internal/batch`, used by both); profile suggestions from records and files; a JSON editor for profiles; records exported, deleted and kept for a set age; the dashboard's own settings. What stays on the command line is on purpose: the first admin, recovery, starting the programs, the dashboard's address and certificate, building Caddy.
4. A mistake: a comparison of `ids-offline` before and after the move wrote records into the user's records folder; it was found and undone the same hour (the plan's note 5.4).

### 4.13. The dashboard on IBM Carbon's own components (21 November)

The user found the dashboard "a little raw" and chose IBM's component library over fixing what was seen. Ten decisions (Y1–Y10, main plan section 11.36) shaped it; five stages were built in one run, each with its tests, a browser round and a commit.

1. IBM's own files: `tools/carbon-fetch.sh` copies one version of Carbon's web components (84 files for 24 components), its licence, its two themes and 52 icons into the binary, with no Node.js; a small Go program, `tools/carbonprep`, takes the themes and icons out of Carbon's packages. The browser keeps them under a versioned address.
2. The frame and lists: Carbon's dark header with the theme and account panels and the side navigation with icons; rows of lists are one link with a ›, "View all" a small button, the pages of a list Carbon's page buttons.
3. Forms: the page's own HTML controls drawn as Carbon's, so that forms, Enter and password managers keep working; icons on the action buttons.
4. Details: a breadcrumb back from an alert, step buttons, status icons, links with Carbon's arrow; explanations behind Carbon's toggletip beside a page's or a card's title; a skeleton while a page loads.
5. The policy gained one directive, `style-src-attr 'unsafe-inline'` (Y2), and a test checks all of its directives.

### 4.14. Own rules (23 November)

The user asked for a way to write the IDS's own rules, for attacks on their own sites that CRS does not know, such as "admin pages reached from outside the office". Eight decisions (N1–N8, main plan section 11.38) shaped it; five stages were built, the first with a pause for review, the others in one run, each with its tests, a browser round and a commit.

1. The engine: a file of own rules, named by `own_rules` and loaded right before CRS's 949 file, which adds up the score. Before it is compiled, every rule is checked to only detect: a number from 1,000 to 99,999, a message, a severity, and exactly that severity's points added to the score; anything that could switch other rules off or skip them is refused with the file, line and rule named.
2. Rules for some applications only: each application's list of rules switched off gains the own rules not meant for it, and requests of no application get a list of their own, so the one shared rule set stays (decision F5's option B).
3. The dashboard: own rules in a group of their own on the Rules page, with the requests each one is for; a form that writes a rule from conditions, a message and a severity, and shows the SecLang; the rules added, changed and removed as pending changes with the preview, versions and undo of the other changes; analysts propose, admins apply.
4. Trying a rule before it is applied: the Test tab runs a request written by hand with the pending changes, built as they would be applied, and Analyse files' Try runs them on analysed files.
5. A mistake: a check run in stage 1 wrote two runs into the user's records folder; they were removed the same hour (the plan's stage 1, note 10).

## 5. How the work was done

### 5.1. Decisions before code

1. The assistant proposed options in numbered points, each with a reason and a small example; the team chose. Nothing open was treated as decided.
2. Each decision got an ID and was written down with its date and reason: M (architecture), A (open topics), D (rule-layer plan), K (whole rule part), R and V (records and dashboard), U (dashboard UI), F (application profiles), T (live traffic), S (the test tab), G (marks, roles and the change log), W (a dashboard that controls the IDS), Y (the dashboard on IBM Carbon), N (own rules). The history is in section 11 of the main plan.
3. Work was split into plans with a number to reach (tests that must pass), and a report followed each plan. From plan A on, the team asked for one plan at a time with a stop for review. Code was committed and pushed only when the team asked.

### 5.2. Behaviour taken from a source, never guessed

Every behaviour was copied from one of three sources, and every expected test value came from a source too:

1. **ModSecurity v2's C code** (commit `151074a`). The C functions were compiled unchanged into a small test program and run on thousands of inputs; the inputs and outputs are stored in the repository, and Go tests compare our functions with every one.
2. **Coraza's Go code** (v3.8.1), the same way for the functions that follow Coraza.
3. **The CRS files and CRS's own regression tests.** The CRS files are never edited.

Several times a value written from memory turned out wrong, and only a reference caught it. That is why the rule exists.

### 5.3. Five kinds of checks

| Check | What it shows | Where |
| --- | --- | --- |
| Reference results for single functions | A transformation or operator gives the same output as ModSecurity or Coraza | `internal/engine/transform/testdata/`, `internal/engine/operator/testdata/` |
| CRS regression tests | For each test request, the rules CRS expects match, and the rules it expects not to match do not | `testdata/requests/crs/` (converted by `tools/convert_crs_tests.py`) |
| Comparison with Coraza on whole requests | Same rules, places, match counts, and score as an independent engine, at levels 1 and 4 | `tools/coraza-reference/`, `testdata/reference/`, `internal/engine/reference_test.go` |
| Fuzzing and Go's race detector | No crash on random input; requests running at the same time do not share state | `go test -fuzz`, `go test -race` |
| Requirement tests | M11 (no request content in the output) and M21 (separate state per request, also in 8 goroutines) | `cmd/ids-offline`, `internal/engine` tests |
| Per-application exceptions against SecLang | The same exceptions applied per request and written as SecLang give the same results on all CRS tests at levels 1–4 | `internal/engine/tuning_test.go` |
| Live against offline | The same requests give the same records through Caddy and `ids-live` as from files | `lab/compare`, `lab/lab.sh`, `TestLiveMatchesOffline` in `internal/live` |
| Test tab against offline | A request written as raw text in the dashboard gives what `ids-offline` gives from its file | `TestTabMatchesOffline` in `internal/dashboard` |
| Roles on every route | Each page and answer as no login, viewer, analyst and admin | `TestRoutesByRole`, `TestEveryRouteNeedsALogin` in `internal/dashboard` |

Generated requests were added where the CRS tests had too few cases: 400 path traversal, 400 file access, and 500 SQLi/XSS variants with different encodings (`testdata/requests/generated/`).

### 5.4. Rules the engine follows

1. CRS files are loaded unchanged.
2. The engine refuses to start when a rule needs something it does not support, and lists every such rule. A rule may only be left out with a written reason in the configuration (M15). Nothing is skipped silently.
3. Where ModSecurity and Coraza differ, the engine takes the behaviour that detects more without hiding text, and the difference is written down:

| Behaviour | Follows | Why |
| --- | --- | --- |
| 12 transformations (URL decoding, comment removal, and others) | ModSecurity v2 | CRS is written for ModSecurity |
| `normalizePathWin`, `normalizePath`, `htmlEntityDecode`, `base64Decode` | Coraza | ModSecurity's versions can lose a file name or stop at a line break |
| `@validateUtf8Encoding` | Coraza (Go) | ModSecurity also accepts a few byte sequences that are not UTF-8 |
| Body without a reader | ModSecurity (one text) | Team decision, 16 October; a CRS test supports it |
| Multi-line patterns | ModSecurity (off) | CRS patterns are written for it; Coraza plans the same change |
| Multipart header with forbidden characters | Kept (ModSecurity stops with an error) | So that rule 922130, written for such headers, can find it |

### 5.5. Making it fast without changing results

Profiling showed that over 90 % of the time was spent in Go's regular-expression matcher. Three changes:

1. A pattern is first asked only "does it match?"; the slower search for its groups runs only on a match.
2. **Word prefilter:** many patterns can only match if the value contains one of a few fixed words, worked out from the pattern when it is loaded. A value without any of them skips the pattern. 144 of the 268 patterns get one. Because a wrong prefilter would hide an attack, a test runs every pattern on about 30,000 values with and without it: about 4 million values were skipped, and none of them was a match. A fuzz test checks the same on random input.
3. The values of each variable are built once per request instead of once per rule.

After these changes all 5,072 CRS tests and the Coraza comparison were run again with the same results.

### 5.6. Roles and tools

1. The team made the decisions; the AI coding assistant (Claude Code) wrote the code and documents (decision D5), and the team reviews them.
2. Go 1.26.8 for the product, 1.26.10 since 18 November; Python for the test converters and the ML pilot; Coraza only in a separate helper module; Caddy v2.11.9, built with xcaddy, only in the copier's own module; git and a private GitHub repository. Browser checks of the dashboard used browser-use until 25 October and Playwright from 18 November.
3. Development machines: Fedora Linux on an AMD Ryzen 5 7530U laptop (12 threads) until 17 November; since then Fedora 44 in WSL2 on a PC with an Intel Core i5-9400F, 4 CPUs given to WSL. The lab's numbers come from that machine.

## 6. How the engine works today

```text
                                  client ==HTTPS==> Caddy + ids_copy --> application
                                                          |
                                                          | a copy over a Unix socket
                                                          v
example request (JSON file)                         internal/live
        |                                           receives the copies; a queue
        v                                           with limits; drops counted
internal/offline      reads the requests                  |
        |                                                 |
        +-------------------------------------------------+
        |
        v
internal/httpmodel    received content -> parsed view (path, query, cookies,
                      form, JSON, multipart, XML) + analysis status
        |
        v
internal/profile      the application of the request (Host and path),
                      with its exceptions and paranoia level
        |
        v
internal/engine       for each rule in phase 1, then phase 2:
                      variables -> transformations -> operator -> actions
                      (score, chain, skip, ctl); TX state is per request;
                      the application's exceptions applied on the way
        |
        v
internal/profile      the request against the profile's allow list:
                      profile findings, kept apart from the score
        |
        v
internal/result       findings (rule, severity, location), score,
internal/record       profile findings, status; records with secrets
                      masked; no request content in the output (M11)
        |
        v
cmd/ids-offline       text, JSON, or per-file test summary;
cmd/ids-live          the live input as a service, writing records;
cmd/ids-dashboard     the records in a browser, also the live input's gaps;
                      its test tab analyses a request written by hand
```

A real run (`go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json`), one of the starter requests, `GET /get?arg=../../../etc/passwd`:

```text
[2] CRS 930110-2: traversal in the query string
    request: GET, body empty
    930100  CRITICAL  REQUEST_URI_RAW                     Path Traversal Attack (/../) or (/.../)
    930100  CRITICAL  ARGS:arg                            Path Traversal Attack (/../) or (/.../)
    930110  CRITICAL  REQUEST_URI_RAW                     Path Traversal Attack (/../) or (/.../)
    930110  CRITICAL  ARGS:arg                            Path Traversal Attack (/../) or (/.../)
    930120  CRITICAL  ARGS:arg                            OS File Access Attempt
    932160  CRITICAL  ARGS:arg                            Remote Command Execution: Unix Shell Code Found
    949110  -         TX:BLOCKING_INBOUND_ANOMALY_SCORE   Inbound Anomaly Score Exceeded (Total Score: 30)
    score 30, threshold 5: THRESHOLD EXCEEDED
    expectation: met
```

The output names where each rule matched but not the matched text (M11). Coraza gives the same score, 30.

## 7. Problems met and how they were solved

| Problem | How it was found | What was done |
| --- | --- | --- |
| Go reads text as UTF-8; some CRS patterns name single bytes above 0x7F | Counting the patterns before stage 6 | A byte mode for those patterns, as PCRE matches them |
| ModSecurity's `normalizePathWin` and `htmlEntityDecode` miss disguised attacks | Coraza comparison | Followed Coraza (section 4.4) |
| `REQUEST_FILENAME` must be URL-decoded, or a rule misses `alert(` after `%3E` | Coraza comparison | Decoded, as Coraza and ModSecurity v3 do |
| Coraza adds a multi-line flag to every pattern | 2 differences at level 4 in plan A | Reference built with Coraza's option that turns it off; our engine was right |
| A test of ours assumed every detection reaches the alert threshold | Failing test at levels 2–4 | Test corrected: some rules add 3 points, the threshold is 5 |
| A CRS test needs the name of a JSON list to be a field name | CRS test 934210-13 | The JSON reader also gives the list length under the list name, as Coraza does |
| A `#fragment` stayed in the last query parameter | Coraza comparison, plan D | Fixed; servers drop the fragment |
| A three-digit card code (`cvv=731`) was masked in its own place but not inside a finding that holds the whole query or body | Review of the masking code, then a failing test (23 October) | Short secret values are now removed from such whole texts too |
| The product configuration's new `records` section broke the engine's own tests | Full test run (23 October) | The engine tests read only the engine part of that file |
| The dashboard redrew a page every 5 seconds, closing an open table | Looking at the pages in a browser | A page is redrawn only when its data changed |
| CRS tests assume CRS's test setup and Apache's request handling | Failing protocol tests in plan D | CRS's test setup rule copied for the tests only; converter applies RFC 9112 message length; HTTP/0.9 supported |
| Coraza numbers multipart headers in random order | Comparison differed between runs | The number is compared without that detail; rules and scores always agreed |
| Speed fell to 57 ms on long values as rules were added | Benchmarks in plans B–D | Profiling, then the three changes of section 5.5 |
| Race-detector run longer than Go's 10-minute default | Timeout, not a race | Run with a longer limit; passes |
| The fuzzer broke a property in our own test (`\/..` becomes empty) | Fuzzing, plan C | The property was wrong (Coraza does the same); corrected, input kept as a seed |
| A JSON body written in full could keep a secret written with JSON escapes | A new fuzz test (25 October) | A JSON body with a secret field is written again with that field masked |
| A setup rule that sets a CRS setting on every request would silently replace an application's value | Reading the CRS test setup (rule 900005) | The profile is refused, naming that rule |
| Paths with `..` could fit an allowed folder in a profile while the application resolves them elsewhere | Writing the path matcher | Such paths are unknown endpoints |
| Two scanner probes on the CSIC shop's host fell outside its path prefix and skipped the profile | The training records (25 October) | The prefix was removed: the host serves only the shop |
| Coraza refuses an empty `setvar` value | The Coraza comparison of the CSIC profile | A single space, which has the same effect for that setting |
| A request body over 1 MiB was not inspected at all | Writing the proxy plan (26 October) | A setting with Coraza's limit, 12.5 MB; past it the first part is inspected and the record says so |
| A Unix socket's path can't be longer than about 108 bytes | The first socket measurement failed | `ids-live` and the copier check the path at start, with a clear message |
| Go's HTTP server, under Caddy, changes the case and order of header names | Reading Caddy's code, before building | The copier rebuilds them in a fixed order; the lab showed no rule result changed |
| A copy longer than `ids-live`'s frame limit would be refused whole | A question from the team about 15 MB bodies | `ids-live` gives its limit when a copier connects; the copier shortens the copy |
| The plan's build command failed: xcaddy treats every `--with` as a Caddy plugin | The first build | This repository is given with `--replace` instead |
| Caddy writes a file into the home folder whatever its storage setting says | After the first test with a real Caddy | Tests and the lab point Caddy's data folder at their own folder |
| Caddy's reverse proxy unzips gzip for a client that did not ask for it | The lab's response check | Documented; the check now asks for gzip |
| With CPU pinning, the lab script saved the IDs of helper shells, so a timing run stopped nothing and left programs running | The process list after the run | Those numbers were thrown away; the script starts the pinning itself and waits for each run's own ready line |
| A comparison run during the work wrote into the repository's `records/` folder, which holds the team's own records | Checking the folder afterwards | The added lines were removed from a copy; check runs always get a temporary records folder |

## 8. What the results do not show

1. **Not full CRS compatibility.** Response rules (CRS files 950–980) are not run; they need a copy of each response and wait for the proxy decision.
2. **No request has been run through ModSecurity itself.** ModSecurity behaviour comes from its source code and from running single C functions.
3. **The CRS tests are not detection or false-alarm rates.** They show agreement with CRS's expectations on its own test requests.
4. **The CSIC data is old and synthetic** (one shop application from 2010), and its "anomalous" label includes many requests that are not attacks of these types. The numbers in sections 4.5 and 4.8 are not rates for real traffic. The shop's profile was written from its training records, which therefore no longer measure false alarms; the ML test set had been looked at before.
5. Live traffic was measured in a lab, not on a real site. The requests were the CSIC files, replayed on one machine; the times hold for that machine, where the analysis shared four CPUs with the site. Only Caddy can send copies so far. Response bodies are copied but not analysed until the response rules.
6. An alert is the rule layer's score at the CRS threshold, or a profile finding of an application in `alert` mode, not the planned decision of all layers.

## 9. What comes next

The order the team decided on 12 October 2026, with the first step widened on 23 October:

1. Records, alerts, and a dashboard (A09), built as one step: **done on 23 October** (section 4.6); the dashboard UI was reworked on 24 October (section 4.7).
2. Hand-written application profiles (A04): **done on 25 October** (section 4.8).
3. Live traffic through Caddy (A01, A08): done on 18 November and closed on 19 November (section 4.9).
4. A test tab in the dashboard: done on 19 November (section 4.10). Marks, users with roles and a change log: done on 20 November (section 4.11).
5. Next, the team's choice: turning a false positive into an exception with a preview and a history, settings pages, more views, or the response rules and alerts sent by webhook and syslog (decided on 23 October). `ids-offline` keeps its name (decided 19 November).
6. Moving the ML model into Go through ONNX, and the decision mechanism (A10, A05, A07, A06).
7. Prevention, learned profiles, other protocols, and an Nginx input.

On 16 October the team added two ideas (main plan section 6.15): an MCP server through which an AI assistant configures the IDS and corrects false positives, after the dashboard exists and the IDS is usable; and correcting the false positives found on the CSIC 2010 records, which was done by hand with the profiles on 25 October.

Each step needs its own decisions before work starts. Other open points: realistic normal traffic for measuring false alarms (A07), and the remaining slow patterns on long values.

## 10. Where the details are

| Document | Content |
| --- | --- |
| [ids-system-plan-phaze1.md](../ids-system-plan-phaze1.md) | Architecture, all decisions with reasons, dated history (section 11) |
| [development-plan-rule-layer.md](development-plan-rule-layer.md) | The 8-stage plan of 11 October, with results per stage |
| [development-plan-all-request-rules.md](development-plan-all-request-rules.md) | Plans A–F, with results per plan |
| [development-plan-records-dashboard.md](development-plan-records-dashboard.md) | The plan for records, alerts, and the dashboard, with notes per stage |
| [development-plan-dashboard-ui.md](development-plan-dashboard-ui.md) | The dashboard UI plan: problems, decisions U1–U8, notes and checks |
| [development-plan-profiles.md](development-plan-profiles.md) | The profile plan: decisions F1–F11, stages, notes with every measurement, the CSIC results |
| [development-plan-proxy.md](development-plan-proxy.md) | The plan for live traffic through Caddy: research, decisions T1–T12, stages, notes with every lab measurement |
| [copy-format.md](copy-format.md) | The frames between a proxy's copier and `ids-live`, and how to set both up |
| [development-plan-test-tab.md](development-plan-test-tab.md) | The plan for the dashboard's test tab: decisions S1–S4, notes with the checks and timings |
| [development-plan-marks-users.md](development-plan-marks-users.md) | The plan for marks, users with roles and the change log: decisions G1–G6, notes with the checks |
| [dashboard-state.md](dashboard-state.md) | The dashboard's own files: users, the log of logins, the change log, the marks |
| [profile-format.md](profile-format.md) | The profile format, exceptions, findings, and known limits |
| [records-format.md](records-format.md) | The record format, masking rules, and known limits |
| [crs-4.30.0-ruleset.md](crs-4.30.0-ruleset.md) | The CRS files and what the engine supports |
| [context.md](../context.md) | Short current state |
| [testdata/requests/README.md](../testdata/requests/README.md), [testdata/reference/README.md](../testdata/reference/README.md) | How the test requests and the Coraza reference were made |

Commits on `main`:

| Commit | Date | Content |
| --- | --- | --- |
| `4aa613f`, `6698f28`, `fc80ae3` | 4 Oct | Initial repository, clean-up |
| `48c1f19` | 11 Oct | First offline engine, rules 930100 and 930110 |
| `36f2251` | 11 Oct | Rule layer for the Phase 1 scope, with the Coraza behaviour of two transformations |
| `5cdaef3` | 11 Oct | Coraza's colon cut left out of `normalizePathWin` |
| `4aa49f3` | 12 Oct | Plan A |
| `1da15b3` | 16 Oct | Plan B (done 12 October) |
| `1503ee9` | 16 Oct | Plan C |
| `3c1b6bf` | 16 Oct | Plan D |
| `c8bcab7` | 16 Oct | Plans E and F |
| `df0ecdc` | 23 Oct | Records, alerts, and the read-only dashboard |
| `dbc6338` | 24 Oct | Dashboard UI reworked |
| `68b42c8` | 25 Oct | Application profiles and the CSIC shop's profile |
| `71ffe71` | 25 Oct | Closing documents of the profile plan |
| `659a0f1` | 30 Oct | Copy frame format for live traffic (proxy plan, stage 2) |
| `2be0781` | 30 Oct | Request body limit of 13,107,200 bytes, partly inspected bodies (stage 3) |
| `5fba3dc` | 30 Oct | Proxy plan with decisions T1–T12 (stage 1) |
| `8a1d3af` | 17 Nov | Notes for a second machine, LF line endings |
| `6c376ce` | 18 Nov | `ids-live` and the live records (stage 4) |
| `353d63e` | 18 Nov | The Caddy copier `ids_copy` (stage 5) |
| `a378c5b` | 18 Nov | The dashboard shows the live input, in IBM Carbon (stage 6) |
| `f1bc32f` | 18 Nov | The lab and its measurements (stage 7) |
