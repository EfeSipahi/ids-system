# Project history: what was done and how

Written: 16 October 2026, for the project report; updated 23 October 2026  
Covers: 27 September 2026 (ML pilot) to 23 October 2026 (records, alerts, and dashboard built)  
Sources: the main plan [ids-system-plan-phaze1.md](../ids-system-plan-phaze1.md) (history in section 11), the two development plans in this folder, [context.md](../context.md), the git history, and the README of the separate ML project `ids-model`. Every number below comes from one of these or from a run of the code on 16 or 23 October 2026.

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

**What exists on 23 October 2026:**

| Part | State |
| --- | --- |
| Rule layer (Go) | **Done for the request side of CRS.** Runs every CRS 4.30.0 request rule file at paranoia levels 1 to 4, on requests read from files |
| Records and alerts (Go) | **Done.** Every request with a finding or an incomplete analysis is written to a record file, with secrets masked; an alert is a score at the CRS threshold ("rule layer only") |
| Dashboard (Go) | **Done, read-only.** A separate program shows the records in a browser, behind a login, over HTTPS only |
| ML layer | A pilot in the separate Python project `ids-model` (Random Forest and logistic regression on 1,000 CSIC 2010 records). Not yet moved into Go |
| Profiles, decision mechanism, proxy/TLS | Designed and approved (decisions M01–M21), not built yet |

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
| Code | About 9,500 lines of Go product code and 8,100 lines of Go tests (190 test functions, 6 fuzz tests, 5 benchmarks); 850 lines of dashboard HTML, CSS, and JavaScript; 714 lines of Python tools; one Go dependency (`libinjection-go`). On 16 October: 6,100 and 5,350 lines |

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

## 5. How the work was done

### 5.1. Decisions before code

1. The assistant proposed options in numbered points, each with a reason and a small example; the team chose. Nothing open was treated as decided.
2. Each decision got an ID and was written down with its date and reason: M (architecture), A (open topics), D (rule-layer plan), K (whole rule part). The history is in section 11 of the main plan.
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
2. Go 1.26.8 for the product; Python for the test converters and the ML pilot; Coraza only in a separate helper module; git and a private GitHub repository.
3. Development machine: Fedora Linux, AMD Ryzen 5 7530U (12 threads).

## 6. How the engine works today

```text
example request (JSON file)
        |
        v
internal/offline      reads the requests
        |
        v
internal/httpmodel    received content -> parsed view (path, query, cookies,
                      form, JSON, multipart, XML) + analysis status
        |
        v
internal/engine       for each rule in phase 1, then phase 2:
                      variables -> transformations -> operator -> actions
                      (score, chain, skip, ctl); TX state is per request
        |
        v
internal/result       findings (rule, severity, location), score, status;
                      no request content by default (M11)
        |
        v
cmd/ids-offline       text, JSON, or per-file test summary
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

## 8. What the results do not show

1. **Not full CRS compatibility.** Response rules (CRS files 950–980) are not run; they need a copy of each response and wait for the proxy decision.
2. **No request has been run through ModSecurity itself.** ModSecurity behaviour comes from its source code and from running single C functions.
3. **The CRS tests are not detection or false-alarm rates.** They show agreement with CRS's expectations on its own test requests.
4. **The CSIC data is old and synthetic** (one shop application from 2010), and its "anomalous" label includes many requests that are not attacks of these types. The numbers in section 4.5 are not rates for real traffic.
5. **The engine reads requests from files only.** There is no live traffic yet. An alert is the rule layer's score at the CRS threshold, not the planned decision of all layers.

## 9. What comes next

The order the team decided on 12 October 2026, with the first step widened on 23 October:

1. Records, alerts, and a dashboard (A09), built as one step: **done on 23 October** (section 4.6).
2. **Next:** hand-written application profiles (A04). The CSIC results show why they are needed.
3. Proxy and TLS integration (A01, A08), then the response rules, and alerts sent by webhook and syslog (decided on 23 October).
4. Moving the ML model into Go through ONNX, and the decision mechanism (A10, A05, A07, A06).
5. Prevention, learned profiles, other protocols.

On 16 October the team added two ideas (main plan section 6.15): an MCP server through which an AI assistant configures the IDS and corrects false positives, after the dashboard exists and the IDS is usable; and correcting the false positives found on the CSIC 2010 records.

Each step needs its own decisions before work starts. Other open points: realistic normal traffic for measuring false alarms (A07), and the remaining slow patterns on long values.

## 10. Where the details are

| Document | Content |
| --- | --- |
| [ids-system-plan-phaze1.md](../ids-system-plan-phaze1.md) | Architecture, all decisions with reasons, dated history (section 11) |
| [development-plan-rule-layer.md](development-plan-rule-layer.md) | The 8-stage plan of 11 October, with results per stage |
| [development-plan-all-request-rules.md](development-plan-all-request-rules.md) | Plans A–F, with results per plan |
| [development-plan-records-dashboard.md](development-plan-records-dashboard.md) | The plan for records, alerts, and the dashboard, with notes per stage |
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

The work of 23 October is not committed yet.
