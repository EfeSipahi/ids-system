# Development plan: all CRS request rules, all paranoia levels

Written: 12 October 2026. Approved by the user on the same day. Progress is recorded in section "Progress" at the end.

## Context

1. The rule layer runs the 51 PL1 rules of CRS files 930, 941 and 942 (687 CRS tests pass, results agree with Coraza). It is on `main` and pushed.
2. On 12 October 2026 the user decided to finish the rule part before any other layer, and accepted the recommendations K1–K11:
   - K1–K5: proxy/TLS, ML, decision mechanism, prevention and other protocols wait.
   - **K6:** support all request attack groups (amends M19).
   - **K7:** support all four paranoia levels, configurable, PL1 the default (amends M20).
   - **K8:** response rules (files 950–980) wait for the proxy decision; they need a copy of each response.
   - K9, K10: records/alerts, then hand-written profiles, come after this work.
   - K11: stages in a row, a report after each.
3. Goal of this plan: every rule of the 17 request files loads and runs from the unmodified CRS files, and all **5,073** request-side CRS regression tests that an offline engine can check pass.
4. The numbers of tests in this document were corrected during plan A. The first count (5,070) came from a text search that missed some tests. The CRS request tests hold 5,094 requests. 21 of them expect only an answer of the web server (a status code), which an offline engine does not have; they are left out and counted. The other 5,073 are converted.

## What was examined

All 28 rule files were loaded into the current engine. Request side: 459 rules, 286 of them detection rules; 91 rules cannot load. No regex pattern fails to compile in Go.

| File | Group | Rules | Detection rules (PL1/2/3/4) | Cannot load | CRS tests | What it lacks |
| --- | --- | --- | --- | --- | --- | --- |
| 901 | Setup | 33 | – | 0 (7 excluded) | 18 | – |
| 905 | Common exceptions | 2 | – | 2 | 0 | `REMOTE_ADDR`, `@ipMatch`, `REQUEST_LINE`, `ctl` in a chain |
| 911 | Method enforcement | 9 | 1/0/0/0 | 1 | 8 | `REQUEST_METHOD`, `@within` |
| 913 | Scanner detection | 9 | 1/0/0/0 | 0 | 9 | nothing; never run |
| 920 | Protocol enforcement | 68 | 40/9/5/5 | 36 | 407 (+21 left out) | 21 different items (see plan D) |
| 921 | Protocol attack | 26 | 11/2/3/1 | 7 | 117 | `ARGS_GET(_NAMES)`, `@gt`, `REQUEST_BODY`, `REQUEST_HEADERS_NAMES`, engine items |
| 922 | Multipart attack | 7 | 4/0/0/0 | 7 | 47 | `MULTIPART_PART_HEADERS`, `@gt`, `@unconditionalMatch`, engine items |
| 930 | LFI | 14 | 5/1/0/0 | 0 | 83 | nothing; PL2 never run |
| 931 | RFI | 13 | 3/2/0/0 | 2 | 42 | `QUERY_STRING`, `REQUEST_BODY`, `@endsWith`, engine items |
| 932 | RCE | 56 | 19/19/10/0 | 14 | 1,089 | `t:escapeSeqDecode`, `t:normalizePath`, `REQUEST_LINE`, `MATCHED_VAR`, `@beginsWith` |
| 933 | PHP | 29 | 13/3/5/0 | 3 | 442 | `t:normalizePath` |
| 934 | Generic | 22 | 8/5/1/0 | 5 | 287 | `t:base64Decode`, `REQUEST_BODY` |
| 941 | XSS | 42 | 26/7/0/0 | 0 | 263 | nothing; PL2 never run |
| 942 | SQLi | 68 | 20/31/7/2 | 0 | 1,033 | nothing; PL2–4 never run |
| 943 | Session fixation | 11 | 3/0/0/0 | 1 | 47 | `@endsWith`, a request macro |
| 944 | Java | 22 | 6/6/1/1 | 13 | 1,176 | `REQUEST_BODY`, `REQUEST_LINE` |
| 949 | Blocking evaluation | 28 | – | 0 | 5 | – |

"Engine items" = a macro inside a `setvar` name, a regex selector on `TX`, `ctl` on a chained rule, `ctl:ruleRemoveById`, macros for request values such as `%{request_line}`.

A rule that loads is not thereby correct: only the tests show that.

## The implementation plans

Each plan is one unit of work with its own acceptance number. They run in this order because each uses what the one before added.

### Plan A — Paranoia levels and the test base

1. Config option for the paranoia level (1–4, default 1) in `internal/engine/config.go`; an invalid value is a startup error (M20 point 1).
2. Find in the CRS test setup which level the regression tests expect, and run them that way. Checked in the CRS source, not assumed.
3. Convert the tests of all 17 request files with `tools/convert_crs_tests.py`; extend it for test fields it does not handle yet (10 tests use `encoded_request`).
4. Record the baseline per file with `ids-offline -summary`.
5. Make the files that already load pass: 913, 930, 941, 942 at all levels.

**Acceptance:** 1,388 tests (913: 9, 930: 83, 941: 263, 942: 1,033). The 23 tests of 901 and 949 moved to plan D, because five of them need rules of file 920.

### Plan B — Request basics and engine items

1. Variables in `internal/engine/targets.go`: `REQUEST_METHOD`, `REQUEST_LINE`, `REQUEST_PROTOCOL`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `REQUEST_HEADERS_NAMES`, `ARGS_GET`, `ARGS_GET_NAMES`, `ARGS_COMBINED_SIZE`, `FILES_COMBINED_SIZE`, `MATCHED_VAR`, `REQBODY_PROCESSOR`.
2. Operators in `internal/engine/operator/`: `@gt`, `@within`, `@endsWith`, `@beginsWith`, `@unconditionalMatch`.
3. Transformation `length`.
4. Engine items: macros in `setvar` names, regex selectors on `TX`, request-value macros, `ctl:ruleRemoveById`, `ctl` in a chain.

**Acceptance:** 911 (8), 931 (42), 943 (47), 944 (1,176) = 1,273 tests.

### Plan C — Three transformations

`normalizePath`, `escapeSeqDecode`, `base64Decode`, each written from the reference source and checked against recorded reference results, as the existing 13 are.

**Acceptance:** 932 (1,089), 933 (442), 934 (287) = 1,818 tests.

### Plan D — Protocol rules

1. Operators `@validateUtf8Encoding`, `@validateUrlEncoding`, `@ipMatch`.
2. `REMOTE_ADDR`: the offline request format gets an optional client address (file 905 only uses it to exempt local health checks).
3. Whatever of 920 and 921 still fails after plans B and C.

**Acceptance:** 920 (407), 921 (117), 901 (18), 949 (5) = 547 tests; file 905 loads with no exclusion.

### Plan E — Multipart rules

`MULTIPART_PART_HEADERS` in `internal/httpmodel/body.go`: the multipart reader keeps the header lines of every part.

**Acceptance:** 922 (47 tests).

### Plan F — Checks on the whole set

1. New Coraza reference file for all request files (`tools/coraza-reference`), compared at PL1 and PL4; every difference explained or fixed.
2. Normal-traffic check with the 1,000 pilot records at each of the four levels (shows how many normal requests each level flags).
3. Benchmarks again. With about five times as many rules, the two speed improvements already noted (run a transformation chain once per value; skip a pattern whose required word is absent) are done here if the numbers call for it.
4. Fuzzing, race detector, M11 and M21 checks again.
5. Documents: amend M19 and M20 in `ids-system-plan-phaze1.md`, update `context.md` and `docs/crs-4.30.0-ruleset.md`.

**Acceptance:** all 5,073 tests pass; no unexplained difference from Coraza.

## Rules for every plan

1. Behaviour comes from a source: the ModSecurity v2 C code, Coraza's Go code, or the CRS files. Expected test values are never guessed.
2. Where ModSecurity and Coraza differ, take the one that detects more without hiding text, and write the difference down (as in section 11.15 of the main plan).
3. CRS files stay unmodified. A rule that cannot run is excluded in the config with a written reason, never skipped silently (M15).
4. No new Go dependency is expected (`encoding/base64` and `net/netip` are standard library). If one is needed, it is proposed first.
5. After each plan: `go vet`, `go test`, `go test -race`, the test summary, and a report in numbered points.
6. No commit unless the user asks.
7. Stop and ask only for a new decision or a result that looks wrong.

## Verification

```
go vet ./... && go test ./... && go test -race ./...
go run ./cmd/ids-offline -requests testdata/requests/crs -summary -paranoia-level 4
go test -v -run 'TestAgainstCoraza$' ./internal/engine
```

The summary must show 0 failed and 0 not inspected for the files of every finished plan.

## What this plan does not include

Response rules (950–980), records and alerts, profiles, proxy, ML, the decision mechanism. Passing the CRS tests is still not a detection rate for real traffic, and no request is run through ModSecurity itself.

## Progress

### Plan A — done on 12 October 2026

**What was added**

1. **Paranoia level.** `paranoia_level` in the configuration (1 to 4, default 1) and the flag `-paranoia-level` of `ids-offline`. Any other value stops the start with an error. The engine sets `tx.blocking_paranoia_level` before the first rule runs, which is what CRS's own setup rule 900000 does; the CRS files then switch their rules on and off themselves. The startup report shows the level, and each rule's status carries its own level.
2. **Rule file 913** (scanner detection) is loaded. 188 of 195 rules are active; the 7 excluded ones are unchanged.
3. **Test converter** (`tools/convert_crs_tests.py`) reads all tests of a rule file at all levels. New: a request given as raw bytes (`encoded_request`), a body that is not text (`body_base64`), and tests that look at log text (`match_regex` becomes `expect_log`). Tests that expect only a web-server status are left out and counted.
4. **Example format:** `expect_log`, `no_expect_log`, `body_base64`. A log line has the form `[id "930110"] [msg "..."] [data "..."]`.
5. **Test folders:** `testdata/requests/crs/` holds the tests of finished rule files, which must all pass: 100 files, 1,388 tests. `testdata/requests/crs-pending/` holds the others: 190 files, 3,685 tests. A file moves from the second to the first when its plan is done.
6. **Coraza helper** got a `-paranoia-level` option. There are now two reference files, for levels 1 and 4.

**What the CRS source says about the test level:** the CRS test setup runs all regression tests at level 4 (`BLOCKING_PARANOIA: 4` in `tests/docker-compose.yml`, and `setvar:tx.blocking_paranoia_level=4` in `tests/regression/README.md`). Ours run the same way.

**Results**

| Check | Result |
| --- | --- |
| CRS tests of 913, 930, 941, 942 at level 4 | 1,388 of 1,388 pass |
| The same tests at levels 1, 2, 3 | A test passes when its rule belongs to the level; a rule above the level never matches |
| Comparison with Coraza, level 1 | 2,694 requests, 1,423 with a match, 0 differences |
| Comparison with Coraza, level 4 | 2,694 requests, 2,154 with a match, 0 differences |
| `go vet`, `go test`, `go test -race` | Pass, eight packages |

In both comparisons 4 requests with invalid UTF-8 differ in match count only, as before (`utf8toUnicode`).

No engine code had to be corrected: the rules of levels 2 to 4 in these four files passed their tests on the first run.

**Two things found on the way**

1. **Coraza's multi-line mode.** The first comparison at level 4 showed 2 differences. Both came from Coraza adding the multi-line flag to every pattern, so that `^` and `$` also match at line breaks inside a value. ModSecurity does not do that, and CRS patterns are written for ModSecurity. Coraza's own README calls this a default it will drop in its next major version, and gives a build option to turn it off (`coraza.rule.no_regex_multiline`). The reference files are now produced with that option, and the two differences are gone. Our engine was right in both cases; nothing was changed in it.
2. **A wrong assumption in a test of ours.** The test assumed every detection reaches the alert threshold. Some rules of levels 2 to 4 add 3 points, and the threshold is 5. The test now checks what holds: a detection gives a score, and rule 949110 reports exactly the requests at or above the threshold.

**Pilot records per level** (the 1,000 CSIC records; with files 913, 930, 941, 942 only; not rates for real traffic)

| Level | Normal flagged (of 500) | Anomalous flagged (of 500) |
| --- | --- | --- |
| 1 | 0 | 80 |
| 2 | 0 | 98 |
| 3 | 0 | 100 |
| 4 | 1 | 102 |

**Baseline of the pending tests:** of the 3,685 pending tests, 792 pass today. That number means little: their rule files are not loaded, so a test passes only when it expects no match.

**Left for later plans**

1. Five tests of 901 and 949 need rules 920100 and 920420 (plan D).
2. 21 tests expect only a web-server status and are not converted. Plan D decides whether any of them says something about a rule.
3. The log-line form was only needed by one test so far. 13 more tests in later plans use it and will show whether the form is close enough to ModSecurity's.

### Plan B — done on 12 October 2026

**What was added**

1. **Variables:** `REQUEST_METHOD`, `REQUEST_PROTOCOL`, `REQUEST_LINE`, `REQUEST_URI`, `QUERY_STRING`, `REQUEST_BODY`, `REQUEST_HEADERS_NAMES`, `ARGS_GET`, `ARGS_GET_NAMES`, `ARGS_POST`, `ARGS_POST_NAMES`, `MATCHED_VAR`, `MATCHED_VAR_NAME`.
2. **Operators:** `@gt`, `@within`, `@beginsWith`, `@endsWith`, `@unconditionalMatch`, written after Coraza's operators of the same names.
3. **Transformation:** `length`.
4. **Engine:** a macro may name any supported variable (`%{request_headers.host}`, `%{REQUEST_LINE}`); a `setvar` name may contain a macro (`tx.rfi_parameter_%{MATCHED_VAR_NAME}`); a pattern may select TX variables (`TX:/rfi_parameter_.*/`).
5. **Rule files 911, 931, 943, 944** are loaded. 243 of 250 rules are active; the 7 excluded ones are unchanged.

**`REQUEST_BODY`, the one design point.** It holds the body as one text when the body is a form or of a type that has no reader, such as `text/plain`. For a JSON, XML or multipart body it has no value; the rules see the parts. This is what ModSecurity does with the CRS defaults: it fills `REQUEST_BODY` for a form, and CRS rule 901340 asks for it when no body reader was chosen. Rule 901340 itself stays excluded, because the engine does this without being told. One consequence: a `text/plain` body used to be invisible to the rules and is now inspected by every rule that reads `REQUEST_BODY`. It is still reported as "not inspected", meaning not split into fields.

**Results**

| Check | Result |
| --- | --- |
| CRS tests of the eight finished files at level 4 | 2,661 of 2,661 pass (911: 8, 913: 9, 930: 83, 931: 42, 941: 263, 942: 1,033, 943: 47, 944: 1,176) |
| The same tests at levels 1, 2, 3 | As in plan A: a rule above the level never matches |
| Comparison with Coraza, level 1 | 3,967 requests, 2,253 with a match, 0 differences |
| Comparison with Coraza, level 4 | 3,967 requests, 3,382 with a match, 0 differences |
| `go vet`, `go test`, `go test -race` | Pass, eight packages |

All 1,273 new tests passed on the first run after the features were written.

**One explained class of difference from Coraza.** 108 of the compared requests have a body without a reader. Coraza splits such a body into parameters as if it were a form; ModSecurity, and we, do not. So on 62 of them at level 1 (95 at level 4) Coraza has more matches, all in `ARGS` or `ARGS_NAMES`, and a higher score. The comparison checks this class by its own rule: everything we find, Coraza must find, and what only Coraza finds must be in `ARGS`. On none of the 108 requests did Coraza find a rule that we did not. CRS has a setting for the other behaviour (`tx.enforce_bodyproc_urlencoded`, rule 901350, off by default). It is not implemented. The user decided on 16 October 2026 to keep the body as one text.

**Corrections to the comparison test itself.** It compared only the rules of the files finished earlier; the new files are now included. It also skipped requests whose body has no reader; they are now compared as described above. A rule that counts values (`&REQUEST_HEADERS:Referer`) is named with the `&` by us and without by Coraza; the test now treats the two names as the same.

**Pilot records per level:** unchanged from plan A (normal flagged: 0, 0, 0, 1; anomalous flagged: 80, 98, 100, 102). The four new rule files flag none of the 1,000 records.

**Speed, measured and not yet treated.** With the four new rule files an ordinary request takes about 1.1 to 1.6 ms on one core of the development laptop, against about 0.5 ms after plan A; the request with a 9.4 kB field takes about 49 ms, against about 20 ms. The numbers vary between runs. File 944 tests many patterns against every header, cookie and parameter. This is the subject of plan F.

**Moved from plan B to plan D.** `REQUEST_BODY_LENGTH`, `ARGS_COMBINED_SIZE`, `FILES_COMBINED_SIZE`, `REQBODY_PROCESSOR`, `ctl:ruleRemoveById` and `ctl` in a chain. Only rules of file 920 use them, and their tests are in plan D; writing them now would have left them unverified.

### Plan C — not started

### Plan D — not started

### Plan E — not started

### Plan F — not started
