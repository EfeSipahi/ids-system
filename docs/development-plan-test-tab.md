# Development plan: a request test tab in the dashboard

Decided by the user on 19 November 2026, decisions S1–S4 (main plan section 11.29). This document is the plan of the work and its progress.

## Context

1. Why. The user wants to see how the rules behave on requests they write themselves, before the dashboard gets alert marking and users (the next step they chose). Until now a request can only be analysed from a file (`ids-offline`) or as live traffic through Caddy (`ids-live`).
2. Others offer the same kind of tool, for checking rules and finding false positives:
   - the CRS project's public sandbox answers a request with the matched rule IDs and the score, at a paranoia level chosen with a header; its policy says submitted requests may be kept by the CRS team ([coreruleset.org](https://coreruleset.org/docs/6-development/6-4-using-the-crs-sandbox/));
   - Coraza lists a Playground, a web page for testing rules ([README](https://github.com/corazawaf/coraza));
   - Cloudflare's Trace simulates a request through the configured rules without sending traffic ([Trace](https://developers.cloudflare.com/rules/trace-request/)); its Rules simulator page is for administrators only ([simulator](https://developers.cloudflare.com/rules/simulator/)).
3. Decided by the user (19 November 2026):

   | # | Decision |
   | --- | --- |
   | S1 | The dashboard runs the analysis itself, with the same engine and profiles as `ids-offline` and `ids-live`. Nothing goes through Caddy, and nothing else needs to run |
   | S2 | A list of configuration files in `dashboard.json`, chosen from a menu on the tab; the first is the default. The tab shows each one's fingerprint and whether it is the newest run's |
   | S3 | The request is written as raw HTTP text: the request line, the headers, an empty line, the body |
   | S4 | Examples: a short built-in list, and a picker of CRS's own test requests by rule, read from a folder named in `dashboard.json` |

4. Consequences, found while reading the code; they are approved with this plan:
   1. C1: the dashboard gets its first request that computes something. It still changes nothing: no record is written, no setting changes, and the test request is kept nowhere. V2 ("nothing in it changes a record or a setting") stays true; the package comment says so.
   2. C2: the dashboard loads rule sets. One keeps 13.4 MB and takes 217 ms to build (measured for the profile plan, its context item 4). A configuration is loaded when it is first used and kept; it is loaded again when its fingerprint changes (the configuration file, a rule file it loads, or a profile). At most 4 rule sets are kept; the least recently used one is dropped. A configuration that can't be loaded shows its error on the tab.
   3. C3: limits. The request text is at most 1 MiB (the largest example request in the repository is 66 KB); a larger one is refused before it is read. At most 2 tests run at the same time; a third waits for one to finish. Go's regular expressions can't take exponential time, but a long value is slow (19 ms for 9.4 kB, `context.md` 2.3); the time of a 1 MiB request is measured and reported.
   4. C4: the request is never sent anywhere, so the tab can't be used to reach other machines. The CRS picker reads only the files its listing shows, by name, from the folder in `dashboard.json`.
   5. C5: matched values are shown. The text is the user's own and nothing is stored, so the masking of records (R4) is not needed; values are put into the page as text only, never as HTML, as everywhere in the dashboard.
   6. C6: the built-in example "a body over the size limit" can't be written: the limit is 12.5 MB, the tab's 1 MiB. It is replaced by a request whose `Content-Length` disagrees with its body, which the protocol rules (920) look for.

## Design

### Raw HTTP text: `internal/offline` (`raw.go`, new)

1. `ParseRaw(text) (httpmodel.Received, error)` reads:
   - the request line: method, target and version, split at single spaces. A line with no version is HTTP/0.9, as in the offline files. Anything else (an empty line, more than three parts) is an error naming the line.
   - the headers, one per line, `Name: value`, until the first empty line. The value loses the spaces and tabs around it, as HTTP servers do (RFC 9112, section 5). A line without a colon, or a name with a space, is an error with its line number.
   - the body: every byte after the empty line, unchanged.
   Lines in the request line and headers may end with `\r\n` or `\n`, since a browser's text box gives `\n`.
2. `Raw(httpmodel.Received) (string, bool)` writes a request as that text, for the examples. It says false when the text can't hold the request exactly: a line break inside a header, or a body that is not UTF-8 text (one CRS test, 944200, has one in `body_base64`).
3. `Content-Length` is never changed. When it disagrees with the body, the tab says so and offers a button that sets it.

### Analysis: `internal/dashboard/tester.go` (new)

1. For each configuration of the list: its name (the file's base name), and, when loaded, its paranoia level, its applications, its fingerprint, and whether that fingerprint is the newest run's (the `start` record's `engine.config`).
2. A test takes the configuration, an optional paranoia level (1–4, in place of the configuration's, as `ids-offline -paranoia-level`), an optional application (as `ids-offline -application`; otherwise by Host and path, F3), and the text.
3. It runs what `ids-offline` runs for one request: the application, `EvaluateWith` with its exceptions and level, the profile check, and the result with values (`result.NewRecord` with `ShowValues`, `NewApplication`, `NewProfile`, `AlertBy`). The steps are moved into one function that `ids-offline`, `ids-live` and the tab all call, so the three can't drift apart.
4. The answer: alert or not and why (`alert_by`); the score with its threshold and categories; each finding (rule, severity, message, location, matched value, data); the profile's findings; the analysis status (body format, inspected or partly, issues); what the engine read (path, query and body parameters, cookies, body format); the time the analysis took. For a CRS test, also which expected rules matched and which did not.

### API and page: `internal/dashboard`

1. `GET /api/test`: the configurations, the built-in examples, and the CRS test files (rule ID and number of tests).
2. `GET /api/test/crs/{file}`: the tests of one file, each as raw text with its name and expected rules, or marked as not writable as text.
3. `POST /api/test`: runs a test. JSON in (configuration, level, application, text), JSON out. Behind the login and Go's cross-origin protection, as every route.
4. The page `/test`, a "Test" tab after "Engine": the text box, menus for the configuration, level and application, the examples menu and the CRS picker, a Run button (also Ctrl+Enter), and the result in cards, in the Carbon look. Without `test_configs` in `dashboard.json` the tab says how to enable it.

### Settings: `dashboard.json`

```json
"test_configs": ["configs/crs-first-engine.json", "configs/csic-shop.json", "testdata/crs-tests.json"],
"test_requests_dir": "testdata/requests/crs"
```

Both optional; relative paths start at the dashboard configuration's folder. `testdata/crs-tests.json` is the configuration the CRS tests are written for (level 4, CRS's test setup), so its expectations hold with it. The repository's `configs/dashboard.json` gets these three.

## Stages

Each stage ends with its tests passing and a note in the progress section.

1. Decision documents: this file, the main plan (section 1, history 11.29), `context.md`.
2. Raw text: `ParseRaw` and `Raw`, with tests (line ends, HTTP/0.9, repeated headers, an empty body, a body with line breaks, each error with its line), a fuzz test, and the round trip below (verification 2).
3. Shared analysis and the tester: the one function for the three programs; configurations, loading and the cache; limits; the answer. `ids-offline`'s output and the live tests must stay the same.
4. API and page, the examples and the CRS picker; one batched browser round.
5. Close: documents (`context.md`, the main plan, `docs/project-history.md`, the dashboard UI plan), the full checks. The commit only when the user asks.

## Rules for the work

1. Expected values come from the data, the CRS tests or `ids-offline`, never guessed.
2. No new dependency.
3. The dashboard writes nothing because of a test: no record, no log line with request content.
4. Browser checks: one batched call per round.
5. Check runs pass `-records` with a temporary folder; `records/` is the user's own.
6. No commit unless the user asks; `proje_oneri_formu.docx` is never committed.

## Verification

1. `gofmt -l .`, `go vet ./...`, `go test ./...`; `go test -race` for `internal/dashboard`, `internal/offline`, `internal/live`, `cmd/...`.
2. Round trip: every request of `testdata/requests` (6,391) written with `Raw` and read with `ParseRaw` gives the same `Received`, except those `Raw` reports as not writable, which are counted and listed.
3. Same results as `ids-offline`: the tab's answers equal `ids-offline -json -show-values` (findings, matched values, score, profile findings, analysis) for the 5,072 CRS tests with `testdata/crs-tests.json`, where every expectation is met, and for the 1,000 CSIC requests with `configs/csic-shop.json`.
4. Unchanged numbers: CRS 2,916 of 5,072 flagged at level 1; CSIC 96 of 500 and 176 of 500; the CSIC profile's validation and test numbers.
5. Limits and safety: 1 MiB accepted and 1 MiB + 1 byte refused; a third test waits; no login gives 401; a cross-origin POST is refused; a CRS file name outside the listing is refused; the records folder is unchanged after tests; a matched `<script>` value shows as text. The time of the slowest 1 MiB request is reported.
6. Fuzz: `ParseRaw` (no panic; what it accepts, `Raw` writes back the same).
7. Browser: the tab in light and dark, every built-in example, a CRS test with its expectations, an error in the text, a configuration that can't be loaded; no console errors and nothing wider than its space.

## Progress

| Stage | Status |
| --- | --- |
| 1. Decision documents | Done 19 November 2026 |
| 2. Raw text | Done 19 November 2026 |
| 3. Shared analysis and tester | Done 19 November 2026 |
| 4. API and page | Done 19 November 2026 |
| 5. Close | Done 19 November 2026 |

### Notes from the work

1. Stage 1: this document, the main plan (section 1 and history 11.29) and `context.md`, 19 November 2026.
2. Stage 2: raw text, 19 November 2026 (`internal/offline/raw.go`).
   1. Changes to the design above, made while writing it:
      - A browser's text box gives every line end as `\n`, also one written as `\r\n` (the HTML standard normalizes a text box's value). A multipart body needs `\r\n`, so the line ends of the body travel apart from the text: `ParseRaw(text, bodyCRLF)` turns each `\n` of the body into `\r\n` when `bodyCRLF` is true, and `Raw` gives the text with `\n` and says whether the body's line ends were `\r\n`. The tab will have a switch for it, set by the example it loads.
      - Empty lines before the request line are skipped, as RFC 9112 (section 2.2) allows a server to do.
      - Spaces and tabs around a header value are removed. Go's HTTP server, so Caddy too, does the same: checked with `http.ReadRequest` on `X-Filename: photo.php ` (the value comes out as `photo.php`). So live traffic can't carry them either.
   2. Round trip (verification 2): of the 6,391 example requests in 296 files, 6,384 are written as text and read back the same, 167 of them with `\r\n` body line ends. Seven can't be written as text, and the test names them:
      - six have a header value that starts or ends with a space: CRS 920660-10, 932180-14, 933110-32, 933110-35, 944140-11, and the generated injection variant 247 (cookie);
      - CRS 944200-1 has a body that is not UTF-8 text.
   3. Checks: `gofmt -l .` is empty; `go vet ./...` and `go test ./...` pass; `go test -race ./internal/offline` passes. Tests cover both line ends, HTTP/0.9, empty lines before the request line, repeated headers, spaces around values, an empty value, a colon in a value, bodies with their line ends, the `bodyCRLF` switch, a wrong `Content-Length` left as it is, every error with its line number, and every case `Raw` refuses. `FuzzParseRaw` ran 60 seconds (2.8 million inputs) without a failure: what `ParseRaw` accepts and `Raw` can write comes back the same.
3. Stage 3: the shared analysis and the tester, 19 November 2026.
   1. What was built:
      - `internal/analysis`: `Run`, the one analysis of a request (the rules with the application's exceptions and level, then the profile). `ids-offline`, `ids-live` and the tab call it.
      - `result.Analysed` and `NewAnalysed`: what is said about one analysed request (the record, the application, the profile result, what made it an alert). `ids-offline` prints it inside each request of its output, and the tab answers with it.
      - `internal/dashboard/tester.go`: the configurations of the list, the rule sets kept and prepared again (C2), the two slots (C3), the built-in examples (`web/examples.json`, in the offline file format), the example files, and the answer.
      - `dashboard.json`: `test_configs` and `test_requests_dir`; `configs/dashboard.json` lists `crs-first-engine.json`, `csic-shop.json` and `../testdata/crs-tests.json`, and the CRS tests' folder.
   2. Changes to the design above, made while writing it:
      - C6's replacement example: no CRS 4.30.0 rule compares `Content-Length` with the length of the body (rule 920160 checks that it is a number, 920170 that a GET or HEAD has none, 920180 and 920181 that a POST has one, and not both it and `Transfer-Encoding`), so the example became "a GET request with a body" (920170). The tab still notes a `Content-Length` that disagrees and offers to correct it.
      - A client address field: the 905 examples (Apache's internal requests from 127.0.0.1) and `secrets.json` set `remote_addr`, and raw text has no place for it. It is optional and empty by default, as in an example file without `remote_addr`.
      - The text travels as the body of `POST /api/test` (`text/plain`), with the choices in the address. So the 1 MiB limit is checked before the text is read; inside JSON it could not be.
      - The example files are opened at `/api/test/files/{name}`, as the folder need not hold CRS tests.
   3. Checks:
      - The built-in examples, with `configs/crs-first-engine.json` at level 1, find what their names say: the normal request nothing; the SQL injection 942100, 942190, 942270 and 942360; the XSS five 941 rules; the traversal 930100, 930110, 930120 and 932160; the command injection 930120 and 932160; the JSON body 942100; the PHP upload 933110; the scanner 913100; the HTTP version 920430; the GET with a body 920170. These are the rules `ids-offline` found for `web/examples.json`.
      - `TestTabMatchesOffline` (verification 3, in Go): 5,066 CRS tests with `testdata/crs-tests.json` and 1,318 other example requests with `configs/csic-shop.json`, written as text and tested in the tab, give exactly the analysis of the same requests read from their files; every expectation of the 5,066 CRS tests is met. The 7 requests raw text can't hold (note 2) are left out.
      - `ids-offline`'s output is byte for byte the same as before the shared analysis (a build of `f1bc32f`), run IDs and records folders aside, in 8 runs: the CRS summary at level 1, `-json -show-values` and text of the CRS tests at level 4, the CSIC shop's applications with `-json -show-values`, `-application`, `-summary`, `-show-values` on the generated variants, and `-paranoia-level 2`. The records written are the same too (IDs, times and cookie hashes aside). The live tests, among them `TestLiveMatchesOffline`, pass.
      - Rule sets: prepared once, prepared again after their configuration changed and `recheckAfter` passed, at most 4 kept (levels 1–4 and the configuration's own: the least recently used one dropped); a broken configuration is an error with status 500 and its set is dropped.
      - Errors: a configuration or level out of range, an unknown application, a client address that is not an IP address, text that can't be read (with its line), an empty text, and the tab turned off.
4. Stage 4: the API and the page, 19 November 2026.
   1. What was built: the routes `GET /test`, `GET /api/test`, `GET /api/test/files/{name}` and `POST /api/test`, all behind the login; the "Test" tab after "Engine"; the page in `app.js` (`testPage`) and its styles. The page keeps only its configuration choice in the browser, never the text.
   2. The page: the examples menu; the CRS picker (a rule, then one of its tests, with those raw text can't hold shown and disabled), with a hint and a button to switch to `crs-tests.json` while a CRS test is loaded with another configuration; the text box; the configuration (with "the IDS's rules" when its fingerprint is the newest run's), the level, the application, the client address and the body's line ends; Analyse or Ctrl+Enter; the size against the limit. The answer: the verdict, the CRS test's expectation (with a note when the text was changed after loading), the rule findings with their matched values, the decision, the analysis, the application and profile, what the engine read, and the answer as JSON.
   3. Browser, three rounds with Playwright on a demo dashboard in the scratchpad (its own certificate accepted in the test context only), 1440 px and 1024 px, light and dark:
      - every built-in example ran and found its rules; a CRS test (920100-1) with `crs-first-engine.json` and after "Use crs-tests.json"; a broken request ("line 2: a header is …"); a `Content-Length` of 99 for a 16-byte body, then the button set it to 16; the shop's application chosen with level 3 and level 4; a configuration whose rule file is missing, with its error on the page and on Analyse;
      - nothing was wider than its space; the only console messages were the 400 and the 500 of the two deliberate errors.
      - Fixed after the first round: the verdict said "Alert" twice; the level menu's first choice was cut ("The configuration's ("), now "As configured (1)"; the application card now says when the application keeps its own level (F11). After the second round: the parameters, cookies and files are one table instead of three whose columns did not line up.
5. Stage 5: the close, 19 November 2026.
   1. End to end (verification 3): every request of an example folder was posted to a running dashboard's API and compared with the real `ids-offline` binary's `-json -show-values` output (method, URI, analysis, findings with values, score, application, profile, alert):
      - the 290 CRS test files with `testdata/crs-tests.json`: 5,066 compared, 6 not writable as text, 0 different;
      - the 1,000 CSIC requests with `configs/csic-shop.json`: 1,000 compared, 0 different; and with `configs/crs-first-engine.json`: 1,000 compared, 0 different.
   2. Time of a 1 MiB request (C3), the analysis alone, on this machine:

      | Request of about 1 MiB | Level 1 | Level 4 |
      | --- | --- | --- |
      | one long User-Agent | 0.3 s | 2.1 s |
      | repeated SQL injection in a form value | 1.4 s | 3.9 s |
      | repeated script tags in a form value | 1.7 s | 5.2 s |
      | a long query | 1.8 s | 5.0 s |
      | one form value of `A` | 2.2 s | 6.5 s |
      | words and spaces in a form value | 2.9 s | 8.4 s |
      | many short form fields | 3.0 s | 8.1 s |
      | a JSON body with about 80,000 fields | 3.8 s | 9.8 s |

      So with both slots taken, another test can wait about 10 seconds. The limit stays 1 MiB; the user may lower it.
   3. Checks, all records in a temporary folder:
      - `gofmt -l .` is empty in both modules; `go vet ./...` and `go test ./...` pass in both; `go test -race` passes for `internal/dashboard` (with `TestTabMatchesOffline`), `internal/offline`, `internal/live`, `internal/analysis`, `internal/result` and `cmd/...`. `internal/analysis` got its own test (`TestRun`) at the close.
      - Unchanged numbers: 2,916 of 5,072 CRS tests flagged at level 1; CSIC 96 of 500 normal and 176 of 500 anomalous; with the CSIC profile, validation 5 of 99 and 27 of 98, test 3 of 100 and 30 of 99.
      - `FuzzParseRaw` ran 60 seconds (2.8 million inputs) without a failure (note 2).
      - The repository's `records/` folder was the same, byte for byte, before and after.

