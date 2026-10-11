# IDS — Current Working Context

Last updated: 11 October 2026  
Product directory: `/home/esip/Documents/ids-system`  
Main architecture reference: [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md)

## 1. What is the project?

A general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. Phase 1 detects SQLi, request-borne XSS, and path traversal attempts and produces alerts. It does not block requests.

Planned product: a Go core, our own SecLang rule engine running CRS 4.30.0 at PL1 in the selected groups, an ML layer, manually defined application profiles, and a decision mechanism that combines them. HTTPS traffic arrives as request copies from an existing reverse proxy. **Of these, only the rule layer exists**, and it works on offline requests. The rest is approved design (M01–M21), not working features.

## 2. What we have made

**The rule layer is complete for the Phase 1 scope.** All 51 PL1 detection rules of CRS files 930 (path traversal and file access), 941 (XSS), and 942 (SQL injection) run from the unmodified CRS files, with the setup, gate, and scoring rules they depend on.

Run it:

```
go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json
go run ./cmd/ids-offline -requests testdata/requests/crs -summary
```

### 2.1. Code

Go module `github.com/EfeSipahi/ids-system`. One dependency: `github.com/corazawaf/libinjection-go`.

| Package | What it does |
| --- | --- |
| `internal/seclang` | Parses CRS rule files into Go values. Six directives are supported; any other is an error |
| `internal/httpmodel` | The common request (M03, M16): received content, parsed view, analysis status (M05). Reads the query, cookies, and form, JSON, multipart, and XML bodies |
| `internal/offline` | Reads example requests from JSON, with optional `expect_ids` / `no_expect_ids` |
| `internal/engine/transform` | 13 transformations. 11 are ports of the ModSecurity v2 functions; `normalizePathWin` and `htmlEntityDecode` follow Coraza (user decision, main plan section 11.15) |
| `internal/engine/operator` | `@rx`, `@pm`, `@pmFromFile`, `@detectSQLi`, `@detectXSS`, `@contains`, `@streq`, `@validateByteRange`, `@eq`, `@lt`, `@ge` |
| `internal/engine` | `Load` prepares a read-only rule set and refuses to start on anything unsupported (M15). `Evaluate` runs phases 1 and 2 for one request with its own state (M21) |
| `internal/result` | Output records: analysis status, findings, score. Request content is left out by default (M11) |
| `cmd/ids-offline` | Command-line tool: `-config`, `-requests` (file or directory), `-summary`, `-json`, `-show-values` |

Other files:

| Path | Content |
| --- | --- |
| `configs/crs-first-engine.json` | Loads seven CRS files; 179 of 186 rules active, 7 excluded with a written reason each (all in file 901) |
| `testdata/requests/` | Example requests: starter file, the 687 converted CRS tests (`crs/`), 1,300 generated variants (`generated/`); see its README |
| `testdata/reference/` | What Coraza found for those requests; see its README |
| `tools/` | Python scripts that generate the test data, and `coraza-reference/`, a separate Go module that runs Coraza. Coraza is not a dependency of the IDS |
| `docs/development-plan-rule-layer.md` | The plan that was followed, with results per stage in its section 8 |
| `docs/crs-4.30.0-ruleset.md` | Reference for the CRS files and our scope |
| `docs/go-learning-plan.md` | The user's Go learning plan |

### 2.2. What was checked (11 October 2026)

1. `go vet ./...`, `go test ./...`, and `go test -race ./...` pass for all eight packages.
2. **Acceptance:** all 687 CRS regression tests of the 51 PL1 rules pass.
3. **Against Coraza v3.8.1:** all 1,993 requests compared, 1,281 of them with a match. Rules, match places, match counts, and scores are identical on 1,989. The other 4 differ in match count for a known reason (invalid UTF-8 in `utf8toUnicode`). The list of known differences is empty.
4. **Transformations:** 11 agree with 10,008 results recorded from the ModSecurity v2 C code; the 2 that follow Coraza agree with 2,517 results recorded from Coraza's Go code.
5. **M21:** attack and normal requests alternate against one rule set, in sequence and in eight goroutines, without affecting each other.
6. **M11:** the default text and JSON output contain none of the payloads of the example file.
7. **Fuzzing** of the whole rule layer, the transformations, and the body parsers found no crash.

### 2.3. Two measurements, and what they do not show

1. **Pilot records:** of the 1,000 CSIC records of the ML pilot, 0 of 500 normal and 80 of 500 anomalous were flagged. This is not a false-positive rate or a detection rate for real traffic: the data is old and synthetic, and "anomalous" there includes many requests outside our three attack types.
2. **Speed** on the development laptop: 0.4 to 0.7 ms per ordinary request on one core; 18.5 ms for a request with a 9.4 kB field. A long value is slow because more than 90 patterns each read it. Measured, not optimised.

### 2.4. What it does not do

1. It reads requests from files only. There is no proxy integration.
2. There is no ML layer, profile layer, decision mechanism, or stored record. A finding of the rule layer is not an alert decision.
3. Only PL1 in three rule files. No other CRS group; see section 3.1 for what the others need.
4. `text/plain` bodies are not read (M17 lists them); they are reported as not inspected.
5. Passing the CRS tests is not full CRS compatibility, and no request has been run through ModSecurity itself.

### 2.5. Other facts

- The Python Random Forest pilot is in the separate [ids-model](../ids-model/) directory and is not integrated. Its test set has already been observed.
- Go version last verified: `go version go1.26.8-X:nodwarf5 linux/amd64`.
- Git: `main` holds the first engine (two rules) and is pushed. The whole rule layer, including the change of two transformations to Coraza's behaviour, is committed on the local branch `rule-layer`. It is **not merged into `main` and not pushed**; the user has not asked for that yet.

## 3. What we are going to do

### 3.1. Next step the user named: support all CRS detection rules

On 11 October 2026 the user said the next step is to support all detection rules, and asked for a survey first. The survey was made by loading every CRS 4.30.0 rule file into the engine. **Its three decisions are not made yet, and no plan document is written.**

| Part | Rules | Detection rules | Cannot load today | CRS tests |
| --- | --- | --- | --- | --- |
| Request files (901–949) | 459 | 286 | 91 | 5,070 |
| Response files (950–980) | 168 | 59 | 160 | 105 |
| Total | 627 | 345 | 251 | 5,175 |

What the request side lacks:

| Kind | Missing (rules affected) |
| --- | --- |
| Variables | `REQUEST_BODY` (18), `REQUEST_METHOD` (8), `REQUEST_LINE` (7), `MULTIPART_PART_HEADERS` (6), `REQUEST_HEADERS_NAMES` (3), `REQUEST_URI` (3), `REQBODY_PROCESSOR` (3), `ARGS_GET` (2), `REMOTE_ADDR` (2), `REQUEST_PROTOCOL` (2), six others (1 each) |
| Operators | `@gt` (16), `@within` (9), `@endsWith` (6), `@ipMatch` (2), `@beginsWith`, `@unconditionalMatch`, `@validateUrlEncoding`, `@validateUtf8Encoding` (1 each) |
| Transformations | `normalizePath` (8), `escapeSeqDecode` (7), `base64Decode` (3), `length` (3) |
| Engine | Macros inside a `setvar` name (6), regex selectors on `TX` (6), `ctl` on chained rules and `ctl:ruleRemoveById` (4), macros for request values (4) |

No regex pattern in any file failed to compile in Go. A rule that loads is not thereby correct: the PL2–PL4 rules of files 913, 930, 941, and 942 load but have never been run or tested. All 160 response rules need the response status, headers, and body (phases 3 to 5), which means a copy of each response as input.

**Decisions the user has to make before a plan is written** (the assistant's recommendation in brackets; none is approved):

| # | Decision | Touches |
| --- | --- | --- |
| 1 | Response rules now or later [later, together with the proxy question] | M17, A01 |
| 2 | Extend the attack groups from SQLi, XSS, and path traversal to all request groups [yes] | M19 |
| 3 | Paranoia levels: support and test all four, with a configuration option, PL1 as default [yes] | M20 |

Proposed order if the user agrees: (1) paranoia-level option and the PL2–PL4 tests of 913, 930, 941, 942; (2) the small variables and operators, for 911, 920, 921; (3) `REQUEST_BODY` and the four transformations, for 931–934, 943, 944; (4) multipart part headers and the engine items, for 922 and the rest of 920; (5) comparison with Coraza and the normal-traffic check again. Acceptance target: all 5,070 request-side CRS tests.

### 3.2. Other open points

| # | Point | Why it matters |
| --- | --- | --- |
| 1 | Merge `rule-layer` into `main` and push | Waiting for the user to ask |
| 2 | One Coraza behaviour to keep or drop | `normalizePathWin` cuts the last path segment at a colon, as Coraza does, so `ab: boot.ini` becomes `ab`. This could hide a file name from rules 930120 and 930130. The user was told and has not decided |
| 3 | Speed on long values | 18.5 ms for 9.4 kB. Two candidate improvements are named in the rule-layer plan, section 8.7 |
| 4 | User review | The user has not read the code. Reading order: [docs/go-learning-plan.md](docs/go-learning-plan.md), then `internal/engine/transaction.go` |

### 3.3. Later layers: not chosen

| Candidate | Opens |
| --- | --- |
| Live request copies from a reverse proxy | A01 (which proxy, how copies are transferred), A08 |
| Go feature extractor and the ONNX model | A10, A05, A07 |
| Application profiles | A04 |
| Decision mechanism and stored records | A06, A09 |

Do not start one without the user choosing it and making its decisions.

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
3. Working mode for code: small packages with tests and an explanation of each. For the rule-layer plan the user asked for all decisions first and then the stages in a row; that plan is finished, so return to one step at a time with a pause for review unless told otherwise. The user knows Python and finished a Go course.
4. Check behaviour against a source before writing it down. Expected values in tests must come from the rule files, a reference implementation, or an independent count, not from a guess. Several times in this project a guessed value or a remembered behaviour was wrong and only a reference caught it.
5. Approved Go dependencies may be downloaded by the assistant. Propose a new dependency first.
6. Do not commit unless the user asks.
7. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
8. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
