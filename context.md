# IDS — Current Working Context

Last updated: 12 October 2026  
Product directory: `/home/esip/Documents/ids-system`  
Main architecture reference: [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md)

## 1. What is the project?

A general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. Phase 1 started with SQLi, request-borne XSS, and path traversal; since 12 October 2026 the rule part is being extended to all request rules of CRS (decision K6). It produces alerts and does not block requests.

Planned product: a Go core, our own SecLang rule engine running CRS 4.30.0 at a configurable paranoia level, an ML layer, manually defined application profiles, and a decision mechanism that combines them. HTTPS traffic arrives as request copies from an existing reverse proxy. **Of these, only the rule layer exists**, and it works on offline requests. The rest is approved design (M01–M21), not working features.

## 2. What we have made

**The rule layer runs four CRS rule files at all four paranoia levels:** 913 (scanner detection), 930 (path traversal and file access), 941 (XSS), and 942 (SQL injection), 100 detection rules in all, from the unmodified CRS files, with the setup, gate, and scoring rules they depend on. The other twelve request rule files are the work in progress; see section 3.

Run it:

```
go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json
go run ./cmd/ids-offline -requests testdata/requests/crs -summary -paranoia-level 4
```

### 2.1. Code

Go module `github.com/EfeSipahi/ids-system`. One dependency: `github.com/corazawaf/libinjection-go`.

| Package | What it does |
| --- | --- |
| `internal/seclang` | Parses CRS rule files into Go values. Six directives are supported; any other is an error |
| `internal/httpmodel` | The common request (M03, M16): received content, parsed view, analysis status (M05). Reads the query, cookies, and form, JSON, multipart, and XML bodies |
| `internal/offline` | Reads example requests from JSON, with optional `expect_ids` / `no_expect_ids` |
| `internal/engine/transform` | 13 transformations. 11 are ports of the ModSecurity v2 functions; `normalizePathWin` and `htmlEntityDecode` follow Coraza (user decision, main plan section 11.15); `normalizePathWin` leaves out Coraza's cut at a colon, which could hide a file name |
| `internal/engine/operator` | `@rx`, `@pm`, `@pmFromFile`, `@detectSQLi`, `@detectXSS`, `@contains`, `@streq`, `@validateByteRange`, `@eq`, `@lt`, `@ge` |
| `internal/engine` | `Load` prepares a read-only rule set and refuses to start on anything unsupported (M15). `Evaluate` runs phases 1 and 2 for one request with its own state (M21) |
| `internal/result` | Output records: analysis status, findings, score. Request content is left out by default (M11) |
| `cmd/ids-offline` | Command-line tool: `-config`, `-requests` (file or directory), `-summary`, `-json`, `-show-values`, `-paranoia-level` |

Other files:

| Path | Content |
| --- | --- |
| `configs/crs-first-engine.json` | Loads eight CRS files; 188 of 195 rules active, 7 excluded with a written reason each (all in file 901). Optional `paranoia_level`, 1 to 4, default 1 |
| `testdata/requests/` | Example requests: starter file, the 1,388 converted CRS tests of the finished rule files (`crs/`), the 3,685 of the others (`crs-pending/`), 1,300 generated variants (`generated/`); see its README |
| `testdata/reference/` | What Coraza found for those requests; see its README |
| `tools/` | Python scripts that generate the test data, and `coraza-reference/`, a separate Go module that runs Coraza. Coraza is not a dependency of the IDS |
| `docs/development-plan-all-request-rules.md` | **The plan in progress:** six plans, A to F, with results after each |
| `docs/development-plan-rule-layer.md` | The earlier plan (finished 11 October), with results per stage in its section 8 |
| `docs/crs-4.30.0-ruleset.md` | Reference for the CRS files and our scope |
| `docs/go-learning-plan.md` | The user's Go learning plan |

### 2.2. What was checked (12 October 2026)

1. `go vet ./...`, `go test ./...`, and `go test -race ./...` pass for all eight packages.
2. **CRS regression tests:** all 1,388 tests of files 913, 930, 941, and 942 pass at paranoia level 4, the level the CRS project runs them at. At levels 1 to 3 a test passes when its rule belongs to the level, and a rule above the level never matches.
3. **Against Coraza v3.8.1:** 2,694 requests compared at level 1 (1,423 with a match) and at level 4 (2,154 with a match). Rules, match places, match counts, and scores are identical, except that 4 requests with invalid UTF-8 differ in match count for a known reason (`utf8toUnicode`). The reference is produced with Coraza's build option `coraza.rule.no_regex_multiline`; see `testdata/reference/README.md` for why.
4. **Transformations:** 11 agree with 10,008 results recorded from the ModSecurity v2 C code; the 2 that follow Coraza agree with 2,517 results recorded from Coraza's Go code.
5. **M21:** attack and normal requests alternate against one rule set, in sequence and in eight goroutines, without affecting each other.
6. **M11:** the default text and JSON output contain none of the payloads of the example file.
7. **Fuzzing** (11 October) of the whole rule layer, the transformations, and the body parsers found no crash.

### 2.3. Two measurements, and what they do not show

1. **Pilot records:** of the 1,000 CSIC records of the ML pilot, 0 of 500 normal and 80 of 500 anomalous were flagged at level 1; at level 4, 1 normal and 102 anomalous. This is not a false-positive rate or a detection rate for real traffic: the data is old and synthetic, and "anomalous" there includes many requests outside our three attack types.
2. **Speed** on the development laptop: 0.4 to 0.7 ms per ordinary request on one core; 18.5 ms for a request with a 9.4 kB field. A long value is slow because more than 90 patterns each read it. Measured, not optimised.

### 2.4. What it does not do

1. It reads requests from files only. There is no proxy integration.
2. There is no ML layer, profile layer, decision mechanism, or stored record. A finding of the rule layer is not an alert decision.
3. Four of the sixteen request rule files with detection rules or tests. The others are planned; see section 3.1. No response rules.
4. `text/plain` bodies are not read (M17 lists them); they are reported as not inspected.
5. Passing the CRS tests is not full CRS compatibility, and no request has been run through ModSecurity itself.

### 2.5. Other facts

- The Python Random Forest pilot is in the separate [ids-model](../ids-model/) directory and is not integrated. Its test set has already been observed.
- Go version last verified: `go version go1.26.8-X:nodwarf5 linux/amd64`.
- Git: everything up to and including plan A is on `main` and pushed to GitHub (12 October 2026). The local branches `rule-layer` and `first-offline-engine` point to commits that are on `main` and can be deleted.

## 3. What we are going to do

### 3.1. In progress: all CRS request rules, all paranoia levels

On 12 October 2026 the user decided to finish the rule part before any other layer (decisions K1–K11, main plan section 11.16). The work follows [docs/development-plan-all-request-rules.md](docs/development-plan-all-request-rules.md). **The user wants one plan at a time: do it, report, stop.**

| Plan | Content | Tests to pass | Status |
| --- | --- | --- | --- |
| A | Paranoia levels, test base, files 913, 930, 941, 942 | 1,388 | **Done 12 October 2026** |
| B | Request variables, small operators, engine items; files 911, 931, 943, 944 | 1,273 | Next; not started |
| C | `normalizePath`, `escapeSeqDecode`, `base64Decode`; files 932, 933, 934 | 1,818 | Not started |
| D | Protocol rules; files 920, 921, 905, and the tests of 901 and 949 | 547 | Not started |
| E | Multipart rules; file 922 | 47 | Not started |
| F | Checks on the whole set: Coraza, normal traffic, speed, documents | all 5,073 | Not started |

Do not start plan B before the user says so.

Response rules (CRS files 950–980) are not part of this; they wait for the proxy decision (K8).

### 3.2. Other open points

| # | Point | Why it matters |
| --- | --- | --- |
| 1 | Speed on long values | 18.5 ms for 9.4 kB. Two candidate improvements are named in the rule-layer plan, section 8.7 |
| 2 | User review | The user has not read the code. Reading order: [docs/go-learning-plan.md](docs/go-learning-plan.md), then `internal/engine/transaction.go` |

### 3.3. After the rule part (order decided by the user, 12 October 2026)

1. Records and alerts (A09).
2. Hand-written application profiles (A04).
3. Proxy and TLS (A01, A08), then response rules.
4. Transfer of the ML model, which the user improves in the separate project, and the decision mechanism (A10, A05, A07, A06).
5. Prevention, learned profiles, other protocols.

Each still needs its own decisions before work starts.

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
3. Working mode for code: small packages with tests and an explanation of each. For the current plan the user wants one plan (A to F) at a time, with a report and a stop after each. The user knows Python and finished a Go course.
4. Check behaviour against a source before writing it down. Expected values in tests must come from the rule files, a reference implementation, or an independent count, not from a guess. Several times in this project a guessed value or a remembered behaviour was wrong and only a reference caught it.
5. Approved Go dependencies may be downloaded by the assistant. Propose a new dependency first.
6. Do not commit unless the user asks.
7. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
8. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
