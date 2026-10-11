# IDS — Current Working Context

Last updated: 11 October 2026  
Product directory: `/home/esip/Documents/ids-system`  
Main architecture reference: [ids-system-plan-phaze1.md](ids-system-plan-phaze1.md)

## 1. What is the project?

A general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. Phase 1 detects SQLi, request-borne XSS, and path traversal attempts and produces alerts. It does not block requests.

Planned product: a Go core, our own SecLang rule engine running CRS 4.30.0 at PL1 in the selected groups, an ML layer, manually defined application profiles, and a decision mechanism that combines them. HTTPS traffic arrives as request copies from an existing reverse proxy. Only the part described in section 2 exists; the rest is approved design (M01–M21), not working features.

## 2. What we have made

**The first offline rule engine is complete** (main plan section 7.4, steps 0 to 6). It runs two real CRS detection rules, 930100 and 930110 (path traversal), from the unmodified CRS files, together with the setup, gate, and scoring rules they depend on.

Run it:

```
go run ./cmd/ids-offline -requests testdata/requests/path-traversal.json
```

### 2.1. Code

Go module `github.com/EfeSipahi/ids-system`, standard library only.

| Package | What it does |
| --- | --- |
| `internal/seclang` | Parses CRS rule files into Go values. Five directives are supported; any other is an error |
| `internal/httpmodel` | The common request (M03, M16): received content, parsed view, analysis status (M05). Parses query strings and form-urlencoded bodies |
| `internal/offline` | Reads example requests from JSON, with optional `expect_ids` / `no_expect_ids` |
| `internal/engine/transform` | `utf8toUnicode`, `urlDecodeUni`, `removeNulls`, `cmdLine`, and the `none` reset |
| `internal/engine/operator` | `@rx`, `@eq`, `@lt`, `@ge`, and negation |
| `internal/engine` | `Load` prepares a read-only rule set and refuses to start on anything unsupported (M15). `Evaluate` runs phases 1 and 2 for one request with its own state (M21) |
| `internal/result` | Output records: analysis status, findings, score. Request content is left out by default (M11) |
| `cmd/ids-offline` | Command-line tool: `-config`, `-requests`, `-json`, `-show-values` |

Other files:

| Path | Content |
| --- | --- |
| `configs/crs-first-engine.json` | Loads four CRS files; 65 of 76 rules active, 11 excluded with a written reason each |
| `testdata/requests/` | Example requests, including the 18 CRS regression tests of the two rules; see its README |
| `docs/crs-4.30.0-ruleset.md` | Reference for the CRS files and our scope |
| `docs/go-learning-plan.md` | The user's Go learning plan |

### 2.2. What was checked (11 October 2026)

1. `go vet ./...`, `go test ./...`, and `go test -race ./...` pass for all eight packages.
2. **Acceptance:** of the 18 CRS regression tests for 930100 and 930110, the 14 the engine can inspect give the expected rule IDs. Two normal requests give no finding and score 0.
3. **Transformations** agree with 3,592 results recorded from the ModSecurity v2 C code.
4. **The two rule patterns** agree with Python `re` on 4,708 inputs.
5. **M21:** attack and normal requests alternate against one rule set, in sequence and in eight goroutines, without affecting each other.
6. **M11:** the default text and JSON output contain none of the payloads of the example file.
7. The local CRS copy is identical to the official `v4.30.0` archive.

### 2.3. What it does not do

1. **Only two detection rules run.** No SQLi, no XSS, and not the other three PL1 rules of file 930.
2. **Four of the 18 CRS tests are not detected**, because their payload is in an XML or multipart body, which is not parsed. Those requests are reported as "analysis incomplete", not as clean.
3. **Score values were not compared with a reference engine.** No ModSecurity or Coraza run was made. One difference is expected from reading the ModSecurity source: it would add the score of 930110 more often than we do. Details: main plan section 11.9.
4. No proxy integration, ML layer, profiles, decision mechanism, or persistent records exist.
5. This result is not CRS compatibility and not a detection-quality or performance measurement.

### 2.4. Other facts

- The Python Random Forest pilot is in the separate [ids-model](../ids-model/) directory and is not integrated. Its test set has already been observed.
- Go version last verified: `go version go1.26.8-X:nodwarf5 linux/amd64`.
- Git: the work above is committed on branch `first-offline-engine`. It is not merged into `main` and not pushed.

## 3. What we are going to do

### 3.1. Before more code

1. **User review.** The user has not yet read the code of steps 1 to 6. Reading order: the files listed in [docs/go-learning-plan.md](docs/go-learning-plan.md), then `internal/engine/transaction.go`.
2. **Merge.** Merge `first-offline-engine` into `main` and push, when the user decides.

### 3.2. Next development step: not chosen yet

The user chooses. These are the candidates, in the order the assistant proposes; the order is a proposal, not a decision.

| # | Candidate | Why | Opens which decision |
| --- | --- | --- | --- |
| 1 | Compare with a reference engine | Tells us whether our scores and matches are right before more is built on them | Which engine is the reference (A11) |
| 2 | Multipart and JSON body parsing | Closes 2 of the 4 undetected CRS tests; needed by every later rule group (M17) | Request data contract (A02) |
| 3 | The other PL1 rules of file 930 (`@pmFromFile`, `normalizePathWin`, cookies, `REQUEST_FILENAME`) | Finishes one rule file | Whether these rules are in the path traversal scope (A11) |
| 4 | First XSS and SQLi rules (941, 942) | Reaches the other two Phase 1 attack types | libinjection library for `@detectXSS` / `@detectSQLi` (A11) |

Smaller follow-ups, recorded in main plan section 11.10: the Unicode mapping file for `urlDecodeUni`, XML bodies, and size limits (A08).

### 3.3. Later, after the rule layer is broader

Live request copies from the proxy (A01), the Go feature extractor and ONNX model (A10), application profiles (A04), the decision mechanism (A06), and persistent records (A09). None of these has started.

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
3. Working mode for code: write one small package at a time with tests, explain it, and wait for the user's review before the next step. The user knows Python and is learning Go.
4. Check behaviour against a source before writing it down. Expected values in tests must come from the rule files, a reference implementation, or an independent count, not from a guess.
5. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
6. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
