# Development Plan — Rule Layer for Phase 1

Created: 11 October 2026
Status: approved by the user on 11 October 2026, with all decisions made (section 3). Progress is in section 8.
Related: [main plan](../ids-system-plan-phaze1.md) (M15, M17–M21, A02, A07, A08, A11), [context](../context.md), [CRS reference](crs-4.30.0-ruleset.md)

## 1. Goal

Take the engine from two detection rules to the full approved rule scope of Phase 1 (M19, M20): every PL1 rule for path traversal, SQL injection, and XSS in CRS 4.30.0.

| | Today | Target of this plan |
| --- | --- | --- |
| PL1 detection rules running | 2 (930100, 930110) | 51 (5 in file 930, 20 in 942, 26 in 941) |
| Attack types | Path traversal | Path traversal, SQLi, XSS |
| Body formats read | Form-urlencoded | Form-urlencoded, JSON, multipart |
| CRS regression tests available for these rules | 18 used, 14 pass | 687 |

Outside this plan: the proxy, the ML layer, profiles, the decision mechanism, stored records, and PL2–PL4. They follow after the rule layer.

## 2. What the remaining rules need

Counted from the rule files on 11 October 2026 with a script; "new" means not in the engine today.

| | File 930 (3 rules left) | File 942, SQLi (20 rules) | File 941, XSS (26 rules) |
| --- | --- | --- | --- |
| New operators | `@pmFromFile` | `@detectSQLi` | `@detectXSS`, `@pm` |
| New transformations | `normalizePathWin` | `replaceComments`, `removeCommentsChar`, `removeWhitespace` | `htmlEntityDecode`, `jsDecode`, `cssDecode`, `lowercase`, `compressWhitespace`, `removeWhitespace` |
| New variables | `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `ARGS_NAMES`, `REQUEST_FILENAME` | The same four | The same four, and `MATCHED_VARS` |
| Chained rules | 0 | 0 | 1 (941310) |
| Data files | `lfi-os-files.data`, `restricted-files.data`, `ai-critical-artifacts.data` | none | none |

Shared by 941 and 942: file `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf` has 53 `SecRuleUpdateTargetById` lines for these two groups. They remove known harmless cookies (for example Google Analytics) from the rules' targets, using regular-expression selectors. The parser rejects that directive today.

Two facts checked for this plan:

1. **All regular expressions compile.** Every `@rx` pattern in files 930, 941, and 942 (93 patterns, all paranoia levels, the longest 4,594 characters) compiles with Go's `regexp`. No pattern needs a feature Go lacks.
2. **Five patterns in file 942 name bytes above 0x7F.** Go reads values as UTF-8 text, ModSecurity as bytes, so these five need a decision on how to match (stage 6).

How the 687 regression tests of the PL1 rules carry their payload:

| Payload location | Tests | Readable today |
| --- | --- | --- |
| URI, query, or headers (no body) | 296 | Yes |
| Form-urlencoded body | 324 | Yes |
| XML body | 49 | No |
| JSON body | 15 | No |
| Multipart body | 3 | No |
| Among the above, tests with a `Cookie` header | 14 | Header only; no cookie variables |

## 3. Decisions

All were made by the user on 11 October 2026.

| # | Decision | Chosen |
| --- | --- | --- |
| D1 | Reference engine for comparing results (A11) | Coraza, run by a separate helper module that writes a reference file |
| D2 | Library for `@detectSQLi` and `@detectXSS` (A11) | The Go port `github.com/corazawaf/libinjection-go`; first dependency of the IDS module |
| D3 | XML bodies | M17 amended: read text and attribute values of XML bodies in Phase 1 |
| D4 | Scope of 930120, 930130, 930140 | In scope |
| D5 | Who writes the code | The assistant; the user reviews afterwards |
| D6 | Test converter | Python script in `tools/` |
| — | Rhythm | Stages 3 to 8 in a row, a report after each; stop only for a new decision or a result that looks wrong |

## 4. Stages

Sizes are relative: S is about one package like `operator`, M about two, L about the size of the whole `engine` package.

### Stage 1 — Test harness (S)

**Why first:** every later stage is accepted by CRS regression tests, and today they are converted by hand.

1. `tools/convert_crs_tests.py`: converts the YAML tests of chosen rule IDs to our JSON format, reproducing what the CRS test runner does to a request (default `Content-Type`, the `autocomplete_headers` switch).
2. Convert the tests of all 51 PL1 rules into `testdata/requests/`.
3. `ids-offline -summary`: one line per rule with tests passed, failed, and not inspected.

**Done when:** one command prints the pass counts for all 51 rules. Most will fail at this point; that table is the baseline every later stage improves.

### Stage 2 — Reference comparison (S to M)

**Needs D1.**

1. A test that runs the same requests through our engine and the reference engine with the same four rule files, and compares matched rule IDs and anomaly scores.
2. Explain every difference: fix ours, or record it as a known difference with its reason.

**Done when:** for 930100 and 930110 on all converted requests, matched IDs agree with the reference, and each score difference is explained in the main plan. This settles the open point in section 11.9 of the main plan (the `multiMatch` score).

### Stage 3 — Request variables and target updates (M)

1. `httpmodel`: parse the `Cookie` header into names and values; expose the path without the query string.
2. `engine`: variables `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `ARGS_NAMES`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `MATCHED_VARS`.
3. Regular-expression selectors such as `REQUEST_COOKIES:/^_ga/`.
4. `seclang` and `engine`: `SecRuleUpdateTargetById`, so file 999 can be loaded.

**Done when:** file 999 loads without an exclusion; unit tests cover each variable; the 14 cookie tests reach the right variables.

### Stage 4 — Finish file 930 (S)

**Needs D4.**

1. `@pm` and `@pmFromFile`: match any phrase of a list. Data files are read once at load time (M21). A missing data file is a startup error.
2. `normalizePathWin`.
3. Remove 930120, 930130, 930140 from the exclusion list.

**Done when:** all 5 PL1 rules of file 930 are active and their tests without XML or multipart bodies pass (67 of 72); the other 5 follow in stage 5.

### Stage 5 — JSON and multipart bodies (M to L)

**Opens A02 (how parsed bodies are represented).** XML was added to this stage by decision D3.

1. JSON: every value, including nested objects and arrays, becomes an argument with a path name; repeated keys are kept (M16, M17).
2. Multipart: text fields become arguments; file names and field names become `FILES` and `FILES_NAMES`; file contents are not read (M17).
3. Malformed bodies: keep what was received, report "not inspected" with the reason (M05).
4. XML: all text nodes become `XML:/*` values and all attribute values become `XML://@*` values. No XPath engine, no DTD processing.
5. A first body-size limit (A08), reported when hit.

**Done when:** the 15 JSON, 3 multipart, and 49 XML tests are inspected; a malformed body never produces a clean-looking result; fuzzing each parser finds no crash.

### Stage 6 — SQL injection, file 942 (L)

**Needs D2.**

1. Transformations `replaceComments`, `removeCommentsChar`, `removeWhitespace`, each checked against results recorded from ModSecurity, as in step 3 of the first engine.
2. `@detectSQLi`.
3. The five patterns with bytes above 0x7F: decide how to match them and test the decision against the reference.
4. Activate the 20 PL1 rules.

**Done when:** all 20 rules are active; their tests pass; results agree with the reference engine or the differences are recorded.

### Stage 7 — XSS, file 941 (L)

1. Transformations `htmlEntityDecode`, `jsDecode`, `cssDecode`, `lowercase`, `compressWhitespace`, each checked against recorded reference results.
2. `@detectXSS`.
3. The chained rule 941310 with `MATCHED_VARS`.
4. Activate the 26 PL1 rules.

**Done when:** all 26 rules are active; their tests pass; results agree with the reference or the differences are recorded.

### Stage 8 — Check on normal traffic and speed (M)

**Opens A07 and A08; needs a discussion before it starts.**

1. Run the normal records of the CSIC pilot data (in `ids-model`) through the engine and count how many get a finding. This is a first look at false positives of the rule layer, on old synthetic data; it is not a product-quality result.
2. Benchmarks: time per request and memory per request for the full rule set.
3. Fuzz the whole pipeline with random requests.

**Done when:** the false-positive count and the per-request time are written down with their limits, and no input crashes the engine.

## 5. Order and reasons

| Order | Stage | Reason for the position |
| --- | --- | --- |
| 1 | Test harness | Everything after it is measured with it |
| 2 | Reference comparison | Finds wrong foundations while only two rules depend on them |
| 3 | Variables and target updates | Every one of the 49 remaining rules needs these |
| 4 | Finish file 930 | Small, and completes one file |
| 5 | JSON and multipart | Before the large rule groups, so their tests are judged on full coverage |
| 6 | SQLi | Fewer new transformations than XSS (3 against 5) |
| 7 | XSS | Largest set of new transformations |
| 8 | Normal traffic and speed | Needs the whole rule set to mean anything |

Stages 4 and 5 can swap. Stages 6 and 7 can swap.

## 6. Rules that apply to every stage

These come from the first engine and from the main plan.

1. **One stage at a time**, with tests, an explanation, and the user's review before the next.
2. **Behaviour is read from a source**: the rule files, the ModSecurity source, or a reference run. Expected values in tests are never guessed.
3. **Nothing is skipped silently** (M15): a rule is active and fully supported, or excluded with a written reason.
4. **Uninspected content is reported** (M05), never shown as clean.
5. **No request content in output by default** (M11).
6. **Rule files stay unmodified** (M18, M19).
7. **Each new dependency is discussed first**; the user installs it.
8. After each stage: update `context.md` and the status in the main plan.

## 7. What this plan does not promise

1. Passing CRS regression tests means the engine behaves as CRS expects on those examples. It is not full CRS compatibility and not a measurement of detection quality on real traffic.
2. Sizes are estimates. Stage 2 may uncover differences that change later stages.

## 8. Progress

### 8.1. Stage 1 — done on 11 October 2026

1. `tools/convert_crs_tests.py` converts the CRS YAML tests of the PL1 rules of chosen rule files. It applies the request completion steps of go-ftw, read from its source (`ftwhttp/request.go`), and stops on any test field it does not know.
2. `testdata/requests/crs/` holds the result: 51 files, one per rule, 687 tests. The two hand-converted files of the first engine were removed.
3. `ids-offline` accepts a directory for `-requests` and has a `-summary` option: one line per file with tests, passed, failed, and not inspected, and whether the rule is active, excluded, or not loaded.
4. Tests pin what must always hold: 51 files and 687 tests; the counts of each file add up; **an active rule has no failed test on a fully inspected request**.

**Baseline**, from `go run ./cmd/ids-offline -requests testdata/requests/crs -summary`:

| | Rules | Tests | Passed | Failed | Not inspected |
| --- | --- | --- | --- | --- | --- |
| Active (930100, 930110) | 2 | 18 | 14 | 0 | 4 |
| Excluded (930120, 930130, 930140) | 3 | 54 | 11 | 42 | 1 |
| Not loaded (941, 942) | 46 | 615 | 105 | 453 | 57 |
| **Total** | 51 | 687 | 130 | 495 | 62 |

How to read it: "passed" for a rule that is not active consists of tests that expect the rule *not* to match, which is trivially true while the rule does not run. "Not inspected" counts tests whose expectation was not met and whose body is XML, JSON, or multipart. The number that matters for progress is "failed", which should reach 0 for each rule as it is activated.

**Not checked:** the converter was not compared with a real go-ftw run. Its steps were written from the go-ftw source.

### 8.2. Stage 2 — done on 11 October 2026

1. **D1 decided by the user:** the reference engine is Coraza, used through a separate helper so the IDS module gets no dependency.
2. `tools/coraza-reference/` is its own Go module requiring Coraza v3.8.1. It loads the same four rule files in detection-only mode, removes the four excluded detection rules, runs example requests, and writes `testdata/reference/coraza-first-engine.json`. The user approved downloading the dependency.
3. `tools/generate_traversal_variants.py` writes 400 path traversal variants (`testdata/requests/generated/`). The CRS tests alone have too few matching requests to compare scores.
4. `TestAgainstCoraza` compares, request by request, the matched rules of file 930 and rule 949110, the place and number of each match, and the total score.

**Result:**

| | Requests |
| --- | --- |
| In the reference file | 1,093 |
| Compared | 1,026 |
| of those, with at least one match | 138 |
| Identical in rules, places, match counts, and score | 1,022 |
| Same rules, Coraza counts more matches | 4 |
| Unexplained differences | 0 |
| Not compared: body not inspected by our engine | 67 |

**The one difference, explained:** all 4 requests have a parameter value that is not valid UTF-8. Coraza's `utf8toUnicode` rewrites an invalid byte as `%ufffd`; ours copies it, as ModSecurity v2 does (main plan section 11.7). Coraza's value changes at that step, so the `multiMatch` rule 930110 tests it once more and scores 5 points more. Both engines find the same rules. This is kept as a known difference, because following Coraza here would mean leaving the ModSecurity behaviour that the transformation tests verify.

**What this settles:** the open point of main plan section 11.9. For `multiMatch`, Coraza re-tests a value only when it changed, as our engine does, and the scores agree. The expected higher score of ModSecurity v2 (its `cmdLine` always reports a change) is still a reading of its source, not a measurement; no ModSecurity run was made.

**Limits:** only rules 930100, 930110, and 949110 are compared, since no other detection rule is active. Coraza is an independent implementation, not a definition of correct behaviour. Requests with XML, JSON, or multipart bodies are outside the comparison until stage 5.


### 8.3. Stage 3 — done on 11 October 2026

1. `httpmodel`: cookies are parsed from every `Cookie` header the way ModSecurity parses version 0 cookies (read from `msc_parsers.c`); values are not decoded. A target written as a full URL gives the path after the host.
2. `engine`: variables `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_FILENAME`, `REQUEST_BASENAME`; regular-expression selectors such as `REQUEST_COOKIES:/^_ga/`, matched without regard to case as in ModSecurity.
3. `seclang` and `engine`: `SecRuleUpdateTargetById`. An update for a rule that is not active changes nothing and is listed by `RuleSet.IgnoredTargetUpdates`. The form with a replaced target is rejected.
4. `MATCHED_VARS` was moved to stage 7, where its only user (941310) is activated.

### 8.4. Stage 4 — done on 11 October 2026

1. `@pm` and `@pmFromFile`, built as one Aho-Corasick automaton per rule so a value is read once however long the phrase list is. Data files are read at load time; a missing or empty file stops loading. A randomised test compares the automaton with a plain search for each phrase.
2. `normalizePathWin`, a line-by-line port of `normalize_path_inplace` from ModSecurity v2, compared with 934 results from the C original.
3. Rules 930120, 930130, 930140, and the PL2 rule 930121 were taken off the exclusion list. The configuration now excludes 7 rules, all in file 901; 69 of 76 are active.

**Result for file 930:** all 5 PL1 rules are active with 0 failed tests; 67 of their 72 CRS tests pass and 5 are not inspected (XML or multipart bodies, stage 5).

**Comparison with Coraza**, on 1,426 requests (464 with a match; 400 generated file-access variants were added): identical except the 4 invalid-UTF-8 requests already known and **one new, explained difference**:

- A value whose path segment ends in two dots, such as `win.ini..`. ModSecurity v2's `normalizePathWin` reads that segment as a back-reference and removes it; our port does the same, and the C original confirms it. Coraza uses a different algorithm that keeps the segment and strips trailing dots, so Coraza still finds `win.ini` and rule 930120 matches there.
- **Security note for the user:** in this case the ModSecurity behaviour we follow loses a detection that Coraza makes. On Windows a file name with trailing dots opens the file without them, so this is a possible way around rule 930120 on ModSecurity-compatible engines. Following Coraza here instead would mean replacing the verified port with Coraza's algorithm. Not decided; recorded as an open point.

A side effect on earlier results: the example request `/get?arg=../../../etc/passwd` now also matches 930120 (the file name `etc/passwd`), so its score is 25, not 20. Coraza gives 25 as well.

### 8.5. Stage 5 — done on 11 October 2026

1. `httpmodel` reads three more body formats, chosen from the Content-Type the way CRS and the recommended engine configuration choose a body processor:
   - **JSON:** every value becomes an argument named by its path (`json.user.name`, `json.items.0`); repeated keys are kept; numbers keep their written text.
   - **Multipart:** text fields become arguments; for files the field name and the file name are kept (the name as the client wrote it, with its path) and the content is skipped (M17).
   - **XML:** the text between tags and the attribute values, read with Go's standard XML reader, which loads nothing the document refers to.
2. New body state **partly inspected**: a body that breaks off or is malformed is read as far as it goes; what was read is inspected and the status says the rest was not (M05).
3. A body over 1 MiB is not parsed and is reported as not inspected. The value is a first default; A08 stays open.
4. `engine`: variables `FILES`, `FILES_NAMES`, `XML:/*`, `XML://@*`. Other XPath expressions are refused at load time. Since every variable of the rules in scope is now provided, the "variables not provided" part of the startup report was removed.
5. This settles, for the rule layer, the A02 questions on JSON and multipart representation. Naming follows Coraza (index-based paths); Coraza additionally adds one argument per array holding its length, which is not reproduced.

**Result:** all 72 CRS tests of file 930 pass. In the summary over all 687 tests, "not inspected" is 0.

**Comparison with Coraza:** 1,492 requests compared (468 with a match), no unexplained difference; the known ones are unchanged (4 invalid-UTF-8 requests, 1 `normalizePathWin` request). Coraza reports XML under the name `REQUEST_XML` and files without the field name; the comparison accounts for both.

**Limits:** Go's JSON reader replaces invalid UTF-8 inside strings; XML in an encoding other than UTF-8 is reported as partly inspected; a 20-second fuzz run of the body parsers found no crash.

### 8.6. Stages 6 and 7 — done on 11 October 2026

The two stages were worked together, because the SQLi and XSS rules share most of what they need.

1. **Transformations:** `replaceComments`, `removeCommentsChar`, `removeWhitespace`, `compressWhitespace`, `lowercase`, `htmlEntityDecode` (with ModSecurity's table of 44 entity names), `jsDecode`, `cssDecode`. Each is a port of the ModSecurity v2 function and agrees with the C original on about 870 inputs each (11,827 recorded results for all 13 transformations).
2. **`urlDecodeUni` now uses the best-fit table** (code page 20127 of ModSecurity's `unicode.mapping`, 370 entries, generated into `unicode_best_fit.go`). A `%uXXXX` code for a look-alike character becomes the ASCII character: the curly apostrophe becomes `'`, the guillemets become `<` and `>`. Checked against the C original with the table loaded. This closes the open point "Unicode mapping file" of main plan section 11.7. Note: `%u2215` is not in that code page and still gives its low byte.
3. **Operators:** `@detectSQLi` and `@detectXSS` through `github.com/corazawaf/libinjection-go` v0.3.5 (decision D2), which is now the one dependency of the IDS module; `@contains`, `@streq`, `@validateByteRange`.
4. **`@rx` byte mode:** a pattern that names a byte above 0x7F (`\x80`–`\xff`, also written `\x{80}`) is matched byte by byte, as PCRE does. Go would otherwise read such an escape as a two-byte character and never find the byte. Six patterns in files 941 and 942 need this.
5. **Engine:** `MATCHED_VARS` (what the earlier rules of a chain matched); `ctl:ruleRemoveTargetByTag`, which rule 941010 uses to stop the XSS rules from inspecting a plain file path for the rest of a request. Other `ctl` forms are refused at load time.
6. **`REQUEST_FILENAME` is now the percent-decoded path**, as in Coraza and ModSecurity v3. ModSecurity v2 gives the path as sent. Found by the comparison: without decoding, a rule with no decoding step of its own missed `alert(` after `%3E`.
7. **Configuration:** files 941, 942, and 999 are loaded. All their rules, including the PL2–PL4 rules that the gates skip at level 1, are supported; nothing in them is excluded. 179 of 186 rules are active; the 7 excluded rules are all in file 901. File 999's one update for rule 932240, which is not loaded, is ignored and reported.

**Result: all 687 CRS regression tests of the 51 PL1 rules pass.**

| Rule file | PL1 rules | Tests | Passed |
| --- | --- | --- | --- |
| 930 path traversal and file access | 5 | 72 | 72 |
| 941 XSS | 26 | 242 | 242 |
| 942 SQL injection | 20 | 373 | 373 |

**Comparison with Coraza** (500 generated SQLi/XSS variants with different encodings were added):

| | Requests |
| --- | --- |
| Compared | 1,989 |
| of those, with at least one match | 1,277 |
| Identical in rules, places, match counts, and score | 1,985 |
| Same rules, Coraza counts more matches (invalid UTF-8, known since stage 2) | 4 |
| Left out as known differences, each with a written reason | 4 |
| Unexplained differences | 0 |

**The second detection-relevant difference, for the user's attention:** three generated requests write `<` as the entity `&LT` with no semicolon, directly followed by letters (`&LTscript`). ModSecurity v2's `htmlEntityDecode` reads the whole run of letters as the entity name and leaves it; our port does the same, and the C original confirms it. Coraza accepts the known name at the start, as browsers do, so it sees `<script` and one more rule matches. Each of the three requests is still flagged by other rules in both engines. Together with the `normalizePathWin` case of stage 4, this is the second place where the ModSecurity behaviour we follow sees less than Coraza. **Open decision:** keep following ModSecurity v2 for transformations, or follow Coraza in these two functions.

### 8.7. Stage 8 — done on 11 October 2026

**1. Pilot records.** The 1,000 CSIC 2010 records of the ML pilot (`ids-model/data/http-mini/requests.jsonl`) were run through the full rule set. `tools/csic_to_examples.py` converts them; the data is read where it is and not copied into this repository. The label only chooses the output file; the engine never sees it.

| Group | Requests | Flagged (score at threshold) | Not completely inspected |
| --- | --- | --- | --- |
| Labelled normal | 500 | **0** | 0 |
| Labelled anomalous | 500 | **80** | 0 |

Of the 80, 46 were flagged by XSS rules, 34 by SQLi rules, and 3 by file 930 rules (a request can be in more than one group).

How to read this, and how not to:

- No normal request was flagged. That is one false-positive measurement on 500 synthetic requests of one shop application from 2010. It is not a false-positive rate for real traffic.
- 16% of the anomalous records were flagged. This is **not a detection rate**. "Anomalous" in CSIC includes many requests that are not SQLi, XSS, or path traversal (parameter tampering, overflow attempts, CRLF injection and others), and the label does not mean every record is a confirmed attack (main plan section 2.1). How many of the 500 are in the three attack types is not known.
- Nothing was tuned on these numbers. The same records were already observed in the ML pilot.
- These are rule-layer results. Combining them with the ML score is the job of the decision mechanism (M10, A06).

**2. Speed.** Benchmarks in `internal/engine/bench_test.go`, on the development laptop (AMD Ryzen 5 7530U, 12 threads), full rule set, including parsing the request:

| Request | Time | Memory | Allocations |
| --- | --- | --- | --- |
| Normal GET with seven headers and a cookie | 0.42 ms | 146 kB | 1,881 |
| Normal POST, form body | 0.48 ms | 151 kB | 2,153 |
| Normal POST, JSON body | 0.74 ms | 259 kB | 2,795 |
| Attack GET (SQLi and traversal) | 0.47 ms | 134 kB | 1,778 |
| POST with a 9.4 kB form field | **18.5 ms** | 425 kB | 3,258 |
| Normal GET, all 12 threads at once | 0.10 ms per request | | |
| Loading and compiling all rules (once, at startup) | 12 ms | 10.7 MB | |

- One core handles about 2,000 small requests per second; all cores together about 9,600.
- **A long value is slow:** about 0.5 MB per second, because more than 90 regular expressions each read the whole value. This is the main finding for A08. It was measured, not optimised. Candidates for later: run each chain of transformations once per value instead of once per rule, and skip a pattern when a required literal is absent.
- These are single-machine micro-benchmarks. They are not the end-to-end measurement M09 asks for.

**3. Fuzzing.** 30 seconds on the whole rule layer (requests built from random text, 256,000 runs), 20 on the transformations, 20 on the body parsers: no crash, and the same request always gave the same result. The transformation fuzzer did find an input where my own test property was wrong (`normalizePathWin` can leave a backslash); the C original gives the same result, so the property was corrected and the case recorded.

### 8.8. State at the end of the plan

All eight stages are done. The goal of section 1 is reached: the 51 PL1 rules of files 930, 941, and 942 run from the unmodified CRS files, and their 687 regression tests pass.

Open points this work produced:

1. **Whom to follow where ModSecurity v2 and Coraza differ** (`normalizePathWin`, `htmlEntityDecode`, `utf8toUnicode`). In the first two, Coraza detects what ModSecurity's behaviour misses. Decided for those two on 11 October 2026; see section 8.9.
2. **Speed on long values** (A08).
3. **No ModSecurity run** has been made; everything about ModSecurity comes from its source and from running single C functions.
4. **Evaluation data** (A07): the only traffic used so far is the CRS tests, generated variants, and the 1,000 pilot records.
5. Smaller: Go's JSON reader replaces invalid UTF-8 in strings; XML in encodings other than UTF-8 is only partly inspected; the body limit of 1 MiB is a first default.

### 8.9. After the plan: two transformations changed to Coraza's behaviour — 11 October 2026

**Decision (user, 11 October 2026):** `normalizePathWin` and `htmlEntityDecode` follow Coraza, not ModSecurity v2. Reason: in both, the ModSecurity behaviour left a disguise in place that Coraza removes, so a rule could be avoided.

| Function | Input | Before (ModSecurity v2) | Now (Coraza v3.8.1) |
| --- | --- | --- | --- |
| `normalizePathWin` | `a/win.ini..` | `a` (the segment is removed) | `a/win.ini` |
| `htmlEntityDecode` | `&LTscript` | unchanged | `<script` |

**What was done:**

1. Both functions were rewritten after reading Coraza's source. The change is larger than the two examples, because Coraza's functions are different algorithms, not variants of ModSecurity's.
2. `normalizePathWin` now also removes dots and spaces at the end of every path segment and cuts a Windows data-stream name (`web.config::$DATA` becomes `web.config`).
3. `htmlEntityDecode` now knows all names of the HTML standard and reads them as a browser does. It uses the entity table of Go's standard `html` package; no dependency was added. Go's own decoder is not used for numbers, because it reads a few broken ones differently from the decoder Coraza uses; the comparison below found that.
4. The reference results of these two functions were removed from the ModSecurity file and recorded anew from Coraza's code in `internal/engine/transform/testdata/coraza_v3_vectors.txt`. Its header says how.

**What the change gives up:** ModSecurity decodes some things that Coraza and browsers do not, and these are no longer decoded: an entity name in the wrong letter case (`&COLON;`), most names without their semicolon (`&colon`), and of a number above 255 only its low byte. A browser does not read these as the character either. Two results of Coraza's `normalizePathWin` are odd and are reproduced: a path that is only `/` becomes `//`, and a value such as `ab:boot.ini` is cut to `ab`.

**Checked:**

1. Both functions agree with 2,517 results recorded from Coraza's code (1,276 and 1,241), and with about 92,000 further random inputs in a one-time run.
2. The other 11 transformations still agree with their 10,008 ModSecurity results.
3. Comparison with Coraza on whole requests: all 1,993 requests compared, 1,281 with a match, 0 differences. The list of known differences is now empty. 4 requests with invalid UTF-8 still differ in match count only (`utf8toUnicode`, unchanged).
4. All 687 CRS regression tests pass.
5. Pilot records unchanged: 0 of 500 normal and 80 of 500 anomalous flagged.
6. `go vet`, `go test`, and `go test -race` pass for all eight packages; 20 seconds of fuzzing found nothing.

Not committed.
