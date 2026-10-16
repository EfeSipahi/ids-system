# OWASP CRS 4.30.0 — Ruleset Reference

Created: 5 October 2026
Source directory: [`coreruleset-4.30.0/`](../coreruleset-4.30.0)
Related decisions: M15, M17, M18, M19, M20, M21 in the [main plan](../ids-system-plan-phaze1.md)

**Reading rule:** This document describes what is in the CRS files. It does not describe what our engine supports; for that see [context.md](../context.md). Sections 6.2 and 7 were written before the engine existed: since 11 October 2026 all 51 PL1 rules of files 930, 941, and 942 run.

## 1. What this directory is

1. OWASP CRS (Core Rule Set) is a set of attack-detection rules written in SecLang. It is not a program. An engine has to read and execute it; under M15 that engine will be our own.
2. The local copy is the official source archive of the `v4.30.0` tag (released 2 October 2026), licensed Apache 2.0.
3. **Integrity check, 5 October 2026:** the official archive `https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.30.0.tar.gz` was downloaded to a temporary directory and compared with the local copy using `diff -rq`. There were no differences. All 627 rules carry `ver:'OWASP_CRS/4.30.0'`.
4. The files must stay unmodified (M18, M19). Our own settings go in separate configuration, not into these files.

## 2. Directory layout

| Path | Content | Used by us |
| --- | --- | --- |
| `crs-setup.conf.example` | Settings template: paranoia level, thresholds, default actions | Yes, loaded first |
| `rules/*.conf` | 27 rule files | All request files (since 16 October 2026); response files not yet, see section 6 |
| `rules/*.data` | 20 word lists read by `@pmFromFile` rules | Those that request rules read |
| `tests/regression/tests/` | 326 YAML files with 5,260 test cases, grouped per rule | Yes, as acceptance examples |
| `regex-assembly/` | Sources from which the long regexes are generated | No, reference only |
| `plugins/` | Empty placeholders for optional plugins | No |
| `docs/`, `*.md`, `.github/` | Upstream project documentation and CI | No |

## 3. Rule files

File names start with a number. The engine loads them in that order.

Columns: **Rules** = rules with an ID. **PL1–PL4** = detection rules at that paranoia level. **Control** = rules without a PL tag (setup, gates, score evaluation).

### 3.1. Request files

| File | Purpose | Rules | PL1 | PL2 | PL3 | PL4 | Control |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `REQUEST-901-INITIALIZATION` | Default settings and score variables | 33 | 0 | 0 | 0 | 0 | 33 |
| `REQUEST-905-COMMON-EXCEPTIONS` | Exceptions for known harmless requests | 2 | 0 | 0 | 0 | 0 | 2 |
| `REQUEST-911-METHOD-ENFORCEMENT` | Allowed HTTP methods | 9 | 1 | 0 | 0 | 0 | 8 |
| `REQUEST-913-SCANNER-DETECTION` | Known scanner user agents | 9 | 1 | 0 | 0 | 0 | 8 |
| `REQUEST-920-PROTOCOL-ENFORCEMENT` | Malformed or unusual HTTP | 68 | 40 | 9 | 5 | 5 | 9 |
| `REQUEST-921-PROTOCOL-ATTACK` | Request smuggling, header injection | 26 | 11 | 2 | 3 | 1 | 9 |
| `REQUEST-922-MULTIPART-ATTACK` | Multipart body attacks | 7 | 4 | 0 | 0 | 0 | 3 |
| **`REQUEST-930-APPLICATION-ATTACK-LFI`** | **Path traversal, local file access** | 14 | 5 | 1 | 0 | 0 | 8 |
| `REQUEST-931-APPLICATION-ATTACK-RFI` | Remote file inclusion | 13 | 3 | 2 | 0 | 0 | 8 |
| `REQUEST-932-APPLICATION-ATTACK-RCE` | Command injection | 56 | 19 | 19 | 10 | 0 | 8 |
| `REQUEST-933-APPLICATION-ATTACK-PHP` | PHP injection | 29 | 13 | 3 | 5 | 0 | 8 |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC` | Node.js, SSRF, template injection and others | 22 | 8 | 5 | 1 | 0 | 8 |
| **`REQUEST-941-APPLICATION-ATTACK-XSS`** | **Cross-site scripting** | 42 | 26 | 7 | 0 | 0 | 9 |
| **`REQUEST-942-APPLICATION-ATTACK-SQLI`** | **SQL injection** | 68 | 20 | 31 | 7 | 2 | 8 |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION` | Session fixation | 11 | 3 | 0 | 0 | 0 | 8 |
| `REQUEST-944-APPLICATION-ATTACK-JAVA` | Java attacks | 22 | 6 | 6 | 1 | 1 | 8 |
| `REQUEST-949-BLOCKING-EVALUATION` | Sum request scores, compare with threshold | 28 | 0 | 0 | 0 | 0 | 28 |
| `REQUEST-999-COMMON-EXCEPTIONS-AFTER` | 55 `SecRuleUpdateTargetById` exclusions (for example Google Analytics cookies); no rules with an ID | 0 | 0 | 0 | 0 | 0 | 0 |

### 3.2. Response files

These inspect what the application sends back. Response bodies are outside the Phase 1 scope (M17).

| File | Purpose | Rules |
| --- | --- | --- |
| `RESPONSE-950-DATA-LEAKAGES` | General information leaks | 15 |
| `RESPONSE-951-DATA-LEAKAGES-SQL` | Database error messages | 25 |
| `RESPONSE-952-DATA-LEAKAGES-JAVA` | Java errors | 9 |
| `RESPONSE-953-DATA-LEAKAGES-PHP` | PHP errors | 12 |
| `RESPONSE-954-DATA-LEAKAGES-IIS` | IIS errors | 13 |
| `RESPONSE-955-WEB-SHELLS` | Web shell output | 35 |
| `RESPONSE-956-DATA-LEAKAGES-RUBY` | Ruby errors | 10 |
| `RESPONSE-959-BLOCKING-EVALUATION` | Sum response scores | 28 |
| `RESPONSE-980-CORRELATION` | Final reporting of request and response scores | 21 |

### 3.3. Totals

| | Count |
| --- | --- |
| All rules | 627 |
| Control rules | 282 |
| PL1 detection rules | 214 |
| PL2 detection rules | 90 |
| PL3 detection rules | 32 |
| PL4 detection rules | 9 |

The two `.conf.example` files (`REQUEST-900-…BEFORE-CRS` and `RESPONSE-999-…AFTER-CRS`) are templates for user-written exclusions and contain no active rules.

## 4. How CRS works

1. **Anomaly scoring.** A detection rule does not block. When it matches, it adds points to a score. Points depend on the rule's severity: critical 5, error 4, warning 3, notice 2.
2. **Threshold.** File 949 adds up the request scores and compares the total with the inbound threshold (default 5). One critical match is enough to reach it. In our Phase 1 this produces a finding and a score, never a block (M09, M15).
3. **Paranoia level (PL).** PL1 is the default set with the fewest false positives. PL2 to PL4 add stricter rules. Each file contains gate rules that jump over the rules above the configured level.
4. **Phases.** Every rule has a `phase:` number. All phase 1 rules run first (request headers), then all phase 2 rules (request body). Phases 3 to 5 concern the response and logging.
5. **Per-request variables (`TX`).** Settings and scores live in a variable collection that belongs to one request. Under M21 our engine keeps this separate for each request.

## 5. Structure of a rule

```
SecRule  VARIABLES  "OPERATOR"  "ACTIONS"
```

| Part | Question | Examples |
| --- | --- | --- |
| Variables | Where to look | `ARGS`, `REQUEST_HEADERS`, `REQUEST_COOKIES`, `REQUEST_FILENAME`, `TX:name` |
| Operator | What test | `@rx`, `@pmFromFile`, `@detectSQLi`, `@detectXSS`, `@eq`, `@lt`, `@ge` |
| Transformations | How to clean the value first | `t:urlDecodeUni`, `t:lowercase`, `t:removeNulls` |
| Actions | What to do on a match | `setvar`, `skipAfter`, `msg`, `severity`, `tag`, `chain` |

Other directives in the files: `SecAction` (actions without a test), `SecMarker` (jump label), `SecDefaultAction` (defaults per phase), `SecComponentSignature` (version label), `SecRuleUpdateTargetById` (edits another rule's variable list).

Rule roles: **setup** (write defaults to `TX`), **gate** (skip higher PL rules), **detection** (inspect the request, add score), **evaluation** (sum and compare).

## 6. Our scope

### 6.1. Scope after the decisions of 12 October 2026 (K6, K7)

M19 and M20 first limited the scope to the PL1 rules of files 930, 941, and 942. On 12 October 2026 the user extended it (main plan, section 11.16): all request attack groups (K6) and all four paranoia levels, chosen in the configuration with PL1 as the default (K7). Response rules wait for the proxy decision (K8).

| Part | Files | Status on 16 October 2026 |
| --- | --- | --- |
| Request rules | 901, 905, 911, 913, 920, 921, 922, 930–934, 941–944, 949, 999 | All run, at levels 1 to 4. 456 of 460 rules active; 4 setup rules of 901 excluded with reasons |
| Response rules | 950–956, 959, 980 | Not loaded; they need a copy of each response |

The work followed `docs/development-plan-all-request-rules.md`.

### 6.2. Earlier stages

1. **First engine (5–11 October 2026):** detection rules 930100 and 930110, with their real dependencies.
2. **Rule layer for the first scope (11 October 2026):** the 51 PL1 rules of files 930, 941, and 942. Sections 6.3 to 6.5 and 7 below describe that scope and are kept as a reference.

### 6.3. PL1 rules in file 930

| ID | Phase | Operator | Message | Transformations |
| --- | --- | --- | --- | --- |
| 930100 | 2 | `@rx` | Path Traversal Attack (/../) or (/.../) | none |
| 930110 | 2 | `@rx` | Path Traversal Attack (/../) or (/.../) | utf8toUnicode, urlDecodeUni, removeNulls, cmdLine |
| 930120 | 2 | `@pmFromFile lfi-os-files.data` | OS File Access Attempt | utf8toUnicode, urlDecodeUni, normalizePathWin |
| 930130 | 1 | `@pmFromFile restricted-files.data` | Restricted File Access Attempt | utf8toUnicode, urlDecodeUni, normalizePathWin |
| 930140 | 1 | `@pmFromFile ai-critical-artifacts.data` | Restricted File Access Attempt: AI Coding Assistant Artifact | utf8toUnicode, urlDecodeUni, normalizePathWin |

930100 looks at the value as received, so it catches encoded forms such as `%2f..%2f`. 930110 decodes first and then looks for plain `../`.

### 6.4. PL1 rules in file 941 (XSS)

All run in phase 2 with severity critical.

| ID | Operator | Message |
| --- | --- | --- |
| 941100 | `@detectXSS` | XSS Attack Detected via libinjection |
| 941110 | `@rx` | XSS Filter - Category 1: Script Tag Vector |
| 941120 | `@rx` | XSS Filter - Category 2: Event Handler Vector |
| 941130 | `@rx` | XSS Filter - Category 3: Attribute Vector |
| 941140 | `@rx` | XSS Filter - Category 4: Javascript URI Vector |
| 941160 | `@rx` | NoScript XSS InjectionChecker: HTML Injection |
| 941170 | `@rx` | NoScript XSS InjectionChecker: Attribute Injection |
| 941180 | `@pm` | Node-Validator Deny List Keywords |
| 941190 – 941300 (12 rules) | `@rx` | IE XSS Filters - Attack Detected; 941210 is "Javascript Word Detected" |
| 941310 | `@rx`, chained | US-ASCII Malformed Encoding XSS Filter |
| 941350 | `@rx` | UTF-7 Encoding IE XSS |
| 941360 | `@rx` | JSFuck / Hieroglyphy obfuscation detected |
| 941370 | `@rx` | JavaScript global variable found |
| 941390 | `@rx` | Javascript method detected |
| 941400 | `@rx` | XSS JavaScript function without parentheses |

Most of them share the transformation chain utf8toUnicode, urlDecodeUni, htmlEntityDecode, jsDecode, cssDecode, removeNulls.

### 6.5. PL1 rules in file 942 (SQLi)

All run in phase 2 with severity critical. Nearly all use only `t:urlDecodeUni`.

| ID | Operator | Message |
| --- | --- | --- |
| 942100 | `@detectSQLi` | SQL Injection Attack Detected via libinjection |
| 942140 | `@rx` | Common DB Names Detected |
| 942151 | `@rx` | SQL function name detected |
| 942160 | `@rx` | Blind sqli tests using sleep() or benchmark() |
| 942170 | `@rx` | SQL benchmark and sleep injection attempts including conditional queries |
| 942190 | `@rx` | SQL code execution and information gathering attempts |
| 942220 | `@rx` | Integer overflow attacks |
| 942230 | `@rx` | Conditional SQL injection attempts |
| 942240 | `@rx` | MySQL charset switch and MSSQL DoS attempts |
| 942250 | `@rx` | MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections |
| 942270 | `@rx` | Basic sql injection, common attack string |
| 942280 | `@rx` | Postgres pg_sleep, waitfor delay, database shutdown attempts |
| 942290 | `@rx` | Basic MongoDB SQL injection attempts |
| 942320 | `@rx` | MySQL and PostgreSQL stored procedure/function injections |
| 942350 | `@rx` | MySQL UDF injection and other data/structure manipulation |
| 942360 | `@rx` | Concatenated basic SQL injection and SQLLFI attempts |
| 942500 | `@rx` | MySQL in-line comment detected |
| 942540 | `@rx` | SQL Authentication bypass (split query) |
| 942550 | `@rx` | JSON-Based SQL Injection |
| 942560 | `@rx` | MySQL Scientific Notation payload detected |

## 7. What the PL1 scope requires from an engine

This is the work list for the engine, read from the three files. None of it is implemented.

| Area | Needed |
| --- | --- |
| Operators | `@rx`, `@pm`, `@pmFromFile`, `@detectXSS`, `@detectSQLi`, and for control rules `@eq`, `@lt`, `@ge` |
| Transformations | none, urlDecodeUni, utf8toUnicode, removeNulls, htmlEntityDecode, jsDecode, cssDecode, lowercase, removeWhitespace, compressWhitespace, replaceComments, removeCommentsChar, cmdLine, normalizePathWin |
| Variables | `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `REQUEST_URI_RAW`, `FILES`, `TX`, `XML` |
| Data files | `lfi-os-files.data` (1,222 lines), `restricted-files.data` (787), `ai-critical-artifacts.data` (55) |
| Flow | Phases, `skipAfter` with markers, chained rules, `multiMatch`, `capture`, macro expansion `%{...}` |

Points to keep in mind:

1. `@detectSQLi` and `@detectXSS` are not regexes. In ModSecurity they call the libinjection library. Which Go implementation we use is an open choice under A11.
2. `XML` appears in almost every detection rule's variable list. Structured XML is deferred (M17), so the engine must report that target as not inspected rather than ignore it silently.
3. The regexes in these files are long and generated from `regex-assembly/`. They must be taken from the rule files as they are, not retyped.

## 8. Regression tests

1. Location: `tests/regression/tests/<rule file name>/<rule id>.yaml`.
2. Each test describes a request (`method`, `uri`, `headers`, `data`) and the expected result (`expect_ids` or `no_expect_ids`).
3. Counts (converted on 16 October 2026, all request files): 5,094 test requests; 22 of them only check the web server's answer and are left out; the other 5,072 are converted to `testdata/requests/crs/` and all pass with the test configuration `testdata/crs-tests.json`. The first scope had 83 in file 930, 263 in 941, and 1,033 in 942 (1,032 in the first count of 5 October, which missed one).

4. These tests were written for reference engines running the complete ruleset. Some expectations may depend on rules or engine behaviour outside our scope, so each group has to be reviewed before it is used as an acceptance set.

## 9. How the numbers were produced

Counted on 5 October 2026 from the files in `coreruleset-4.30.0/rules/` with a script that joins continuation lines, skips comments, and reads `id:`, `phase:`, `tag:'paranoia-level/N'`, the operator and the `t:` actions of each rule. Inner rules of a chain have no ID and are not counted separately. Test cases were counted by `test_id:` entries.
