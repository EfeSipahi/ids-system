# Development plan: own rules

Written: 23 November 2026, at the user's request of 21 November: "lets add a feature to write our own rules make a plan first". Today the IDS runs only CRS 4.30.0's rules. An application can switch CRS rules off or narrow them (exceptions), but nobody can add a rule for their own site's attacks, such as "alert when `/admin` is reached from outside the office network". This is item 5 of [dashboard-roadmap.md](dashboard-roadmap.md) (5.1–5.3). Every question has a code (N1, N2, …) and numbered options; the user decided them on 23 November 2026, N4 and N6 after an explanation.

## 1. What was checked first (21–23 November 2026)

1. The engine (`internal/seclang`, `internal/engine/compile.go`) runs `SecRule`, `SecAction`, `SecMarker` and chains, in phases 1 and 2. Its operators include `rx`, `pm`, `contains`, `streq`, `beginsWith`, `endsWith`, `within`, the number comparisons, `ipMatch`, `detectSQLi` and `detectXSS`; its actions are those CRS uses. Anything else is refused when the files are loaded, with file and line (M15).
2. Regular expressions use Go's `regexp`, which is RE2: matching takes time in proportion to the text, so a rule written by a person can't hang the IDS. PCRE-only syntax, such as look-arounds and back-references, is refused at load.
3. The score. A CRS rule adds points to `tx.inbound_anomaly_score_plN` by its severity: critical 5, error 4, warning 3, notice 2 (`REQUEST-901`). `REQUEST-949` adds them up into `blocking_inbound_anomaly_score`, which the IDS compares with the threshold, 5 by default (`result.NewScore`). So a rule of our own must run before the 949 file and add to that variable. CRS puts the score's `setvar` on the last rule of a chain.
4. Per application. `engine.TuningSpec.Off` already switches rules off per application, per request, on one shared rule set (F5, option B). `profile.NewSet` builds each application's tuning. Requests of no application run with no tuning.
5. All analysis goes through `analysis.Run`: ids-offline, ids-live, and the dashboard's Analyse files, Test tab and change checker.
6. `ids-live` reads its configuration, rule files and profiles every 3 seconds and takes a change when the configuration's fingerprint changes (W13). So an own-rules file must be part of the fingerprint.
7. The start record of a run lists every rule (`record.Rule`); optional fields can be added within schema 1 ([records-format.md](records-format.md)).
8. ModSecurity keeps rule ids 1–99,999 for local rules; CRS uses 900,000–999,999.

## 2. Questions

N1. How a rule is written.

1. A form: one or more conditions (place, test, value, "not"), all must match; a message; a severity. The dashboard writes the SecLang and shows it. Admins may also edit the SecLang text, within N4.
2. SecLang text only, as in CRS's files.
3. The form only.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

N2. Where own rules are kept.

1. One own-rules file per configuration, named by a new setting `own_rules`. The engine loads it right before CRS's 949 file, so the order can't be wrong, and the dashboard writes only that file.
2. An ordinary entry in the configuration's `files` list, placed by hand before 949.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

N3. Rule numbers.

1. Given by the dashboard: the next free number in 1,000–99,999, shown, not typed. Hand-written text must stay in that range.
2. Typed by the person, checked to be free and in range.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

N4. What an own rule may do.

1. Detect only: match, add to the score by its severity, message, tags. No `ctl`, no `setvar` but its score, no `skipAfter`, no `pmFromFile`. Turning rules off stays with exceptions.
2. Anything the engine supports.

Recommendation was 1: a rule that raises the threshold or removes rules would silently weaken all detection. Decided by the user on 23 November 2026: 1, after asking what the four are and why they are left out. The answer: `setvar` sets any of the request's shared values, so `setvar:tx.inbound_anomaly_score_threshold=1000` would end every alert; `ctl` changes the engine for the rest of the request, and CRS's own rule 905100 uses `ctl:ruleRemoveByTag=OWASP_CRS` to switch every CRS rule off; `skipAfter` jumps over the rules up to a marker, and since own rules load just before the 949 file, it could jump over the scoring itself; `@pmFromFile` reads its words from a second file that the dashboard's versions and undo don't cover, which can go missing and whose path can point anywhere. `@pm`, with the words in the rule, does the same job.

N5. Which requests a rule applies to.

1. Chosen per rule: every request, or chosen applications, and/or requests of no application. The rule is switched off for the others through each application's existing off list; requests of no application get such a list too.
2. Every request for now; per application later.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

N6. Score and level.

1. The severity gives the score as in CRS (critical 5, error 4, warning 3, notice 2); the rule counts at level 1, so it runs at every level. A critical rule alone reaches the default threshold of 5.
2. The person also picks a paranoia level.

Recommendation was 1. Decided by the user on 23 November 2026: 1, after asking what the level means. The answer: the IDS runs CRS at a paranoia level, 1 to 4, per application; each level adds stricter rules that find more and flag more normal requests. With option 1 an own rule runs at every level and its severity is its weight: a critical rule makes an alert by itself, a warning only together with other points. With option 2 the rule would run only at the chosen level and above, like CRS's stricter rules.

N7. Who writes them.

1. As exceptions: analysts propose, admins apply after the preview; the password is asked again, as for other changes to every application (W9, W10).
2. Admins only.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

N8. Trying a rule before it is applied.

1. The Test tab gains "with pending changes": a hand-written request runs with the rule before anyone applies it; Analyse's Try (W8) shows what it would flag in analysed files.
2. Analyse's Try only.

Recommendation was 1. Decided by the user on 23 November 2026: 1.

## 3. The own-rules file

What the dashboard writes; it stays valid SecLang for ModSecurity and Coraza too:

```
SecRule REQUEST_FILENAME "@beginsWith /admin" \
    "id:1000,phase:1,block,msg:'Admin pages reached from outside the office',severity:'CRITICAL',tag:'paranoia-level/1',tag:'application/lab-site',chain"
    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8" \
        "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

The engine checks every own rule (N3, N4, N6):

1. Only `SecRule`, with chains. No `SecAction`, `SecMarker`, `SecDefaultAction`, `SecRuleUpdateTargetById` or `SecComponentSignature`.
2. The id is 1,000 to 99,999; the phase is 1 or 2; `msg` and `severity` (CRITICAL, ERROR, WARNING or NOTICE) are there.
3. The actions are id, phase, block, chain, msg, logdata, severity, tag, t, capture and multiMatch, and exactly one `setvar`, on the last rule of the chain, that adds the severity's score to `tx.inbound_anomaly_score_pl1`. No `ctl`, no `skipAfter`, no other `setvar`.
4. No `@pmFromFile`.
5. A `paranoia-level/N` tag only with N = 1.
6. Which requests (N5): the tags `application/<name>`, and `application/none` for requests of no application. A rule without such a tag runs for every request. A name the configuration doesn't have is an error.

## 4. Stages

1. The engine and the configuration, without a dashboard change: the setting `own_rules`; the check of section 3; the own file loaded just before the 949 file; the rules' applications turned into each application's off list and an off list for requests of no application; the own file in the fingerprint, only when it is set, so every fingerprint of today stays the same; the start record marks own rules and their applications.
2. The dashboard, reading: the Rules page lists own rules; the page per rule shows the text, the applications, the severity, the matches and the false positives; the preview knows a rule's applications.
3. The dashboard, writing: a New rule form with its SecLang shown (N1), edit and remove, as pending changes through the change path (versions, undo, change log, proposals, N7). The first own rule also sets `own_rules` and makes `own-rules/<configuration>.conf` beside `profiles/`. The preview: removing a rule from the records, adding one through Try.
4. The Test tab with pending changes (N8).
5. The close: `context.md`, the main plan's section 11, `docs/project-history.md`, the roadmap, a browser round in a sandbox.

Work went one stage at a time, with a pause for the user's review after stage 1 (context.md, section 4). After that review the user decided on 23 November 2026: "commit and start the stages auto after every commit": stage 1 committed, then stages 2 to 5 one after another, each committed when done, without a pause. Nothing is pushed until the user says so.

## 5. Checks

1. `gofmt -l .`, `go vet ./...`, `go test ./...`; `go test -race` for the packages changed.
2. Nothing changes without own rules. Measured before the work on 23 November 2026 with `ids-offline` and temporary records folders: the CRS tests with `testdata/crs-tests.json` (5,072 tests, 4,623 flagged, every expectation met); the 1,000 CSIC requests with `configs/crs-first-engine.json` (272 flagged) and `configs/csic-shop.json` (172 flagged, 319 with a profile finding); the 1,300 attack variants with `configs/lab-site.json` (799 flagged). The outputs, and the fingerprints of the four configurations, must stay the same.
3. The example rule of section 3: a request to `/admin` from 203.0.113.5 scores 5 and is an alert for `lab-site`; the same request for another application, or from 10.1.2.3, is not.
4. The check refuses each thing section 3 rules out, each with its own test and an understandable message.
5. Test runs use temporary records folders and configurations, never the user's `records/` or `configs/lab-site.json`.

## 6. Progress

| Stage | Status |
| --- | --- |
| Decisions N1–N8 | All decided on 23 November 2026 |
| 1. Engine and configuration | Done 23 November 2026, commit 773f1a3 |
| 2. Dashboard, reading | Done 23 November 2026 |
| 3. Dashboard, writing | Next |
| 4. Test tab with pending changes | |
| 5. Close | |

## 7. Notes from the work

Stage 1, 23 November 2026:

1. `own_rules` is a field of the engine's configuration (`engine.Config.OwnRules`), relative to the configuration's folder like `files`. Naming the same file in `files` too is an error. `engine.Load` loads it just before the first file whose name starts with `REQUEST-949-`; without such a file, `own_rules` is an error, since the own rules' points would never be added up.
2. The check (`internal/engine/own.go`) runs before the compiler. When it finds a problem, the file is not compiled, so its reasons come first and alone; a file that passes it is compiled like every rule file, so what the engine can't run (a look-behind, an unknown operator) is still an error. Every message names the file, the line and the rule.
3. `engine.Config.ReadFile`, set by `config.Parse` to its `readFile`, reads the own-rules file when the rules are loaded. Stage 3 uses it to check a pending own rule before it is written, as profiles are checked today (W12).
4. Which requests (N5): `profile.NewSet` adds the own rules that are not for an application to its off list, and makes an off list for requests of no application (`Set.NoApplicationTuning`), which `analysis.Run` uses. With no own rule limited to applications, that list is nil, so requests of no application run exactly as before. An own rule naming an application the configuration doesn't have is an error with the rule's file and line.
5. The fingerprint covers the own-rules file only when `own_rules` is set, so the fingerprints of `crs-first-engine.json`, `csic-shop.json`, `lab-site.json` and `testdata/crs-tests.json` are the same as before. `ids-live` compares fingerprints every 3 seconds (W13), so a changed own-rules file is taken like a changed profile. This is covered by the configuration's test and the existing test of W13, not by a test of its own.
6. The start record marks own rules with `own` and `applications` ([records-format.md](records-format.md)); CRS's rules have neither field, so records without own rules are written byte for byte as before.
7. `testdata/own-rules/own-rules.conf` is an example file the tests share: a critical rule for one application with a chain, a warning for every request, an error in phase 2 for requests of no application.
8. Nothing changed without own rules: the seven runs of section 5, item 2, give the same output before and after, apart from the temporary folder's name and the run id.
9. The checks: `gofmt`, `go vet ./...` and `go test ./...` pass; `go test -race` passes for `engine` (948 seconds; the default limit of 10 minutes is too short for it with the race detector), `profile`, `analysis`, `config`, `record` and `ids-offline`.
10. A mistake, corrected: the script of those runs gave `-records` to every run but one, `-json -show-values` with `csic-shop.json`, which wrote two runs (822 records, 411 each) into the user's `records/` folder. They were removed; the file is back to its 1,049 lines and 2,073,205 bytes. The script now gives every run a temporary folder.

Stage 2, 23 November 2026:

1. Own rules have a group of their own, "Own rules", for every id from 1,000 to 99,999 (`groupOf` in `store.go` and `app.js`; a Go test checks that `app.js` has the engine's range). So the Rules page shows the own-rules file as a section named "Own rules", whatever the file is called, and the alerts list can filter by the group.
2. The Rules page: under an own rule's description, the requests it is for ("Own rule, for shop"). The status filter has "Own rules", and, with an application chosen, "Own rules for other requests": an own rule that names other applications is "Not for blog" there, counted in the line above the table, and has no "Change…" button, since an exception for it would change nothing.
3. The page per rule: for an own rule, its severity and the points it adds, "every level" for the paranoia level, which requests it is for, and "an own rule" for the rule set. "Where it runs" says "Not for it" for the applications it does not name. The text comes from the configuration's `own_rules` file, like CRS's from `files`, and the severity is read from that text, so the start record does not need it.
4. The preview: its model of which rules run left out every rule whose file is not in `files`, so it would have counted every own rule's findings as gone with any change. It now reads the own-rules file (`engine.ReadOwnRules`, through the pending files' `ReadFile`): a rule counts while the file has it, for the applications it names. Removing a rule or giving it to another application takes its findings away in the preview; a file that can't be read is the preview's error.
5. The checks: `gofmt`, `go vet ./...`, `go test ./...`, and `go test -race` on the dashboard (302 seconds).
6. A browser round in a sandbox (scratch records from `ids-offline` with the example rules and two applications, a dashboard on its own port): the Rules page with each filter, the pages of rules 1000 and 1001, blog's Rules tab, the alerts of the group, and rule 1000 at phone width; no script errors, and no page wider than the window.
