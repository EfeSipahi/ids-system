# Development plan: hand-written application profiles (A04)

Written: 25 October 2026. Approved by the user on the same day, after decisions F1–F11 were discussed one by one (main plan, section 11.25). Progress is recorded in section "Progress" at the end.

## Context

1. **Why.** The rule layer, the records and the dashboard are done; the last step was committed on 25 October 2026 as `dbc6338`.
   - The user's order puts hand-written application profiles (A04) next, with the decisions first.
   - A profile is a JSON file that describes one application. It gives two things:
     - what normal requests look like for it: an allow list of endpoints, parameters, cookies and headers;
     - which CRS checks are wrong for it: per-application rule exceptions.
2. **The first real case (I2).** The CSIC 2010 shop is flagged heavily by checks that are settings of that one application, not engine errors:
   - 920250 flags its Latin-1 text: 96 of 500 normal records at level 1;
   - 920451 flags the `Accept-Charset` header: all 500 at level 2;
   - 932350 flags its parameter names `pwd` and `id`: 221 at level 3.
3. **Decided by the user (25 October 2026), F1–F11:**

   | # | Decision |
   | --- | --- |
   | F1 | Profiles are JSON, read strictly (an unknown field is an error) with Go's standard library; a `note` field allowed for explanations. No new dependency |
   | F2 | One file per application, listed in the product config under `applications`. The config fingerprint covers the profile files |
   | F3 | A request gets the profile of the application that receives it: offline by Host (with port) plus an optional path prefix (the longest prefix wins); later by the proxy's route. Never by a client header such as `X-Profile`. `ids-offline -application NAME` forces one profile for a whole input |
   | F4 | Allow list. 4a an unknown endpoint is a finding. 4b an unknown parameter is a finding unless `"other_params": "allow"`. 4c types `string` (max length, pattern), `integer`/`number` (min/max), `boolean`, `enum`; patterns are Go regex (linear time). 4d paths: exact, `{name}` for one part, `*` at the end. 4e query, form (normal and multipart) and JSON body fields. 4f a repeated parameter is a finding unless `"repeat": true`. 4g `ids-offline -endpoints` lists the endpoints and parameters of a file and writes nothing. 4h cookies (written like parameters; an unnamed cookie is allowed) and header checks the profile names (an unnamed header is always allowed) |
   | F5 | Rule exceptions, each with a `reason`. Kind 1 a CRS setting; kind 2 a rule skips named targets; kind 3 a rule off for the application. 5a our JSON forms, not raw SecLang. 5b for the whole application for now. 5c rules of files 901 and 949 can't be excepted, with an understandable error. 5d a rule that doesn't run at the level is a note; an unknown rule ID is an error. 5e **option B:** one shared rule set; the application's exceptions are applied per request |
   | F6 | The profile result is separate from the CRS score (M10). Mode `monitor` (the default) records findings only; `alert` makes a profile finding an alert, labelled "profile" |
   | F7 | A broken profile stops the start, naming the file and the problem. No profile for a host means CRS only and `application: none`; this is not "incomplete" (M05). Optional `require_profile` (off by default): when on, a request for an unknown host is a finding |
   | F8 | A profile can mark parameters, cookies and path parts as secret. They are masked in records like `password` |
   | F9 | Records get optional application and profile fields (schema stays 1). The dashboard gets an application filter, profile findings on the detail page, each application's exceptions on the Rules page, and "without a profile" on the overview. It stays read-only (V2). The application name is not an ML input |
   | F10 | I2 is done now, by hand: the CSIC profile is the first profile and its test. It is written from the **training** normal records only and measured on validation and test. 932200/932236/932240 are examined first |
   | F11 | Paranoia level per application: the config's level is the default, a profile may set its own. `-paranoia-level` changes the default only. Request records carry the level used, and the Rules page shows statuses per application |

4. **Measured for 5e (25 October 2026, prototype, removed afterwards).** The prototype's diff is not part of the repository.
   - Option A (a copy per application) and option B gave the same results on 8 requests at all 4 levels.
   - Memory: one rule set keeps 13.4 MB, and B's tables take about 13 KB per application.
   - Start time: 217 ms per copy for A; tables for 8 applications take 0.036 ms.
   - Speed, in alternating rounds: the median difference was −3.2 % to +1.3 %, within the machine's noise.
   - Counted cost: 1,800–5,400 checks per request at ≤ 2.6 ns each, so at most 0.2–0.4 %.
5. **Stays the same:**
   - no new dependency;
   - M11 masking; M05, so a body that wasn't read is never reported as "missing parameters";
   - one writer per records folder;
   - the dashboard is read-only, with no inline script and `el()` only;
   - schema 1 (only optional fields are added);
   - no commit unless the user asks.

## Design

### Files and formats

1. **Product config** (`internal/config/config.go`), new optional fields:
   ```json
   "applications": [
     { "name": "csic-shop", "hosts": ["localhost:8080"], "paths": ["/tienda1/"], "profile": "../profiles/csic-shop.json" }
   ],
   "require_profile": false
   ```
   - Names are unique, and a host plus path prefix may belong to only one application; both are load errors.
   - Profile paths are relative to the config file.
   - `Fingerprint()` hashes every profile file too, like the rule files.
2. **Profile file**, read by the new package `internal/profile`. Example:
   ```json
   {
     "mode": "monitor",
     "paranoia_level": 2,
     "endpoints": [
       { "method": "GET", "path": "/tienda1/publico/anadir.jsp",
         "params": { "id": { "in": "query", "type": "integer", "required": true } } },
       { "method": "POST", "path": "/tienda1/publico/autenticar.jsp",
         "content_type": ["application/x-www-form-urlencoded"],
         "params": { "pwd": { "in": "body", "type": "string", "max_length": 64, "secret": true } } },
       { "method": "GET", "path": "/reset/{token}", "path_params": { "token": { "type": "string", "secret": true } } },
       { "method": "GET", "path": "/tienda1/imagenes/*" }
     ],
     "cookies": { "JSESSIONID": { "type": "string", "pattern": "[0-9A-F]{32}" } },
     "headers": [ { "name": "X-API-Key", "paths": ["/api/*"], "required": true, "max_length": 64 } ],
     "exceptions": [
       { "setting": "crs_validate_utf8_encoding", "value": "0", "reason": "the shop sends Latin-1 text" },
       { "rule": 932350, "skip": ["ARGS_NAMES:pwd", "ARGS_NAMES:id"], "reason": "parameter names, not commands" },
       { "rule": 920230, "off": true, "reason": "…" }
     ]
   }
   ```
   - `in` is one of `query`, `body` (form or multipart field) or `json` (a dotted path such as `user.name`, where `*` stands for any array index).
   - Patterns match the whole value.
   - `max_length` counts bytes after URL decoding.
   - `boolean` is one of `true`, `false`, `1`, `0`.
   - Endpoint order of precedence: an exact path, then `{name}` paths, then `*` paths. Two endpoints with the same method and pattern are a load error.
   - Paths are matched on the decoded path as received; `..` is not resolved. A trick path therefore becomes "unknown endpoint", which is the safe direction, because exceptions apply to the whole application, never to a path.
3. **Allowed settings (kind 1).** Only CRS's per-application policy settings from `crs-setup.conf.example`:
   - `allowed_methods`, `allowed_request_content_type`, `allowed_request_content_type_charset`, `allowed_http_versions`;
   - `restricted_extensions`, `restricted_headers_basic`, `restricted_headers_extended`;
   - `crs_validate_utf8_encoding`;
   - `arg_name_length`, `arg_length`, `total_arg_length`, `max_num_args`, `max_file_size`, `combined_file_sizes`, `allow_method_override_parameter`.
   - Anything else is an error that names the allowed list:
     - paranoia has its own field;
     - thresholds and scores wait for A06;
     - sampling and collections aren't supported;
     - `enforce_bodyproc_urlencoded` stays off by the user's decision of 16 October.
   - A test checks that every name is set by a `setvar` in `crs-setup.conf.example`, and that rule 901 only fills it when missing (`&TX:… @eq 0`), so the profile's value is kept.
4. **Error texts (5c and others).** Each one has the file, where in it, what is wrong and what to do. Example:
   ```
   profiles/shop.json: exceptions[1]: rule 949052 cannot be excepted.
   It is in REQUEST-949-BLOCKING-EVALUATION.conf, which adds up the attack score; without it this
   application would never raise an alert. Remove this exception, or except the attack rule that
   causes the false alarm.
   ```
   There is a similar text for file 901 ("sets up CRS: the threshold and the starting values").

### Engine: per-request exceptions (option B)

1. **`internal/engine/tuning.go`** (new), built on the prototype:
   - `type Tuning struct` holds the settings (with `blocking_paranoia_level` for F11), `skip [][]target` and `off []bool`, indexed by the position of a chain's first rule.
   - `func (rs *RuleSet) NewTuning(spec TuningSpec) (*Tuning, []string, error)` returns the notes for 5d and the errors for 5c (an unknown ID, a bad target, a protected file).
   - Rule files are known from `RuleStatus.Pos`; files 901 and 949 are recognised by their name prefix.
   - A rule excluded in the config (`exclude`) gets a note, not an error.
   - `func (rs *RuleSet) EvaluateWith(req, t *Tuning) *Result`. `Evaluate(req)` stays and equals `EvaluateWith(req, nil)`.
2. **Hooks**, as in the prototype:
   - `isRemoved` (`internal/engine/transaction.go`) also checks `t.off`.
   - `collect` (`internal/engine/targets.go`) applies `t.skip` on the first rule of a chain only, which is CRS behaviour for target exclusions.
   - A rule with no exception in the tuning keeps today's loop unchanged (the cost improvement from 5e).
3. **Indexes.** `rule.index` is set once in `Load` (`internal/engine/compile.go`). The rule set and every `Tuning` stay read-only during requests, so parallel use is unchanged (M21).
4. **Parsing targets.** `seclang.ParseVariables` is exported from `internal/seclang/variables.go:57`, so `"ARGS_NAMES:pwd"` is parsed exactly as rule files are. The result is compiled with `compileTarget` (`internal/engine/targets.go:123`).
5. **Rule statuses per application.** `RuleSet.StatusesFor(t)` returns the existing `RuleStatus` list plus `Off`/`OffReason`, `Skips` and the level, for the startup report and the records.

### Profile checker (`internal/profile`, new)

1. **`profile.go`:** the types, `Load(path)` (strict JSON decoding, as in `config.Load`), and validation with the error texts above. It turns the exceptions into an `engine.TuningSpec`.
2. **`match.go`:** endpoint matching for F4d, and choosing the application by host and path prefix for F3.
3. **`check.go`:** `Check(req *httpmodel.Request, app) Result` returns `Findings []Finding{Kind, Location, Message}`.
   - Kinds: `unknown_endpoint`, `method`, `unknown_param`, `missing_param`, `wrong_type`, `too_long`, `pattern`, `not_in_list`, `repeated_param`, `content_type`, `cookie`, `header`, `no_profile` (only with `require_profile`).
   - Messages never contain values (M11), for example "id: not an integer".
   - It uses `Parsed.Query`, `Parsed.BodyArgs` (form, multipart and `json.`-named fields), `Parsed.Cookies`, `DecodedPath` and `HeaderValues` from `internal/httpmodel/request.go`.
   - When `Status.Body` is not complete, body parameters aren't judged ("missing" and "unknown" are not reported). The result says `body not checked`, and the analysis is already marked incomplete (M05).
4. **Secrets (F8).** `SecretNames(app)` and `SecretPathParts(app, req)` feed the record masker per application.

### Wiring: ids-offline and the startup report

1. **`cmd/ids-offline/main.go`:**
   - For each example, choose the application (F3), or use the one given by `-application NAME`.
   - Run `rules.EvaluateWith(req, app.tuning)` and `profile.Check`.
   - Print the profile findings in the text and JSON output.
2. **Flags:**
   - `-paranoia-level` changes only the default (F11), and the startup report prints each application's level;
   - new `-endpoints` (F4g) prints method, path and count for each endpoint, and for each parameter its origin, count, maximum length and whether every value was an integer. Values are never printed.
3. **`result.Startup`:** a new `applications[]` with name, hosts, paths, mode, level, profile file and exceptions with notes.

### Records (F8, F9, F11): `internal/record`, `docs/records-format.md`

1. **`request` record**, new optional fields:
   - `application` (`name`, `paranoia_level`, `mode`);
   - `profile` (`findings[]`, `body_checked`);
   - `alert_by` (`["rules"]`, `["profile"]` or both, when `alert` is true).
2. **`decided_by`** gets the new value `"rule and profile layers"` when a profile was applied. It stays `"rule layer only"` otherwise.
3. **When a request gets a record:** `Wanted` also says yes when there are profile findings.
4. **Masking:** each application has its own masker, with `newMasker(extra, key)` (`internal/record/mask.go:70`) plus the profile's secret names. Secret path parts become `[masked]` in `path`, and their values join the clean-up pass.
5. **`start` record:** optional `applications[]`, with each application's level and exceptions (rule, kind, targets or setting, reason, note).
6. **`counts` record:** optional `no_profile`.
7. **API:** `Recorder.Add(req, res, prof)`, with a nil `prof` when there is no application.
8. **Golden tests:** the existing golden test is unchanged (no profile means no new fields). A new golden file covers a profiled request.

### Dashboard (F9, F11): `internal/dashboard`

1. **`store.go`:** `entry` gets `application` and `profileKinds`. `rulesPage(r)` uses the newest start record's `applications`.
2. **`query.go`:**
   - `parseFilter` gets `app` (a name, or `none`);
   - `/api/overview` gets the `no_profile` total;
   - `/api/rules?app=NAME` returns statuses for that application: Runs / Above level N / Excluded / Off for this application (with its reason), and the skipped targets.
3. **`app.js`:**
   - Alerts: an application filter (chip and select), and a column only when there is more than one application.
   - Detail: a "Profile" card (application, mode, level, findings) and `alert_by` badges.
   - Rules: an application selector, the per-application status and an exceptions list.
   - Overview: a "without a profile" note.
   - Engine: an applications table.

## Stages

Each stage ends with its tests passing and a progress entry in `docs/development-plan-profiles.md`.

1. **Documents of the decisions:**
   - new `docs/development-plan-profiles.md` (decisions F1–F11, stages, a progress section);
   - main plan: A04 status, I2, history 11.25;
   - `context.md`.
2. **Engine, option B:**
   - `tuning.go`, the hooks, `ParseVariables`, `StatusesFor`;
   - the errors for 5c and 5d, and the list of allowed settings;
   - the tests and the benchmark.
3. **Profile package:** loading, validation, matching and checking (F1–F4, F7, F8), with table tests for every finding kind.
4. **Config and ids-offline:**
   - `applications`, `require_profile` and the fingerprint;
   - F3 matching, `-application`, `-endpoints`, F11 levels;
   - the startup report and the output.
5. **Records:** the fields, the per-application masking, counts, both golden tests and `docs/records-format.md`. Also a new `docs/profile-format.md`, the profile contract, written in the style of `records-format.md`.
6. **Dashboard:** filter, detail card, Rules per application, overview, engine page, Go tests, and one batched browser check of the demo.
7. **CSIC profile (F10, I2):**
   - `tools/csic_to_examples.py --splits` reads `../ids-model/data/processed/http-mini-splits-v1/assignments.jsonl` (read-only). It writes the normal and anomalous examples per split: train 301/303, validation 99/98, test 100/99.
   - Run `-endpoints` on the normal training records: they have 13 endpoints, all on `localhost:8080`. Write `profiles/csic-shop.json` and `configs/csic-shop.json` by hand.
   - Examine 932200, 932236 and 932240 on the training records only. If they are real findings they stay. If an exception looks justified, it is shown to the user before it is added.
   - Measure levels 1–4 on validation and on test, normal and anomalous, before and after the profile:
     - flagged by the rules;
     - with profile findings;
     - unknown endpoints (does the profile cover endpoints it never saw?).
   - Run Coraza (`tools/coraza-reference`) with the same exceptions written as SecLang (`SecAction` settings, `SecRuleUpdateTargetById`, `SecRuleRemoveById`) on the same records. The rule results must be equal.
   - Write down the I2 condition: the training records are now tuned; validation and test are reported separately; the ML test set was already observed.
8. **Close:**
   - `docs/project-history.md`, `context.md`, main plan 11.25 results;
   - the full checks;
   - the commit only when the user asks.

## Rules for the work

1. Expected test values come from the data, the CRS files or Coraza, never guessed.
2. No new dependency and no inline script; `secrets_test.go` still checks for no `innerHTML`.
3. One batched browser-use call per check round, always on the dashboard tab only (switch to it and check its URL), never on the user's other tabs.
4. No commit unless the user asks. `proje_oneri_formu.docx` is never committed.

## Verification

1. **Option B is the same as option A, on all 5,072 CRS tests at levels 1–4.**
   - A is built from configure-time SecLang: an extra file with `SecRuleUpdateTargetById`, `exclude` and initial settings, as in the prototype.
   - B is built with `NewTuning` from the same exceptions.
   - Matches and scores must be identical.
2. **Isolation.** Application X has exceptions, Y has none. Y's results must equal plain `Evaluate` on all CRS tests, and X's tuning must never change a request routed to Y.
3. **Speed.**
   - `BenchmarkEvaluate` gets a tuned case.
   - The alternating A/B test from the prototype (run with an environment variable) must show a median within 1 %.
   - The counted extra checks for a rule without exceptions must be 0.
4. **Errors.** One test each, with the expected text:
   - an exception of a 901 or 949 rule;
   - an unknown rule ID;
   - a bad target;
   - a setting that isn't allowed;
   - an unknown field;
   - duplicate application names, and a host in two applications;
   - a profile file that doesn't exist.
   - A rule that doesn't run at the level gives a note.
5. **Profile checks:** a table test for every finding kind; a body that wasn't inspected gives no "missing" or "unknown" body findings; messages never hold a value.
6. **Secrets:** `TestNoSecretReachesTheDashboard` and `FuzzSecretsAreMasked` are extended with profile-secret parameters, cookies and path parts. No value may reach records, the API or pages.
7. **Numbers:**
   - without `applications`, every count is unchanged: the CRS summary gives 2,916 alerts at level 1, and the 1,000 CSIC records give 96 / 176 flagged at level 1;
   - with the CSIC profile, the stage 7 numbers equal Coraza's.
8. **Commands:**
   - `gofmt -l .`
   - `go vet ./...`
   - `go test ./...`
   - `go test -race ./internal/dashboard/... ./cmd/...`
   - `go test -race -timeout 60m ./internal/engine/... ./internal/record/... ./internal/profile/...`
9. **Browser** (one batched call, demo records with two applications): alerts filtered by application, the profile card, Rules per application with the exceptions and levels, the overview note, the engine page; no console errors, no overflow.

## Progress

| Stage | Status |
| --- | --- |
| 1. Documents of the decisions | Done 25 October 2026 |
| 2. Engine, option B | Done 25 October 2026 (notes 2–4) |
| 3. Profile package | Done 25 October 2026 (notes 5–7) |
| 4. Config and ids-offline | Done 25 October 2026 (notes 8–10) |
| 5. Records | Done 25 October 2026 (notes 11–13) |
| 6. Dashboard | Done 25 October 2026 (notes 14–16) |
| 7. CSIC profile (F10, I2) | Done 25 October 2026 (notes 17–18) |
| 8. Close | Done 25 October 2026 (note 19) |

### Notes from the work

1. **Speed numbers depend on the laptop's power profile.** On 25 October the machine was in `low-power` mode (`/sys/firmware/acpi/platform_profile`). An ordinary GET took 1.21 ms both at commit `c8bcab7` (16 October) and at `dbc6338`, against 0.55 ms recorded on 16 October. So the code did not get slower; only measurements made in the same session can be compared. The option A/B measurements above were all made in one session.
2. **Stage 2, the engine (`internal/engine/tuning.go`).**
   - `NewTuning` checks a spec against the rules: unknown or excluded rules, unreadable variables, a level out of range. Its notes name skips that change nothing.
   - `EvaluateWith` applies a tuning. `Evaluate` is `EvaluateWith` with none.
   - The skipped variables are added to a copy of the rule's own exclusion list once, when the tuning is made. So the loop over a rule's values is the same as before, and a rule without exceptions costs two pointer checks per request.
   - `seclang.ParseVariables` is exported, so profiles read variables exactly as rule files do.
   - The plan named a `StatusesFor` function. It was not needed: the start record carries each application's level and exceptions (stage 5), and the dashboard derives the statuses from them.
3. **A case the plan had not foreseen: a setup rule that overwrites a setting.** A deployment's setup file may have an active `SecAction` that sets the same CRS setting while each request runs. The CRS test setup does this with `crs_validate_utf8_encoding` (rule 900005). Its value would silently replace the application's. `NewTuning` now refuses such a setting and names the rule. These do not count as overwriting:
   - CRS's own defaults, which test `&TX:name` first;
   - setvars that add to the value they find, such as rules 901360 and 901370, which add JSON types to `allowed_request_content_type`.

   The profile test `TestSettingsAreCRSSettings` found those two rules in the CRS file.
4. **Checks of option B.**
   - **Same as configure time.** All 5,072 CRS tests ran at levels 1–4 through the shared rule set with a tuning, and through a rule set loaded with the same exceptions in SecLang (a `SecAction` before the setup rules, `SecRuleUpdateTargetById` after the rule files, and `exclude`). Matches, values, messages and every TX variable are identical. The exceptions changed the matches of 577 tests at level 1, 968 at level 2 and 999 at levels 3 and 4, so the comparison has power. The shared set was loaded at level 1 and the tuning set the level, which also checks F11.
   - **Isolation.** Eight goroutines mixed requests of an application with exceptions, one without, and none. Each got exactly its own result on all 5,072 tests.
   - **Speed.** `IDS_TIMING=1 go test -run TestTuningTiming -v ./internal/engine/` compares the two ways in alternating rounds, and `IDS_TIMING=control` compares two equal configure-time rule sets.
     - Three runs of the real comparison gave medians from −0.3 % to +1.8 %, on average +0.58 %.
     - The control gave −0.2 % to +1.3 %, on average +0.34 %: that much difference is the measurement itself.
     - So option B's own cost is about 0.2–0.3 %, as the count of its checks predicts. The plan's 1 % limit holds on average, but single medians reached 1.8 %, as they do for two equal rule sets.
5. **Stage 3, the profile package (`internal/profile`).**
   - `profile.go` holds the format and its strict reading.
   - `pattern.go` holds the paths.
   - `set.go` holds the applications, the choice of application by host and longest path prefix, and the exception policy.
   - `check.go` holds the request checks.
6. **Changes to the plan's details while building.**
   - Finding kinds are named by what is wrong, and `Location` says where in CRS's names (`ARGS_GET:id`, `ARGS_POST:json.user.name`, `REQUEST_COOKIES:sid`, `REQUEST_HEADERS:X-Key`, `REQUEST_FILENAME`). So `missing` and `repeated` serve parameters, cookies and headers alike, and `too_short` and `out_of_range` were added.
   - A parameter's `in` may also be `args` (the default): the query or a form body, as CRS's `ARGS`. The CSIC shop sends the same fields in the query of a GET and the body of a POST.
   - Endpoints take `method` or `methods`.
   - **Paths with `.` or `..` parts are unknown endpoints.** The application resolves them: `/img/../admin.php` is `/admin.php` there, although it fits `/img/*` as written. The plan only said that `..` is not resolved, and that would have let such a path through the allow list.
   - **Known limits:** file fields of multipart bodies are not checked. A secret path part can only be masked when the path fits an endpoint.
7. **Tests of stage 3.**
   - Every load error and exception error has its text checked, including both protected files (901, 949).
   - Choosing the application: host case, port, longest prefix, decoded path, no Host, and an `X-Profile` header that is ignored.
   - 34 request cases cover every finding kind. Messages are checked to hold no request value.
   - A body that was not read gives no `missing` or `unknown_param` findings.
   - Secret names and secret path parts are found.
   - `require_profile`, modes and levels.
   - The allowed settings are checked against the CRS files (`TestSettingsAreCRSSettings`), and all of them are accepted together on the product configuration (`TestEverySettingIsAccepted`).
8. **Stage 4, config and ids-offline.**
   - `internal/config`: `applications` and `require_profile`. Each profile path is relative to the configuration file and is read by `Load`. `require_profile` without applications is an error. The fingerprint also hashes each application's name and profile file. Without applications it is the same as at commit `dbc6338` (pinned in `TestFingerprintOfProfiles`).
   - `ids-offline` builds the applications with `profile.NewSet` after the rules. Each request gets the application of its Host header and path, or the one of `-application NAME`. It runs with `EvaluateWith` and that application's tuning, and is then checked against the profile.
   - The text and JSON output get `application` (name, level, mode), `profile` (findings, body checked) and `alert_by`, only when the configuration has applications. The startup report lists the applications with their exceptions and notes. `-summary` gets profile columns: requests with findings, unknown endpoints, profile alerts, and requests of no application.
   - `-endpoints` lists method, path and count, and for each parameter and cookie: where it came from, how many requests sent it, whether one request repeated it, its greatest length and whether all values were integers. It never shows values. It loads no rules and writes no records.
   - The shared types are in `internal/result`: `Application`, `Profile`, `AlertBy`, `AppStartup`. The records will use them in stage 5.
9. **Changes to the plan's details in stage 4.**
   - The exception status field is `no_effect`, not `note`. In JSON, the outer `note` would have hidden the exception's own `note`, the author's text.
   - Notes no longer start with the profile's path. They are printed under the application, which already names its profile.
   - `-endpoints` writes JSON list indexes as `*` (`items.*.id`), as a profile names them. A list of 100 items gives one line, not 100.
   - `-endpoints` cannot be combined with `-records`, `-summary` or `-application`, because it writes nothing and runs no rules.
   - A request of no application gets `application: none` with the configuration's level. It has a `profile` part only when `require_profile` gives it a `no_profile` finding.
10. **Tests of stage 4.**
    - Config: a relative profile path, a missing `profile`, a missing and a broken profile file, `require_profile` without applications, an unknown field, and the fingerprint.
    - ids-offline, on the product rules:
      - rule 930120 off for one application: the traversal request scores 25 there, against 30 for another host (TestTextOutput's request [2] has one 930120 match of 5 points);
      - a `too_long` finding in `alert` mode gives `alert_by: ["rules", "profile"]`;
      - `unknown_endpoint`, Host case, `application: none`;
      - no request value in the output.
    - Levels (F11), with CRS's tests of rule 942200, a level 2 rule: an application at level 2 passes, one at level 1 fails, and `-paranoia-level 2` raises only applications without their own level.
    - Errors: an unknown application, `-application` without applications, an exception of rule 949052, and wrong `-endpoints` use.
    - `-endpoints` on `path-traversal.json`: the counts and lengths were counted with Python's `urllib` from the same file. No value is printed.
    - A survey unit test covers JSON `*` indexes, a body that was not read, body types and cookies.
    - Without applications nothing changed: the CRS summary still gives 2,916 alerts at level 1, and the 1,000 CSIC records 96 normal / 176 anomalous flagged. `gofmt`, `go vet ./...` and `go test ./...` pass.
11. **Stage 5, records (`internal/record`).**
    - `Open(cfg, eng, statuses, apps)` and `Add(req, res, prof)`. `apps` and `prof` are nil when the configuration has no applications. `Wanted` also says yes for a profile finding.
    - Request records get `application` (name or `none`, the level used, the mode), `profile` (findings, `omitted` beyond 64, `body_checked`) and `alert_by`. `alert` is true for a rule alert, or for a profile finding in `alert` mode.
    - The start record gets `applications[]` and `require_profile`, and counts get `no_profile`.
    - Each application has its own masker: the profile's secret parameters by their whole ARGS name (`json.items.*.cvc` included), its secret headers, and its secret path parts (`/reset/[masked]`).
    - `docs/records-format.md` is updated. The new `docs/profile-format.md` is the profile contract.
12. **Changes to the plan's details in stage 5.**
    - `decided_by` is `"rule and profile layers"` only when the application's profile is in `alert` mode. The plan said "when a profile was applied". But in `monitor` mode the profile does not take part in the alert decision, so `"rule layer only"` stays true there. Recommendation: keep it so. The user can still change it.
    - `profile.SecretNames` became `SecretArgs` (ARGS names, `json.` in front of JSON fields) and `SecretHeaders`. The masker compares profile names whole, not as parts like the built-in names, so a secret `id` does not mask `idioma`.
    - **A masking gap found and closed (M11).** The new fuzz test found that a JSON body in `full` (with `full_requests` on) was written as received. A client may write a secret with JSON escapes (`\u003c`), and the clean-up pass only knows the decoded value. This was true before profiles too, for built-in names such as `password`. Now a JSON body with a secret field is written again, compact, with that field `[masked]`. A JSON body without a secret field stays exactly as received. Documented in `docs/records-format.md`, section 6.
13. **Tests of stage 5.**
    - A new golden record, `testdata/request-record-profile.json`, for a profiled request. The old golden record is unchanged, and so is a record without applications (`TestRecordWithoutApplications`).
    - One application's secrets do not reach another's records. Mode `monitor` keeps `decided_by: "rule layer only"`.
    - The recorder with applications: the start record, a profile-only alert, a monitor finding, `no_profile` counts.
    - `maskPath`, `argMatches`, and `maskJSON` (escapes, objects under a secret name, broken JSON, a body without secrets kept byte for byte).
    - `FuzzProfileSecretsAreMasked`: 582,137 runs without a leak. `FuzzSecretsAreMasked`: 901,916 runs.
    - ids-offline with `-records` and applications: 5 of 6 written, one alert by the profile only.
    - `gofmt`, `go vet ./...`, `go test ./...`, and `-race` on record, profile, result, config, ids-offline and dashboard pass.
14. **Stage 6, the dashboard (`internal/dashboard`).**
    - Alerts: an Application filter (a select, a chip, `app` in the address), shown once the records have applications; `none` is "No application". The list gets an Application column when there is more than one application, and a hollow diamond "Profile" badge in the score cell for profile findings. With the Application column, the request cell leaves out the host of an application's requests, because the application stands for it.
    - Detail page: an "Application and profile" card (application, mode, level with the configuration's level when it differs, body checked, findings, omitted findings), "Alert by" in the Decision card and the summary. The rule card is now called "Rule findings".
    - Rules: an application selector with each application's level. A choice shows that application's statuses (its level, "Off for" the application, skipped variables, `no_effect` notes) and an "Exceptions of" card, and counts only that application's records. An unknown application is a 400 answer.
    - Overview: "N of no application: the rules only, no profile" under the requests analysed, from the counts' `no_profile`.
    - Engine: an Applications table (hosts, paths, profile, mode, level, exceptions with a link to the Rules page, notes).
    - The footer says that alerts are decided by the rules and by profiles in `alert` mode.
15. **Found by the browser check and fixed.**
    - The Application filter from an address (`/alerts?app=csic-shop`) showed every record: on loading, the empty list of choices was taken for "unchanged", so the chosen application was not yet a choice and the first request went without it. The engine page links use such addresses.
    - With both Status and Application columns, the request cell was about 66 px wide. Narrower Client, Application, Attack groups and Rules columns in that case, and the shorter request text, give it 142 px; without the Status column it has 206 px.
    - A stray comma after "Runs" in every Rules status cell: `el()` flattened children only one level, so an empty nested list became the text ",". It now flattens all levels.
    - The Engine table broke host and file names inside words, and ran the notes together. Hosts and paths are one per line, names are not broken, and each note has its own line.
    - "1 are off" is now "1 is off", and "Off for the application" is offered only when an application is chosen.
16. **Tests and checks of stage 6.**
    - Go: the filter by application (`none` included, a long name refused), a run without applications counting as `none`, the overview's `no_profile`, the Rules statuses and fired counts per application, the API (`/api/rules?app=`, 400 for an unknown application), and the engine page. `TestNoProfileSecretReachesTheDashboard`: a profile's secret parameters, JSON fields and headers do not reach the API or the pages; the rules matched them, so they were recorded.
    - The browser check, in two batched rounds, on demo records of two applications made by `ids-offline` (`csic-shop` at level 1 in `monitor` mode, `local` at level 2 in `alert` mode, CRS tests of other hosts as `none`): filters of each application gave only its rows (734, 54 and 2,170 records), the chip removes the filter, both detail cards, the Rules statuses ("Off for local" for 930120), the Engine table, dark and light. No console or CSP errors, no page wider than the window, nothing out of its card.
    - `gofmt`, `go vet ./...`, `go test ./...`, and `go test -race ./internal/dashboard/... ./cmd/...` pass.
17. **Stage 7 so far: the CSIC profile, from the training split only.**
    - `tools/csic_to_examples.py --splits` writes the six files of ids-model's split v1 (read only): train 301 normal / 303 anomalous, validation 99 / 98, test 100 / 99. Without `--splits` its output is byte for byte the same as before.
    - `-endpoints` on the 301 training normal requests: 13 endpoints, all on `localhost:8080`, one cookie (`JSESSIONID`).
    - `profiles/csic-shop.json` (allow list, types, secrets, mode `monitor`, level 2 and exceptions E1–E3 since the user accepted them (note 18)) and `configs/csic-shop.json` (the product configuration with the `csic-shop` application). The profile's `note` gives the rules it was written by. It gives 0 findings on the 301 training normal requests, and the rule results are those without a profile.
    - Rules on the training normal requests, without exceptions, levels 1–4: 53, 301, 301, 301 flagged. Causes: 920250 (Latin-1 text, 151 requests), 920451 (`Accept-Charset`, all 301 from level 2), 920272 and 920273 (bytes above 126, levels 3 and 4), 932350 (parameter names `pwd` and `id`, level 3).
    - The three rules of F10, on training normal at level 2: 932200 in 6 requests (addresses such as `c/ … 4?g`, where the data set turned `º` into `?`, so `c/` and `?` look like a shell wildcard), 932236 in 3 (the surname `Pico`, also a Unix editor, and the province `La Rioja`), 932240 in 1 (a password with `$r`).
    - Measured on the training split only (301 normal, 303 anomalous), with draft exceptions outside the repository. Each cell gives two counts: normal requests flagged by the rules (false alarms) and anomalous requests flagged by the rules.

      | Exceptions in the draft | Level 1 | Level 2 | Level 3 | Level 4 |
      | --- | --- | --- | --- | --- |
      | none | 53 false alarms, 106 anomalous | 301, 303 | 301, 303 | 301, 303 |
      | E1: `crs_validate_utf8_encoding` = 0 | 0, 73 | 301, 303 | 301, 303 | 301, 303 |
      | E1 and E2: also `restricted_headers_extended` = "" | 0, 73 | 10, 97 | 211, 230 | 280, 278 |
      | E1, E2 and E3: also 932350 skips `ARGS_NAMES:pwd`, `ARGS_NAMES:id` | 0, 73 | 10, 97 | 156, 201 | 230, 266 |

      With E1 and E2, the 10 normal requests left at level 2 are exactly the 932200, 932236 and 932240 cases above.
    - The allow list alone, on the training anomalous requests at level 1: findings in 189 of 303 (unknown parameter 95, wrong type 30, unknown endpoint 30, not in list 17, pattern 8, too long 6, method 3); 118 of them are not flagged by the rules. On training normal: 0. These are training numbers and so optimistic.
    - The user then accepted the recommendations (note 18). Validation and test were not run before that, so that they were measured once, with the final profile.
18. **Stage 7: the final CSIC profile, measured on validation and test.**
    - **Decided by the user on 25 October 2026:** the three exceptions E1, E2 and E3 are added, each with its reason in the profile. 932200, 932236, 932240, 920272 and 920273 get no exception. The shop runs at paranoia level 2, in `monitor` mode.
    - **One correction, found on training data before validation and test were run:** `configs/csic-shop.json` first gave the shop the path prefix `/tienda1/`. Two training anomalous requests, scanner probes for `/asf-logo-wide.inc` and `/_cti_pvt/service.cnf`, were then "no application" and ran at level 1 without a profile. A path prefix is for applications that share a host, and this host serves only the shop, so the prefix was removed. Every path of `localhost:8080` now belongs to the shop, and those probes are unknown endpoints.
    - **Validation** (99 normal, 98 anomalous). "Before" is the rules alone at level 1, the best setting without a profile: from level 2 up, every request is flagged because of `Accept-Charset`. "After" is the shop's configuration, level 2 with the profile.

      | | Before | After |
      | --- | --- | --- |
      | False alarms: normal requests flagged by the rules | 13 of 99 | 5 of 99 |
      | Normal requests with a profile finding | – | 1 of 99 |
      | Anomalous requests flagged by the rules | 33 of 98 | 27 of 98 |
      | Anomalous requests with a profile finding | – | 63 of 98 |
      | Anomalous requests flagged by the rules or with a profile finding | 33 of 98 | 73 of 98 |

    - **Test** (100 normal, 99 anomalous), the same way:

      | | Before | After |
      | --- | --- | --- |
      | False alarms: normal requests flagged by the rules | 30 of 100 | 3 of 100 |
      | Normal requests with a profile finding | – | 0 of 100 |
      | Anomalous requests flagged by the rules | 37 of 99 | 30 of 99 |
      | Anomalous requests with a profile finding | – | 64 of 99 |
      | Anomalous requests flagged by the rules or with a profile finding | 37 of 99 | 74 of 99 |

    - In `monitor` mode only the rules make alerts. The last row shows what `alert` mode would give.
    - **With the profile, by level** (the profile's level changed in copies outside the repository; everything else the same). Each cell: false alarms by the rules / anomalous flagged by the rules / anomalous flagged by the rules or with a profile finding.

      | Level | Validation | Test |
      | --- | --- | --- |
      | 1 | 0 / 19 / 67 | 0 / 24 / 70 |
      | 2 | 5 / 27 / 73 | 3 / 30 / 74 |
      | 3 | 50 / 61 / 82 | 50 / 69 / 87 |
      | 4 | 68 / 83 / 97 | 70 / 91 / 99 |

      Without the profile, every level from 2 up flags all 99 + 98 validation and all 100 + 99 test requests.
    - **What is left.** The false alarms at level 2 are the rules that were kept on purpose: 932200 (validation 3, test 1), 932236 (validation 2), 932240 (test 2). The one normal profile finding is an image under `/tienda1/miembros/imagenes/` that the training requests never asked for; the allow list names exact paths. From level 3, 920272 flags about half of the normal requests for their Latin-1 bytes.
    - **Why the rules alone catch fewer anomalous requests at level 1 than before (33 to 19, 37 to 24).** E1 removed the matches of 920250 on Latin-1 text. Those flagged normal and anomalous requests alike, for the text, not for an attack.
    - **Coraza.** Coraza v3.8.1 (`tools/coraza-reference`) ran the same rule files with the exceptions written in SecLang: `SecAction` rules 900950 and 900255 for the settings, placed after `crs-setup.conf.example` as it describes, and `SecRuleUpdateTargetById 932350 "!ARGS_NAMES:pwd|!ARGS_NAMES:id"` after the rule files. Coraza refuses an empty `setvar` value, so `restricted_headers_extended` is a single space there; the effect is the same, because no `/name/` text is within either. The results were compared request by request, the way `internal/engine/reference_test.go` does (rules 911–944 and 949110, places, counts, score).
      - At each level 1–4, all 396 validation and test requests: no difference.
      - On 2 anomalous requests with Latin-1 values, Coraza counts one rule more often. This is the known `utf8toUnicode` difference that the reference test allows. Both engines flag both requests, so every count above is also Coraza's.
      - The comparison can see a missing exception: against our results without the exceptions, all 396 requests differ at level 2.
    - **The I2 condition.**
      - The profile and its exceptions were written from the training split only. The training numbers are therefore tuned and are not a measurement.
      - Validation and test were run once, with the final profile, and nothing was changed after seeing them.
      - The ML test set of ids-model had already been observed (main plan, section 2.1, item 5). So the test numbers are a first measurement of this profile, not a blind test of the whole project.
      - All 1,000 CSIC records come from one generated application. A false-positive rate that holds elsewhere needs other normal traffic (A07).
    - `TestCSICShopConfiguration` (ids-offline) checks that the repository's CSIC configuration and profile load with level 2, the three exceptions and the 932350 note. The CSIC records belong to ids-model, so the measurements are not repository tests.
    - **To repeat it:** `python3 tools/csic_to_examples.py --splits --out DIR`, then `ids-offline -config configs/csic-shop.json -requests DIR/csic-validation-normal.json -summary` (and the other files). For Coraza, see the comments of `tools/coraza-reference/main.go`, with a configuration that adds the two SecLang files above.
19. **Stage 8, the close.**
    - `docs/project-history.md` has a new section 4.8 and updated numbers, timeline, problems and commits. The main plan has section 11.26 and an updated starting summary and A04 status. `context.md` is updated.
    - Rechecked with a fresh build, without applications: 2,916 alerts on the CRS tests at level 1, and 96 normal / 176 anomalous CSIC records flagged, as before.
    - `gofmt -l .` (nothing), `go vet ./...`, `go test ./...`, `go test -race ./internal/dashboard/... ./cmd/...` and `go test -race -timeout 60m` on the engine, record, profile, config and result packages: all pass. The race run of the engine package took 29 minutes.

