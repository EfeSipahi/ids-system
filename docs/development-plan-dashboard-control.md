# Development plan: a dashboard that controls the IDS

Written: 21 November 2026, at the user's request: "everything the command line and the configuration files can do, the dashboard should do too, without confusing its users". Every question has a code (W1, W2, …) and numbered options; the user reviewed them one by one on 21 November 2026, and each answer is written under its question.

It replaces the order of [dashboard-roadmap.md](dashboard-roadmap.md), whose parts it takes in, and starts over on how the dashboard is organised: earlier ideas (an application selector at the top, a settings page per application) are options here, not givens.

## 1. Context

1. What exists (21 November 2026): a dashboard that shows records, alerts, rules and the engine; marks on alerts; users with roles; a change log; a test tab for one request; a navigation panel on the left. It changes nothing of the IDS: its settings are edited by hand in files, and `ids-live` reads them only at its start.
2. What the command line and the files can do that the dashboard can't, in full: section 2.
3. What confuses users, as found in the conversations of 19–21 November:
   - a hidden choice that changes what every page shows (an application chosen once, then forgotten): a page shows part of the data without saying so;
   - a settings page whose reach is unclear: one application, every application, or the default;
   - two places to change the same thing.
4. What others do, read on 21 November:
   - Fastly's Next-Gen WAF: an overview across all sites (a "corp"), and a dashboard per site; the site is chosen from a menu ([managing sites](https://www.fastly.com/documentation/guides/next-gen-waf/managing-sites/));
   - Cloudflare's WAF: security events and settings per zone (per domain), and an account-wide view for Enterprise ([Security Events](https://developers.cloudflare.com/waf/security-events/));
   - BunkerWeb: settings per service, with a web UI over ModSecurity and CRS ([docs](https://docs.bunkerweb.io/1.6.3/web-ui)).

## 2. What the dashboard can't do today

| # | Where today | What | Dashboard today |
| --- | --- | --- | --- |
| 2.1 | Product configuration | Rule files loaded (`files`) | Shows only |
| 2.2 | Product configuration | Rules off for everyone (`exclude`) | Shows only |
| 2.3 | Product configuration | Default paranoia level | Shows only |
| 2.4 | Product configuration | Body limit (`request_body_limit`) | No |
| 2.5 | Product configuration | Records: file size, files kept, full requests, extra secret names (the folder too) | No |
| 2.6 | Product configuration | Applications: name, hosts, paths, profile file | Shows only |
| 2.7 | Product configuration | `require_profile` | No |
| 2.8 | Product configuration | Live input: socket, workers, queues, frame limit | Shows the socket |
| 2.9 | Profile | Mode, own paranoia level | Shows only |
| 2.10 | Profile | Exceptions: rule off, rule skipping places, CRS setting | Shows only |
| 2.11 | Profile | Endpoints, parameters, cookies, headers, secret marks | No |
| 2.12 | `ids-offline` | Analyse request files; summary; CRS expectations; write records; replay | One request in the Test tab, nothing kept |
| 2.13 | `ids-offline -endpoints` | Endpoints and parameters of traffic, to write a profile | No |
| 2.14 | `ids-live` | Start, stop, restart; read new settings | No; a restart is the only way to read new settings |
| 2.15 | `ids-dashboard` | First admin; recovery | No (should stay so, W21) |
| 2.16 | `dashboard.json` | Address, certificate, folders, idle time, Test tab configurations | No |
| 2.17 | Caddyfile | Sites, `ids_copy` settings, trusted proxies | No |
| 2.18 | Records folder | Delete, prune, export | No |

Development tools (the lab, `tools/`, the Coraza comparison, the Go tests) and building Caddy (`xcaddy`) are not product controls and stay outside.

## 3. Questions

### A. How the dashboard is organised

W1. How a user chooses which application a page is about.

1. A selector at the top of the navigation, kept between pages: every page follows it.
2. No hidden choice. Pages that show what happened (overview, alerts, clients, endpoints) have an application filter in their own filter bar and in their address, "All applications" by default, as the alerts list has today. Configuration is reached through an Applications section with a page per application.
3. Both: the selector, and the application named again in each page's filters.

Recommendation: 2. A filter that is on the page, next to the period, can't be forgotten, and a shared link carries it; a hidden selector is the confusion of section 1.3. Fastly's site menu suits sites run like separate products; here applications share one engine and one rule set, and the view across all of them stays the starting point.

Decided by the user on 21 November 2026: 2.

W2. The groups of the navigation panel.

1. By what one looks at:
   - Monitor: Overview, Alerts, Clients, Endpoints
   - Applications: the list, then a page per application
   - Rules: the catalogue, then a page per rule; Own rules (later)
   - Tools: Test a request, Analyse files
   - System: Settings, Engine and live input, Records
   - Administration: Users, Change log, Dashboard settings
2. By what one does: View (every page that shows) and Change (every page that changes), with the same pages split in two.

Recommendation: 1. A user looks for "the shop" or "rule 942100", not for "change". Every object has one page, and that page shows its state and, for those allowed, its controls; so there is one place to change a thing (section 1.3).

Decided by the user on 21 November 2026: 1.

W3. What an application's page holds.

1. Tabs on one page, with the application's name in the title: Summary (its alerts, false positives, level, mode, hosts), Rules (every rule's status for it: on, off, skipping places; its level), Profile (endpoints, parameters, cookies, headers), Settings (hosts, paths, mode, level, remove), History (its changes).
2. Separate pages in the navigation for each part, each with an application menu.

Recommendation: 1. The application stays in view on every tab, and nothing on its page can reach another application.

Decided by the user on 21 November 2026: 1.

W4. Where settings for every application live.

1. One page, System › Settings, titled "Settings for every application", in sections: Rules (rule files, the default level, rules off for everyone), Analysis (body limit, requests of no application), Records, Live input. Each section says what an application's own setting overrides.
2. On the Applications list, as an "All applications" entry.

Recommendation: 1, which keeps "every application" out of the Applications section and so away from one application's controls.

Decided by the user on 21 November 2026: 1, after asking why and what Records and Live input hold. The answer: most of these settings belong to the whole IDS, not to applications; an "All applications" entry would look like one more application and leave unclear whether its values are defaults or forced; one page for the widest reach also makes the password asked again (W10) a visible boundary. Records: the folder (shown only), file size (10 MB), files kept (10), full requests (off, R4), extra secret names; later how long marks are kept. Live input: the socket (shown only, it is Caddy's too), workers (2), the queue in copies (1,000) and in MB (64), the largest copy (16 MB), shown with what the lab measured with them.

W5. Naming the reach of every change.

1. Every control, every preview and every change log entry names its reach in words: "Switch off for csic-shop", "Switch off for every application", "Default level (for requests of no application and applications without their own)".
2. Only the page title names it.

Recommendation: 1; it is what makes W3 and W4 safe.

Decided by the user on 21 November 2026: 1, after an example: on the shop's Rules tab the button says "Switch off for csic-shop", the preview "For csic-shop only: 151 alerts would no longer be alerts; other applications are not affected", the change log "admin switched rule 920250 off for csic-shop", and the default level's field on System › Settings names whom it applies to and which applications have their own.

W6. A rule's page and an application's Rules tab.

1. The rule's page shows its status for every application in one table, and has one control: off for every application. An application's own control (off, skip, back on) is on that application's Rules tab, which links to the rule's page and back.
2. The rule's page has every control, for each application in its table.

Recommendation: 1: one place per change (section 1.3). The rule's page answers "where is this rule off and why", the application's tab answers "what runs for this application".

Decided by the user on 21 November 2026: 1.

### B. Changing things safely

W7. How a change is made.

1. At once: each control saves when used, after a preview.
2. Pending changes per object: an application's (or the global settings') changes collect as pending, are shown together with one preview of their effect, and are applied together with one reason, as one version.

Recommendation: 2. Several related changes (a level and two exceptions) are judged and undone together, and `ids-live` reloads once.

Decided by the user on 21 November 2026: 2. Pending changes are kept in the dashboard's state folder, so they survive closing the page, and are kept per object (an application, or the settings for every application); a pending change can be dropped before it is applied.

W8. The preview.

Records keep what each rule matched and the score, not whole requests (R4). So a change that takes detection away (a rule off, a rule skipping a place) can be worked out exactly from the records: drop the findings it removes, add up the score again, and see which alerts would no longer be alerts. A change that adds detection (a higher level, a rule back on, a new allowed value in a profile) can't: the requests themselves are needed.

1. Changes that take detection away: worked out from the records of their reach: how many alerts it would remove, how many of those are marked real attack (a warning) or false positive, with the rules and requests in question. Changes that add detection: run on request files when some are given (the Analyse files tool, W14), otherwise the preview says it can't tell.
2. A preview only for changes that take detection away.

Recommendation: 1; the preview always says what it could and couldn't try.

Decided by the user on 21 November 2026: 1. The warning when a change would hide alerts marked real attack comes first in the preview.

W9. Who may change what.

1. Admins change everything; analysts and viewers see the controls' state only.
2. Analysts may propose a change (from a false positive: "skip this place for this rule"), which waits in a list until an admin applies it or turns it down; admins change everything.
3. Analysts apply exceptions themselves; admins the rest.

Recommendation: 2. Analysts find the false positives (they mark them); an exception hides detection, so a second person looks at it. Microsoft Sentinel likewise keeps rule changes from its incident handlers.

Decided by the user on 21 November 2026: 2. A proposal waits on the application's page and in a list of proposed changes for admins, until an admin applies it or turns it down with a reason; both are written to the change log.

W10. The password again before a change.

1. For every change.
2. For applying changes to settings for every application, rule files, users and the dashboard's own settings; not for an application's changes.
3. Never, beyond the login.

Recommendation: 2: the widest reach asks again, the everyday work does not.

Decided by the user on 21 November 2026: 2. Applying one application's changes, also an analyst's proposal for one application, does not ask; wrong passwords count with the login's, as for user changes today.

W11. Versions and undo.

1. Every applied change keeps the files it replaced, as a version in the dashboard's state folder, with who, when and why; "Undo" applies the version before, as a new change, so the history is never rewritten.
2. Undo only the last change.

Recommendation: 1.

Decided by the user on 21 November 2026: 1. Undoing an older change goes through the same preview as any change, and when a later change touched the same file, the preview shows what would be lost.

W12. Which files the dashboard writes.

1. The product configuration that `ids-live` runs, named in `dashboard.json` (a new setting `ids_config`), and the profiles it lists, in place; under a lock against a second editor; checked by the same readers the IDS uses before anything is written. This ends "the dashboard writes only its own state folder" (V2, C1 of the marks plan).
2. A copy owned by the dashboard, in its state folder, which `ids-live` is then told to read.

Recommendation: 1. There stays one configuration, which the command line and the dashboard both change, and a hand edit shows up in the dashboard as it is.

Decided by the user on 21 November 2026: 1. Files in this repository are tracked by git, so changes made from the dashboard show as changed files until committed; a dashboard can be pointed at a configuration outside the repository to avoid that.

W13. How `ids-live` takes a change.

1. It watches its configuration, rule files and profiles, and when their fingerprint changes it prepares the new rule set beside the old one, switches without dropping a copy, and writes a new start record (a new run with the new fingerprint), which the dashboard shows as the change being live. A configuration that can't be read leaves the old one running, and the error is shown.
2. A signal (SIGHUP) or a command over a control socket, sent by the dashboard.

Recommendation: 1: it needs no channel between the two programs, and it also takes the command line's and hand edits'.

Decided by the user on 21 November 2026: 1. The workers keep analysing with the old rule set while the new one is prepared, so no copy is lost; the dashboard shows "applied, live since …" from the new run; the socket path is the one setting that still needs a restart, since Caddy's side changes with it.

### C. What the command line can do, in the dashboard

W14. Analysing request files (`ids-offline`).

1. Tools › Analyse files: upload request files, or choose from a configured folder; choose the configuration, level and application; see the summary, each request's findings, and whether CRS's expectations are met; optionally write the results as a run of records, on the analysis time or as a replay (`-replay`). It runs in the background, one at a time, with a size limit, and can be stopped.
2. Only the summary, nothing written.

Recommendation: 1, with writing records and replays for admins.

Decided by the user on 21 November 2026: 1. One analysis at a time, in the background, with a size limit (about 50 MB of files, to be measured), progress and a Stop button; uploaded files are kept only until their result has been seen; the same numbers as `ids-offline -summary`; writing records, on the analysis time or as a replay, for admins only. It also gives the preview of changes that add detection (W8) its requests.

W15. Profile suggestions from traffic (`-endpoints`).

1. On an application's Profile tab: endpoints, methods and parameter names seen in uploaded files and in its records, next to what the profile allows; each one can be added to the pending changes.
2. Only from uploaded files.

Recommendation: 1. Records keep paths, methods and query parameter names; bodies give names only from uploaded files.

Decided by the user on 21 November 2026: 1. A suggestion seen only in alerts is marked as such, so that an attack's path does not become allowed by a careless click; each one added to the pending changes gets a type chosen (text, number, one of a list).

W16. Editing a profile.

1. Forms for every part (endpoints, parameters with their types and limits, cookies, headers, secret marks).
2. A JSON editor that checks as one types, with the suggestions of W15.
3. Forms for the common parts (mode, level, hosts, paths, exceptions) and the JSON editor for endpoints and parameters, forms for those later.

Recommendation: 3: everything can be done from the first day, and forms come where they are used most.

Decided by the user on 21 November 2026: 3. The JSON editor checks as one types with the reader the IDS uses, offers the suggestions of W15, and its changes go through the same pending changes, preview and undo.

W17. `ids-live` itself.

1. Its state on System › Engine and live input: running or not, its run and fingerprint, copiers connected, queue fill, drops per minute. Start and stop stay with `ids-dashboard-ctl`-like tools or systemd; a change reaches it by W13.
2. Start, stop and restart from the dashboard, through a small supervisor program.

Recommendation: 1 for now: a dashboard that starts programs needs rights the dashboard should not have; 2 belongs with "controlling the system" (W22).

Decided by the user on 21 November 2026: 1, after asking for more. The page shows whether `ids-live` runs, its run and fingerprint and whether the last change is live, copiers connected, queue fill and drops; when it does not run, the command that starts it. An `ids-live-ctl` script, like `ids-dashboard-ctl`, starts and stops it; a Stop button on a web page would be a switch that turns detection off, so buttons wait for W22.

W18. Caddy.

1. The dashboard shows the copier's state and writes the `ids_copy` block for an application, to copy into the Caddyfile.
2. The dashboard changes the Caddyfile and reloads Caddy through Caddy's admin API.

Recommendation: 1 for now, for the reason of W17.

Decided by the user on 21 November 2026: 1. The `ids_copy` block shown on an application's Settings tab carries its name and the socket, with a Copy button; a wrong change to Caddy could take the protected website itself down, so changing Caddy waits for W22.

W19. Records.

1. System › Records: the files, the runs with their sizes; export of the filtered records as CSV or JSON Lines (also from the alerts list); a run deleted, or records older than a date, after a confirmation, written to the change log; how long records and marks are kept (C6 of the marks plan).
2. Export only.

Recommendation: 1, deleting for admins only.

Decided by the user on 21 November 2026: 1. Export as CSV or JSON Lines, also from the alerts list; deleting a run or everything older than a date, admin only, with the password asked again, written to the change log, and only while no program writes the records folder (`ids-live` holds its lock while it runs, so the page says to stop it first); a maximum age for records and for marks, applied once a day, which settles C6 of the marks plan.

W20. The dashboard's own settings.

1. Administration › Dashboard settings: idle time, the Test tab's configurations, the folder of example files, extra names for its certificate. Its address and certificate files stay in `dashboard.json`: a mistake there locks everyone out of the page that could fix it.
2. Everything, with a safety net: a new address or certificate falls back to the old one unless confirmed from it within a minute.

Recommendation: 1.

Decided by the user on 21 November 2026: 1. The page holds the idle time, the Test tab's configurations and its folder of example files, and extra names and addresses for the dashboard's own certificate (for example an address reached through a VPN), after which the certificate is made again; the address, the certificate files and the two folders stay in `dashboard.json`.

W21. What stays on the command line, on purpose.

1. Creating the first admin and recovering when no admin can log in; starting and stopping the dashboard; its address and certificate (W20); building Caddy; the development tools.

Recommendation: 1: these are the ways back in when the dashboard itself can't help.

Decided by the user on 21 November 2026: 1, the list as it stands: the first admin and recovery; starting and stopping the dashboard; its address, port, certificate files and folders (W20); starting and stopping `ids-live` (W17) and changing Caddy (W18) until W22; building Caddy; the development tools.

W22. Controlling the system (start and stop `ids-live`, change Caddy, an installer; idea I3).

1. A later plan, after this one, with its own decisions.
2. In this plan.

Recommendation: 1.

Decided by the user on 21 November 2026: 1: a later plan, with its own decisions on who may use these controls, the safety rules, and how the dashboard gets the rights.

### D. Views

W23. Pages that only show.

1. Monitor › Clients: a page per client address, everything it sent over time, its alerts and marks (the place for blocking later, K4). Monitor › Endpoints: the paths attacked most, per application. Both with the application filter of W1.
2. Clients only.

Recommendation: 1.

Decided by the user on 21 November 2026: 1. Both pages only read; a client's page is where blocking an address would go later (K4).

### E. Order and the night run

W24. Stages.

1. In this order, each with its tests, a browser round and a note:
   1. the organisation, showing only: the navigation of W2, the filters of W1, the Applications list and an application's page with its Summary tab, the rule's page, System › Engine and live input with `ids-live`'s state (W17);
   2. the foundations of change: versions, pending changes, the preview from records, `ids-live` watching its files, and an `ids-live-ctl` script (W7, W8, W11–W13, W17);
   3. the changes: an application's Rules tab and Settings tab (with its `ids_copy` block, W18), the rule's "off for every application", System › Settings, analysts' proposals and the admins' list of them, the password asked again (W3–W6, W9, W10);
   4. the profile: suggestions and editing (W15, W16);
   5. Analyse files, and with it the preview of changes that add detection (W14, W8);
   6. System › Records with export, deleting and retention (W19), the dashboard's settings (W20), Clients and Endpoints (W23);
   7. the close: documents, full checks.
2. Another order, which the user names.

Recommendation: 1: what everything needs comes first, and each stage leaves a working dashboard.

Decided by the user on 21 November 2026: 1, the seven stages as listed. Until stage 5, the preview of a change that adds detection says it can't tell (W8).

W25. The night run.

1. All stages, one after the other, without stopping, as with the test tab; each stage's tests must pass before the next starts; a stage that fails stops the run, and the morning report says where.
2. Stages 1–3 in the night, the rest after the user has looked at them.

Recommendation: 2: stages 1–3 change how the dashboard is organised and start writing the IDS's files; the user should see them before the profile editor and file analysis are built on them.

Decided by the user on 21 November 2026: 1, all seven stages without stopping. Each stage's tests and browser round must pass before the next starts; a stage that fails stops the run there. The morning report gives, per stage, what was built, its test results, screenshots of the new pages, and every choice made along the way that the plan did not settle, listed for the user's approval.

W26. Commits during the night.

1. A commit after each stage, pushed only when the user says so in the morning.
2. No commit; the user looks at everything first.
3. A commit and a push after each stage.

Recommendation: 1: every stage can be looked at, or taken back, on its own.

Decided by the user on 21 November 2026: 1. Each commit holds one stage's code, tests and notes; nothing is pushed until the user says so; `proje_oneri_formu.docx` and the course forms are never committed.

## 4. Verification (for every stage)

1. `gofmt -l .`, `go vet ./...`, `go test ./...`; `go test -race` for the packages changed.
2. Every route as no login, viewer, analyst and admin.
3. For every change: written only after its check passed; its version kept; undo restores the files byte for byte; the change log has one entry; `ids-live` runs the new fingerprint (a new run), or keeps the old one with the error shown when the new one can't be read.
4. The IDS's results unchanged where nothing was changed: CRS 2,916 of 5,072 flagged at level 1, CSIC 96 / 176, the CSIC profile's numbers.
5. A browser round per stage, as each role, light and dark, at 1366 and 1920 px: no confusion of reach (every change names it), nothing wider than its space, no console errors.
6. The records folder and the user's own configuration untouched by the checks: every check runs on copies in a temporary folder.

## 5. Progress

| Stage | Status |
| --- | --- |
| Decisions W1–W26 | Decided 21 November 2026 |
| 1. The organisation, showing only | Done, 21 November 2026 (note 1) |
| 2. The foundations of change | Done, 21 November 2026 (note 2) |
| 3. The changes | Not started |
| 4. The profile | Not started |
| 5. Analyse files | Not started |
| 6. Records, the dashboard's settings, views | Not started |
| 7. The close | Not started |

## 6. Notes of the night run

Each stage's note says what was built, how it was checked, and the choices made along the way that the decisions above did not settle. Those choices wait for the user's approval in the morning.

1. Stage 1, the organisation, showing only.
   1. Built:
      - the navigation of W2, with the pages that exist so far: Monitor (Overview, Alerts), Applications, Rules, Tools (Test a request), System (Engine and live input), Administration (Users, Change log);
      - the overview's application filter (W1): "All applications" by default, in the filter bar and the address; with one application, the tiles that are not kept per application (requests analysed, not analysed) and the gaps are left out, and the chart says so;
      - Applications (`/applications`): each application with its hosts, mode, level, exceptions, alerts, not reviewed, false positives and last alert, then the requests of no application; an application that only older records have is listed as "not in the running configuration";
      - an application's page (`/applications/{name}`) with two tabs so far: Summary (its settings, then the overview of its records and the paths with the most records) and Rules (the rules page with the application fixed);
      - a rule's page (`/rules/{id}`): what the rule is, its status for every application and for the requests of no application (W6), what it found (records, alerts, false positives, over time, where in the request, paths, clients), its text as written in the rule file, and a link to CRS's tests for it in the Test tab, which now opens a rule's tests from its address (`/test?file=942100`);
      - the Engine page is "Engine and live input", with a Live input card first (W17): running or not, since when, the last counts, copiers connected, the socket, and what was not analysed in the last hour.
   2. Checks: `go test ./...` (new tests in `internal/dashboard/apps_test.go`; the route tests by role and without a login cover the new routes); a browser round as admin and viewer, light at 1366 px and dark at 1920 px, on a demo copy of the records with a replay of the 1,300 generated attacks under `csic-shop.json` (60 % of them sent to the shop's host): no page wider than the window, no console error.
   3. Choices made:
      - a new optional setting in `dashboard.json`, `ids_config`: the product configuration `ids-live` runs (W12). Stage 1 uses it only to read a rule's text; without it, the Test tab's configurations are tried. The repository's `configs/dashboard.json` leaves it out, so that a dashboard started from the repository does not write the repository's configuration in later stages;
      - which run is the newest: a replay's start record carries the time of its first request, so a replay done today of last week's requests counted as an old run. A replay now counts from when it was replayed, on every page; the Engine page's "Started" shows that time too;
      - the rule's page links each application to its Rules tab, filtered to the rule; the controls come in stage 3;
      - "Log" in the navigation is now "Change log", as W2 names it.
2. Stage 2, the foundations of change.
   1. Built:
      - `internal/jsonedit`: a JSON file is changed the way a person would, keeping the order of its keys and the layout `json.MarshalIndent` writes; the shop's configuration and profile come back byte for byte;
      - `config.Parse` and `profile.Parse`: a configuration and its profiles are read from memory, so a change is checked by the IDS's own readers before anything is written;
      - pending changes per object (W7), in `pending.json` of the state folder: for an application, a rule off, a rule skipping places, a rule back on, a CRS setting, the mode, the level, hosts, paths, removing it, its whole profile; for every application, the default level, a rule off or back on for all, the rule files, the body limit, `require_profile`, records, the live input, a new application. Each one is tried on the files as they are, with the object's other pending changes, and with the rules loaded, when it is added;
      - applying (W11, W12): the changes are made on the files as they are then, checked again, the files they replace and write are kept as a version in `versions/` of the state folder, and the IDS's files are written in place, each with one rename, under a lock beside the configuration;
      - undo: a pending change that gives each file of a version its content from before, with the same preview; it brought the demo profile back byte for byte;
      - the preview (W8): worked out from the findings of the records, which add up to each record's score (844 of 844 records of the user's on 21 November). A rule off or skipping a place, a lower level or a rule file left out are worked out exactly, and so is a rule back on for the records made before it went off; what records can't show is named;
      - who may do what (W9): an analyst proposes rule exceptions for an application, and may take back their own proposal; an admin adds any change, applies, drops, and turns a proposal down with a reason; applying for every application asks for the password again (W10). Each step is in the change log;
      - `ids-live` reads its configuration again every 3 seconds (`-watch`) and takes a change without stopping (W13): the recorder starts a new run in the same files, and the workers switch to the new rules between two copies; a configuration that does not load is reported once and the old one stays;
      - `scripts/ids-live-ctl`: start, stop, restart, status (W17);
      - on the pages: the pending changes above every tab of an application's page, with their preview, the warning for alerts marked real attack, and the form that applies them; a History tab with Undo; the Engine page says what is on disk and whether `ids-live` runs it; the change log describes the new entries.
   2. Checks: `go test ./...`; `go test -race` for `record`, `live`, `ids-live`, `jsonedit` and `dashboard`; new tests in `control_test.go`, `control_api_test.go`, `jsonedit_test.go`, and `TestTakesAChangedConfiguration` of `ids-live`, which sends copies before, during a broken edit and after a change. A browser round on the demo copy with a demo `ids-live` started by `ids-live-ctl`: an analyst proposed two changes, the admin saw their preview (114 alerts no longer alerts, 9 of them marked real attack, listed first), applied them, and `ids-live` ran them within a second; the undo's preview showed 114 records becoming alerts again, and after applying it the profile was the original byte for byte and `ids-live` ran the original fingerprint again.
   3. Choices made:
      - the `live` section (workers, queues, frame limit) still takes a restart: the queue and the workers are made when `ids-live` starts. This differs from the answer given under W4, that only the socket needs one;
      - a file laid out by hand (such as `crs-first-engine.json`, whose exclusions are one line each) keeps its content but gets the standard layout when the dashboard changes it; the version keeps it as it was;
      - an application added in the dashboard gets a profile that allows every path, in monitor mode, so that it does not fill the records with findings until its profile is written;
      - the lock against a second editor is a hidden file beside the configuration (`.csic-shop.json.lock`);
      - one browser round found a bug the Go tests could not: a preview with nothing untested sent `null` for the list, and the panel failed; every list of the answer is now a list, and a test checks it.

