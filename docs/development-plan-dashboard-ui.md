# Development plan: dashboard UI and user experience (desktop)

Written: 24 October 2026. Approved by the user on the same day, with decisions U1–U8 taken as recommended. Progress is recorded in section "Progress" at the end.

## Context

1. The dashboard (V1–V7) works. Its numbers match the IDS, and the security tests pass. On 24 October 2026 the user asked for a UI check: open it in the browser, look at every page including the login, list the problems, and plan a better general UI.
2. **The check (24 Oct).**
   - The dashboard ran on demo records: the CSIC run and the CRS run, spread over the last 7 days with 31 client IP addresses and hourly counts. The demo files are not in the repository.
   - browser-use opened every page, dark and light, at 1440 px. It checked the chart tooltip, the table staying open after a poll, logout, an unknown address and a missing record.
   - No page overflowed and no script failed. The problems are about usability and look, plus one real bug (P1).
3. **Mobile is out of scope** (user, 24 Oct): the dashboard is used on a desktop. The present small-screen CSS stays as it is; no phone work and no phone checks.
4. **Stays the same:** read-only (V2), Go standard library only, no inline script, text put into pages only through `el()` (no `innerHTML`), CSP, masking (M11), polling every 5 s (V6).

## Problems found

### All pages
- **P1 – Bug.** One failed poll wipes the page.
  - `failed()` in `app.js` replaces the whole view with an error.
  - The comment above `every()` says the last view stays on screen.
  - So a short network error throws away what the user was reading.
- **P2.** An unknown address gives Go's bare `404 page not found` text, with no layout or navigation.
- **P3.** The header spans the whole window but the content is 1240 px wide. At 1440 px the brand and the content start at different places.
- **P4.** Pages have no title of their own. Only the nav tab shows where you are, and the "Updated …" line floats alone on the right.
- **P5.** The chosen period is lost between pages. Choosing "Last 7 days" on the overview and then opening Alerts gives "Last 24 hours" again.
- **P6.** Times come in three styles:
  - `10/22/2026, 8:06:53 PM`
  - `Oct 23, 11:59 PM`
  - `12:01:31 AM`
  
  No time zone is shown.
- **P7.** When the session ends, the user logs in again and lands on the overview, not the page they were on.
- **P8.** Updates can't be paused, and nothing shows that the page is live.

### Login
- **P9.** A wrong password also clears the user name.
- **P10.** The button gives no sign while the slow password check (PBKDF2) runs. There is no Caps Lock warning.
- **P11.** The headings are upside down: "Log in" is the title and "IDS dashboard" is a grey subtitle. The footer, "read-only · alerts are decided by…", sits on the left, away from the centred card.

### Overview
- **P12.** The four top lists are laid out in three columns, so "Client IP addresses" sits alone on a row with empty space beside it.
- **P13.** The last bar is the period still running, for example 11 minutes of a 30-minute bar. It looks like traffic dropped.
- **P14.** The chart tooltip shows only the start time (`10/24/2026, 12:00:00 AM`), not the period. Its lines wrap.
- **P15.** The x-axis has only 3 labels at 1400 px.
- **P16.** Each bar is its own tab stop: 49 presses of Tab to get past the chart.
- **P17.** There is no list of the latest alerts. The most-used thing has to be fetched from the Alerts page.
- **P18.** The tiles give bare numbers. For example, the alerts tile doesn't say what share of analysed requests 1,389 is, or when the last alert came.
- **P19.** A bar can't be clicked to see the alerts of that period.

### Alerts list
- **P20.** On the "Alerts" view the Status column says "Alert" on every row.
- **P21.** Each row is two lines because of the User-Agent. 50 rows make a page 3,200 px tall, and the pager is only at the bottom.
- **P22.** The filters take two rows. Apply and Clear sit alone on the second row. A drop-down list applies at once, but a text field needs Apply. The active filters aren't shown as a list.
- **P23.** Rule chips are underlined text inside a pill.
- **P24.** The list can only be sorted newest first; it can't be sorted by score.
- **P25.** When a poll brings new alerts, the rows move under the mouse.
- **P26.** "← Alerts" on the detail page goes to `/alerts` and loses the filters and the page number.

### Alert detail
- **P27.** The title is only "Alert · date". The request, the client and the main attack group aren't in it.
- **P28.** "By attack group: lfi 45" shows CRS's internal score keys (`lfi`, `rce`), while every other page shows names such as "Path traversal and file access".
- **P29.** Findings repeat the same rule once per place it matched (930110 six times). The score rule 949110 is listed as a finding with severity "–".
- **P30.** Missing pieces:
  - nothing says how often this client appears elsewhere;
  - there is no copy button for the IP, record ID or request line;
  - there is no view of the whole record as JSON (also useful for profile work, A04);
  - there is no way to step to the next or previous alert.
- **P31.** A missing record shows "Could not load the data: no such record" in red. It doesn't explain that old records are removed when files rotate.

### Rules
- **P32.** 460 rows on one page, 22,000 px tall.
- **P33.** "Active" is misleading. At paranoia level 1, a level-2 rule such as 942101 shows "Active", but it never runs at that level.
- **P34.** Rules have no description: 942100 says nothing about what it detects. The start record holds no rule message.
- **P35.** The file column (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf:46`) is wide and makes the group names wrap.

### Engine
- **P36.** The fingerprint is cut short in the runs table and can't be read or copied in full. "(see Rules)" isn't a link.
- **P37.** Runs don't show how many records and alerts each one made.

## Decisions (approved 24 October 2026 as recommended)

- **U1. Rule descriptions (P34).** Add an optional `msg` to every rule in the `start` record: the rule's `msg` text with macros left as written. The record schema stays 1, because the contract allows new optional fields.
  - This touches `internal/engine` (RuleStatus), `internal/record` and `docs/records-format.md`.
  - **Recommend yes.** The rules page, the overview and the findings can then say what a rule does.
- **U2. Rules page (P32).** **Recommend:** group by rule file into sections you can open and close. Each section heading shows the file, the group, the number of rules and the number fired. Sections with fired rules are open; a search opens the matching sections. The other option is plain paging.
- **U3. Alert rows (P21).** **Recommend:** one line per row; the User-Agent goes to a tooltip and the detail page. The other option is to keep two lines.
- **U4. Clicking a bar (P19).** **Recommend yes:** the API accepts `from`/`to` (RFC 3339) next to `range`, and the alerts page shows that period as a filter that can be removed. This changes the API, so it is listed here.
- **U5. Live updates (P8, P25).** **Recommend:**
  - a "Live · updated 12:15" sign with a Pause button;
  - on page 1 of the list, new alerts show as a bar ("3 new alerts – show"), not by moving the rows.
- **U6. Times (P6).** **Recommend** one style everywhere, 24-hour: `Oct 23, 23:52:48`, with the year only when it differs from this year. The footer gives the time zone once, for example "Times in UTC+03:00". The other option is to follow the browser's locale but still use one style.
- **U7. Theme switch.** **Recommend yes:** System / Light / Dark in the header, stored in the browser (localStorage). The CSS already supports `data-theme`.
- **U8. Return after login (P7).** **Recommend yes:** a `next` value that is checked to be a local path. `//host`, `/\host` and full URLs are refused, so nobody can send a user to another site (open redirect).

## Stages

Each stage ends with its tests passing and a short entry in the progress section. Problems are named as P-numbers.

### Stage 1: the frame for every page (P1–P8, U5–U8)
1. **`layout.html`:**
   - an inner header box with the same 1240 px width as the content (P3);
   - a page heading row: the title on the left; the period buttons, the live sign with Pause, and the theme switch on the right (P4, U5, U7).
2. **Period buttons** (1 h · 24 h · 7 days · All) replace the period drop-down list on the overview, alerts and rules pages.
   - The choice goes into the URL with `history.replaceState`, and into localStorage as the default for the next page (P5).
   - localStorage is read inside try/catch, so the page works without it.
3. **`app.js`:**
   - `failed()` draws the full error only when nothing is on screen yet. Otherwise it shows a small bar, "Could not update – retrying", above the data it keeps (P1).
   - A single `fmtTime()` replaces `when`/`whenShort` (U6).
   - Pause stops `every()`.
4. **`server.go`:**
   - a `notfound` template in the layout, with status 404 (P2);
   - `next` on `/login`, checked as in U8 (P7);
   - `api()` in `app.js` sends the current path as `next` when it is sent to the login page.

### Stage 2: login (P9–P11)
1. After a wrong password, the user name is put back in the form; the password never is. This uses a new `pageData.Name`, because `User` controls the header.
2. A small `login` part in `app.js`:
   - the button turns into "Logging in…" and is disabled while the form is sent;
   - a Caps Lock note under the password field (`getModifierState`).
3. **Layout:** the brand mark (`icon.svg`) and "IDS dashboard" above the card; "Log in" as the card title; a centred footer with the version only.

### Stage 3: overview (P12–P19)
1. The top lists go in a 2 × 2 grid (P12).
2. A new "Latest alerts" card: the 8 newest, from `/api/alerts?kind=alerts`, each linked to its detail page (P17).
3. **Tile notes (P18):**
   - Alerts: "57 % of requests analysed · last 3 min ago", using `last_record` from the API;
   - Incomplete: its share of analysed requests.
4. **Chart:**
   - A bar whose period has not ended is drawn lighter, and its tooltip says "so far" (P13).
   - The tooltip shows the period ("Oct 24, 00:00–00:30") on lines that don't wrap (P14).
   - X labels about every 140 px, on round times (P15).
   - The chart is one tab stop; the arrow keys move between bars (P16).
   - With U4, clicking a bar opens the alerts of that period (P19).

### Stage 4: alerts list (P20–P26)
1. **Filters (P22):**
   - one row: Show as buttons (Alerts · All records · Incomplete), then rule, group, IP, location and minimum score;
   - text fields apply 400 ms after typing stops, or on Enter, so the Apply button goes;
   - the active filters show as chips with "×", plus "Clear filters".
2. **Table:**
   - Status shows only on "All records"; the Incomplete badge goes next to the score (P20).
   - One line per row (U3, P21).
   - Rule chips: no underline, with a hover state (P23).
3. **Paging and order:**
   - a pager above and below the table, with "1–50 of 1,389";
   - a "Sort: newest · highest score" choice, using a new `sort=score` in `query.go` `list()` (P24).
4. **Updates:** the new-alerts bar from U5 (P25).
5. **Leaving the list:** the list URL and the IDs on the page are stored in sessionStorage. The detail page's back link uses them, and so do its Newer/Older buttons (P26, P30).

### Stage 5: alert detail (P27–P31)
1. **Title:** `GET /get/index.php` with "from 203.0.113.10 · Path traversal and file access · score 55 / 5", then the time and the badges (P27).
2. **Score by category (P28):** each CRS key gets a name. The names are checked against the CRS 4.30.0 rule files: which file sets which `tx.*_score`. Nothing is guessed.
3. **Findings (P29):**
   - one row per rule, with the number of places it matched; it opens to show each place;
   - the severity as a badge with its word;
   - the score rule (949xxx) leaves the table, because the score is already in the title.
   - With U1, the rule's description appears next to its ID.
4. **Additions (P30):**
   - "This client in the last 24 h: N records" with a link (it uses `/api/alerts?ip=…`);
   - copy buttons for the IP, the record ID and the request line (`navigator.clipboard`; the page is HTTPS);
   - "Show the record as JSON" (a `<details>` holding a `<pre>` filled with `textContent`);
   - the Engine card folded closed.
5. **Missing record (P31):** "This record is no longer kept. Record files rotate and the oldest are removed." and a link back.

### Stage 6: rules and engine (P32–P37)
1. **Rules:**
   - grouping as in U2 (P32);
   - three statuses: **Runs**, **Above level N** (loaded, skipped at this paranoia level) and **Excluded** with its reason. The summary line counts all three (P33). This is UI only: the run's level is compared with the rule's level.
   - With U1, a description column (P34).
   - Inside a file section, the file column becomes just the line number (P35).
2. **Engine:**
   - the full fingerprint as a tooltip, with a copy button; "changed" marked clearly; "see Rules" as a link (P36);
   - records and alerts per run, counted in `store` from `entry.run`, as new fields in `/api/engine` (P37).

### Stage 7: U1, checks and documents
1. **If U1 is approved:**
   - `RuleStatus.Msg` in `internal/engine/ruleset.go`, taken from the compiled rule's msg text (`compile.go`, case "msg");
   - `Rule.Msg` (`msg,omitempty`) in `internal/record/record.go` and `recorder.go`;
   - the `rules` row in `docs/records-format.md`;
   - a test that 942100's description is the text in the CRS file.
2. **Documents:**
   - a new `docs/development-plan-dashboard-ui.md` with a progress section;
   - main plan history 11.24;
   - `context.md` and `docs/project-history.md`.

## Files

- **Most of the work:**
  - `internal/dashboard/web/static/app.js` and `app.css`;
  - `internal/dashboard/web/templates/*.html`, with a new `notfound.html`.
- **Server:**
  - `internal/dashboard/server.go`: 404 page, login name, `next`;
  - `internal/dashboard/query.go`: `sort`, `from`/`to`, runs with counts;
  - `internal/dashboard/store.go`: counts per run.
- **Only with U1:**
  - `internal/engine/ruleset.go` and `compile.go`;
  - `internal/record/record.go` and `recorder.go`;
  - `docs/records-format.md`.
- **Reuse:**
  - `el()`, `chips()`, `card()`, `kv()`, `query()`, `same()`/`replace()` in `app.js`;
  - `groupOf()`/`fileGroup()` in `store.go`;
  - `parseRange()` and `parseFilter()` in `query.go`;
  - the existing auth and page tests in `internal/dashboard/*_test.go`.

## Rules for the work

1. Expected test values come from the data or the CRS files, never guessed.
2. No new dependency and no inline script. `app.js` keeps building pages only with `el()`; `secrets_test.go` still checks that `app.js` uses no `innerHTML`.
3. No commit unless the user asks.
4. **Fewer approval prompts (user, 24 Oct):**
   - browser work goes into one browser-use call per check round, never one call per page;
   - screenshots are saved outside the repository and looked at afterwards.

## Verification

1. **New Go tests:**
   - the 404 page has the layout and status 404;
   - a wrong login keeps the name and never the password;
   - `next`: local paths are accepted, while `//evil.example`, `/\evil`, `https://…` and an empty value fall back to `/`;
   - `sort=score` and `from`/`to`, with the expected order computed from the test records;
   - counts per run in `/api/engine`;
   - U1: the rule msg in the start record.
2. **Commands:**
   - `go vet ./...`
   - `gofmt -l .`
   - `go test ./...`
   - `go test -race ./internal/dashboard/... ./cmd/ids-dashboard/...`
   - With U1, also `go test -race -timeout 60m ./internal/engine/... ./internal/record/...`.
3. **The secrets test** (`TestNoSecretReachesTheDashboard`) and the attack-text test still pass. The new JSON view and copy buttons are covered, because the test reads every page and API answer.
4. **Browser, one browser-use call.** On the demo records, at 1440 px, dark and light:
   - every page, the login (with a wrong password), a 404, a missing record, a chart click (U4), Pause, the new-alerts bar, the back link keeping filters, rule grouping and search;
   - each P-number is checked in the screenshots;
   - no horizontal overflow and no console errors.
5. **Numbers:** the overview and list counts still equal the IDS `-summary` on the CRS records (2,916 alerts at level 1).

## Progress

| Stage | Content | Status |
| --- | --- | --- |
| 1 | Frame for every page | **Done 24 October 2026** |
| 2 | Login | **Done 24 October 2026** |
| 3 | Overview | **Done 24 October 2026** |
| 4 | Alerts list | **Done 24 October 2026** |
| 5 | Alert detail | **Done 24 October 2026** |
| 6 | Rules and engine | **Done 24 October 2026** |
| 7 | U1, checks and documents | **Done 24 October 2026** |

All 37 problems were worked on. P32 (the long rules page) was first only partly solved; the user then chose that all sections start closed (note 3). A second check later the same day found and fixed more problems (note 5).

### Notes from the work

1. **U1 differs a little from the plan.** The description is taken from the rule's `msg` action in the parsed file (`msgOf` in `compile.go`), not from the compiled rule. That way an excluded rule has its description too. Macros such as `%{MATCHED_VAR}` stay as written. A test checks four rules against the CRS files:

   | Rule | Expected description |
   | --- | --- |
   | 942100 | `SQL Injection Attack Detected via libinjection` |
   | 920450 | `HTTP header is restricted by policy (%{MATCHED_VAR})` |
   | 901350 | `Enabling forced body inspection for ASCII content` (an excluded rule) |
   | 901320 | none (the rule has no `msg`) |

2. **Choices made inside the plan:**
   - **Incomplete badge.** It always goes next to the score, also on "All records". The Status column then shows only "Alert" or "Below threshold", so every row stays on one line.
   - **Fixed column widths in the record lists.** A long request, an IPv6 address or a long group name is cut with "…". Hovering shows the whole text.
   - **Chips in a list row.** At first at most 2 rules, then "+N". Changed by the second check (note 5): whole chips only, as many as fit, up to 3.
   - **Title of the alert page.** It is at most two lines. The Request card below it has the whole request line.
   - **Overview tile.** The Alerts tile says "last alert 10 min ago", on its own line.
3. **P32: all sections start closed (user's decision, 24 October 2026).**
   - U2 said sections with fired rules start open. On the demo records, 15 of the 18 file sections have fired rules, both for 24 hours and for all records, so the page was still 17,325 px tall (it was 22,000 px).
   - On a system that sees attacks, most files fire, so this default opens almost everything.
   - The user chose that all sections start closed; each heading still shows "N rules · M fired". A filter or a search opens the sections with matching rules, and "Open all" stays. The page is now 1,581 px.
4. **Found by the browser check and fixed:**
   - The active-filter chips showed "[object HTMLButtonElement]". `replaceChildren` was given a list, and it would also write `null` as text: an empty chart bar's tooltip would have said "null". The new helper `refill()` adds children the way `el()` does.
   - The alerts table was wider than its card, so the Rules column was cut off at 1440 px. Fixed column widths solved it (note 2).
   - The long title of an alert page took three lines.
5. **Second check (24 October 2026, after the user said problems persisted).** One browser round took 26 screenshots of every page, dark and light, and measured cut text and overflow. Found and fixed:
   - **Attack-group chips were cut** ("Protocol en…", "Remote comma…") in the alerts list and the overview's Latest alerts. A list row now shows whole chips only: `fitChips()` in `app.js` measures each cell and folds the chips that don't fit into "+N", whose tooltip names them. It runs after each redraw and when the window is resized. Only a single chip that is wider than its cell is still cut with "…".
   - **The alert filters took two rows** (Order alone on the second). The fields got fixed widths and now fit on one row at 1440 px.
   - **The rules page ignored the address.** `?q=`, `status`, `level` and `sort` were not read or written, unlike on the alerts page. They are now kept in the address, so a link or the back button shows the same rules.
   - **Rule tables had different column widths in each section**, so the columns jumped between files. They now share fixed widths.
   - **Closed rule sections showed no sign that they open** (a flex `summary` loses the browser's triangle). A triangle is drawn, pointing down when open.
   - **Chart labels were on uneven times** (every 3.5 hours on the 24-hour view, 09:00 each day on the 7-day view). Labels are now at least 110 px apart on round local times: every 3 hours on 24 hours, each midnight ("Oct 18") on 7 days, placed where the moment falls even inside a 6-hour UTC bar.
   - **The categories on the alert page did not add up to the score** (45 of 55). In CRS 4.30.0, the rules of files 911, 913 and 922, and all but one rule of 920, raise only the total score, not a category (checked with `grep` on the rule files). The difference now shows as "No category 10 (rules that add to the total only)".
   - **Smaller things:** the alert page's summary line ran together and now has "·" between its parts; the Alerts tile note wrapped mid-phrase; the record-files table touched the list above it; the missing-record card had a second "Alerts" link under the back link; the time links in list rows were underlined on every row and are now underlined on hover.
   - **Not changed:** a group in the address that is not an attack-group name (for example `group=sql_injection`) is ignored, as before; the page's own links use the names.

### Checks (24 October 2026)

1. **Go tests.**
   - **New tests:**
     - the 404 page;
     - a wrong login keeps the name and never the password;
     - `next` against open redirects, as a table of cases (`TestAfterLogin`);
     - `sort` and `from`/`to`, with orders worked out from the test records;
     - wrong periods and sort values are refused;
     - counts per run, and the rules above the level;
     - `app.js` knows every attack group of `store.go`;
     - the rule descriptions of U1.
   - **Commands:** `gofmt -l .` lists nothing. `go vet ./...` and `go test ./...` pass. `go test -race` passes for the dashboard packages and for `internal/engine/...` and `internal/record/...`.
2. **Secrets and attack text.** `TestNoSecretReachesTheDashboard` and the attack-text test pass. They read every page and API answer, including the new JSON view.
   - The attack-text test now looks for `<img src=x` instead of `<img`, because the header shows the dashboard icon as an `<img>`.
3. **Numbers.** On the CRS records (level 1), the dashboard gives the same numbers as `ids-offline -summary`:

   | Number | Value |
   | --- | --- |
   | Requests analysed | 5,072 |
   | Records | 2,967 |
   | Alerts | 2,916 (also the total of the alerts list) |
   | Incomplete | 154 |
   | Rules | 456 active (330 run, 126 above level 1), 4 excluded |

4. **Browser** (browser-use, 1440 px, dark and light, demo records over 7 days).
   - **Rounds.** Four rounds of one call each: the full check, then three short ones after fixes.
   - **Login.**
     - A logged-out visit to `/alerts?range=7d` goes to the login and comes back to that page.
     - A wrong password keeps the name and empties the password.
     - The button says "Logging in…" while the form is sent.
   - **Overview.**
     - The top lists are in a 2 × 2 grid, under the Latest alerts card.
     - The running bar is lighter and its tooltip says "(so far)".
     - Tooltip lines don't wrap, and the x labels are round times.
     - The chart is one tab stop. The arrow keys, End and Escape work.
     - Pause stops updates and Resume starts them again.
     - An open table stays open after a poll.
     - "7 days" is kept on the Alerts page.
   - **Chart click.** It opens `/alerts?kind=all&from=…&to=…` with a removable period chip. The list holds 50 records, the bar's 48 alerts plus 2 other records.
   - **Alerts list.**
     - Every row is one line (37 px), and the table fits its card in all three views.
     - There is a pager above the table.
     - Sorting by score works, and a typed IP is applied without a button.
     - The back link keeps the filters, and Newer/Older step through the list.
     - An appended alert shows "1 new alert. Show" without moving the rows.
   - **Alert detail.**
     - The attack categories have names.
     - Findings are grouped by rule, and the score rule is on its own line.
     - There are 4 copy buttons and the JSON view.
     - "22 records, 22 alerts" for the client in the last 24 hours.
   - **Missing record and 404.** Both have their own text.
   - **Rules.**
     - Summary: 330 run, 126 above the level, 4 excluded.
     - A search for "libinjection" leaves 2 open sections.
     - A section closed by hand stays closed after a poll.
   - **Engine.** Runs with records and alerts, and the full fingerprint in a tooltip.
   - **Theme.** "Dark" is kept after a reload, and "System" follows the system again.
   - **Dashboard stopped.**
     - The data stays on the page under "Could not update … Trying again every 5 seconds", and the sign says "Not updating".
     - After a restart the page asks for a login (sessions are in memory) and comes back.
   - **Errors.** No page overflowed sideways. No script error was recorded; a listener added through the browser's debugging protocol counted them.
5. **Second check (after note 5's fixes).** `gofmt -l .` lists nothing, `go vet ./...` passes, and `go test` passes for the dashboard packages. Three browser rounds (one call each), 1440 px, dark and light:
   - no chip is cut in any list (100 chip cells on the alerts page, 8 on the overview), and no cell overflows; the "+N" tooltips name the hidden chips;
   - the alert filters are on one row (56 px high);
   - `group=SQL injection` with `min_score=10` shows both chips and 265 alerts, all with SQL injection;
   - the rules page is 1,581 px with all 18 sections closed; "Open all" gives one x position for each column in every section; `?q=sql` opens the 932 and 942 sections (69 rules), and a status change is written to the address;
   - chart labels: 24 hours "Oct 23, 12:00 · 15:00 · … · Oct 24, 00:00 · … · 09:00"; 7 days "Oct 18" to "Oct 24";
   - the 1-hour view of the demo correctly shows "No records in this period" (the demo records end 10 hours earlier);
   - no sideways overflow and no script errors.
