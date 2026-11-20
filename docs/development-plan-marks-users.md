# Development plan: marking alerts, users with roles, and a change log

Decided by the user on 20 November 2026, decisions G1–G6 (main plan section 11.31). This document is the plan of the work and its progress.

## Context

1. Why. The dashboard only reads (V2). The user put its extension before the response rules (19 November 2026), and chose marking alerts, users with roles and a change log as the first part: the later pages that V1 and V7 named. The test tab (S1–S4) came first, at the user's wish.
2. What others do, read before the decisions:
   - Elastic Security gives an alert a workflow status, open, acknowledged or closed, and a reason when it is closed ([Elastic](https://www.elastic.co/docs/solutions/security/detect-and-alert/manage-detection-alerts));
   - Microsoft Sentinel closes an incident as true positive, benign positive (real but expected, such as a penetration test), false positive or undetermined ([Sentinel](https://learn.microsoft.com/en-in/azUre/sentinel/incident-navigate-triage)), and has three built-in roles as a ladder: Reader, Responder (also manages incidents) and Contributor (also edits rules and content) ([roles](https://learn.microsoft.com/en-us/azure/sentinel/roles));
   - NIST SP 800-63B revision 4 asks for at least 15 characters when a password is the only factor, and forbids composition rules ([NIST](https://pages.nist.gov/800-63-4/sp800-63b/authenticators)).
3. Decided by the user (20 November 2026):

   | # | Decision |
   | --- | --- |
   | G1 | A mark is a verdict: not reviewed (the default), real attack, expected (real but allowed, such as one's own scanner), false positive (the rule was wrong about this request) or undetermined; with an optional note, who marked it and when. No workflow status |
   | G2 | A mark is put on records that exist: one on its detail page, the selected ones of the list, or all records that match the list's filter. Alerts that come later start as not reviewed; there are no standing marks |
   | G3 | Three roles as a ladder: viewer (reads every page), analyst (also marks alerts and uses the test tab), admin (also manages users, sees the change log, and later changes settings). The existing users become admins. The user asked why not per-user permissions; the answer: they turn back into roles, multiply what must be tested, and must be set again for every user with each new feature. A custom role can be added later if a mixed job appears |
   | G4 | A Users page for admins: add (with a role), remove, change a role, reset a password. A new or reset password is random, shown to the admin once, and kept by the user, who may change it later. Every user can change their own password, giving the current one; a chosen password has at least 15 characters and no composition rules. User changes ask for the admin's password again. The last admin can't be removed or demoted. A user's sessions end when they are removed, their role changes or their password is reset. The command-line commands stay |
   | G5 | A change log of every change made through the dashboard: marks (verdict, note, the earlier verdict) and user changes, never a password. One action is one entry; a bulk mark is one entry with its filter and count. Only appended to. The whole log, with the logins, is for admins only; every role sees an alert's own mark history on its detail page. Test tab runs are not logged (C1 of the test tab plan) |
   | G6 | Marks and the log are JSON Lines files in the dashboard's state folder: `marks.jsonl` (one line per marked record per action; a record's newest line is its mark, the older ones its history) and `changes.jsonl`; `users.json` gets each user's role. A mark keeps a short summary of its alert (time, rule IDs, path, application, client), so counts survive the records' rotation. One dashboard writes them, under a lock |

4. Consequences, found while reading the code; they are approved with this plan:
   1. C1: the dashboard starts to write, but only its own state folder: never a record file, never a setting of the IDS. V2's "read-only" ends there; V4 holds (the IDS writes the records, the dashboard only reads them). The footer, which says "read-only", says "records are read only" instead.
   2. C2: a session keeps the stamp of its login, today the password's salt (`users.stamp`), and ends when it changes. The stamp gets the role too, so a role change ends the user's sessions (G4).
   3. C3: `users.json` is read and written by the running dashboard and by the command-line commands. Both write the whole file through a temporary file and a rename, so a reader never sees half of it, but two changes at the same moment could lose one. Every change of `users.json` takes a lock on a lock file in the state folder (Linux `flock`, as `records.lock`), held for the read, the change and the write.
   4. C4: the state folder gets `dashboard.lock` (G6), held while the dashboard runs. A second dashboard on the same state folder refuses to start, naming the folder. Today the repository's `configs/dashboard.json` and the user's own configuration share `dashboard-state/`, so only one of them can run at a time.
   5. C5: a user in `users.json` without a role, which is every user today, reads as an admin (G3). `ids-dashboard -add-user NAME` gets `-role` (viewer, analyst or admin; admin when left out, since whoever runs the command owns the machine).
   6. C6: a mark's summary keeps the client address after its record has rotated away, so the records' retention no longer bounds how long an address of a marked alert is kept. Retention of marks belongs to A09 and is left for it; the Engine page shows how many marks are kept.
   7. C7: a bulk mark is limited to 10,000 records per action; with more, the page says to narrow the filter. A mark line is about 300 bytes, so the largest action writes about 3 MB.
   8. C8: re-asking the admin's password costs one PBKDF2 check (600,000 rounds), the same work as a login, which also slows guessing through a stolen session. Wrong passwords there count toward the same growing wait as at the login.

## Design

### Roles: `internal/dashboard`

1. `storedUser` gets `role` (`viewer`, `analyst` or `admin`; missing means admin, C5). The stamp is salt plus role (C2).
2. Every route names its least role. Pages and reading APIs: viewer. Marking and the test tab: analyst. Users, the change log and a user's changes: admin. Too low a role gets 403, and the pages hide what the role can't use. Changing one's own password: any role.

### Users and the change log

1. `GET /users` (admin): the users with their role and when they were added; add, remove, change role, reset password. Each change posts the admin's password with it (G4, C8); a new or reset password comes back once.
2. `GET /account` (any role): change one's own password (the current one, the new one twice; 15 to 256 characters).
3. `changes.jsonl`: one line per action: `time`, `user`, `action` (`mark`, `user_added`, `user_removed`, `role_changed`, `password_reset`, `password_changed`), and its facts (for a mark: the verdict, the note, the earlier verdicts counted, how many records, the filter or the record IDs). Never a password.
4. `GET /log` (admin): the change log and the logins (`auth.jsonl`), newest first, filtered by user and kind.

### Marks

1. `marks.jsonl`: one line per record per action: `record`, `verdict`, `note`, `user`, `time`, `action` (the change log entry it belongs to), and `alert` (the summary: `time`, `rules`, `path`, `application`, `client`, `score`).
2. The store reads the file at start and its new lines as they come, and joins a record's newest mark to it. A line it can't read is skipped and counted, as with records.
3. `POST /api/marks`: the verdict, the note, and either record IDs or the list's filter (G2, at most 10,000 records, C7).
4. The alerts list: a verdict column, a "review" filter (not reviewed and each verdict), checkboxes and "mark the selected" or "mark all N that match"; the detail page: the verdict, a form to change it, and the record's mark history; the overview: how many alerts of the period are not reviewed; the Rules page: how many of each rule's records are marked false positive. Viewers see the verdicts without the forms.

## Stages

Each stage ends with its tests passing and a note in the progress section.

1. Decision documents: this file, the main plan (section 1, A09 in section 6.9, history 11.31), `context.md`.
2. Roles: the role in `users.json` and the stamp, the lock of `users.json` (C3), `-role`, the least role of every route, the test tab for analysts.
3. Users and the change log: `dashboard.lock` (C4), `changes.jsonl`, the Users, Account and Log pages.
4. Marks: `marks.jsonl`, the store's join, the API, the list, detail, overview and Rules pages.
5. Close: `docs/dashboard-state.md` (the state files' format, as `docs/records-format.md` is for records), the dashboard UI plan, `context.md`, `docs/project-history.md`, the main plan; browser rounds; the full checks. The commit only when the user asks.

## Rules for the work

1. No new dependency.
2. The dashboard never writes a record file or a setting of the IDS; check runs use a temporary records folder and a temporary state folder.
3. No password, temporary or chosen, reaches a log, a mark, a page after the one that shows it, or the change log.
4. Browser checks: one batched call per round.
5. No commit unless the user asks; `proje_oneri_formu.docx` is never committed.

## Verification

1. `gofmt -l .`, `go vet ./...`, `go test ./...`; `go test -race ./internal/dashboard/... ./cmd/ids-dashboard`.
2. Every route with no login, as a viewer, an analyst and an admin: the expected status, and nothing hidden from a role shows in its pages or answers.
3. Users: the last admin can't be removed or demoted; a wrong admin password refuses the change and counts toward the wait; a removed user's, a demoted user's and a reset user's sessions end at their next request; a chosen password of 14 characters is refused and one of 15 accepted; a user added by the command while the dashboard runs, and one added on the page at the same moment, both stay (C3).
4. The change log: every action writes one entry; a bulk mark is one entry; no password appears in any file of the state folder (a test searches every file for the passwords it used).
5. Marks: a mark survives a restart; a record's history is in order; marks of records that rotated away still count per rule; a bulk mark of 10,000 records, and 10,001 refused; a line that can't be read is skipped and counted; `FuzzStoreReadsAnyFile` also reads marks.
6. A cross-origin post to every new route is refused; the records folder is the same, byte for byte, after every test.
7. Browser: the new pages and controls as each role, light and dark; no console errors and nothing wider than its space.

## Progress

| Stage | Status |
| --- | --- |
| 1. Decision documents | Done 20 November 2026 |
| 2. Roles | Done 20 November 2026 |
| 3. Users and the change log | Done 20 November 2026 |
| 4. Marks | Done 20 November 2026 |
| 5. Close | Done 20 November 2026 |

### Notes from the work

1. Stage 1: this document, the main plan (sections 1, 6.9 and 11.31) and `context.md`, 20 November 2026.
2. Stage 2: roles, 20 November 2026.
   1. What was built:
      - `users.json` keeps each user's `role`; a user without one is an admin (C5), and any change of the file writes every user's role. `allows` compares roles on the ladder (G3).
      - The stamp a session keeps is the password's salt and the role, so a new role ends the user's sessions (C2).
      - The last admin can't be removed or given a lower role; the error says to make another user an admin first. A reset keeps the user's role and the time they were added (before, it set that time anew).
      - Every change of `users.json` holds `users.lock` (Linux `flock`, waiting for another holder) from reading the file to writing it, and reads the file whatever its time and size say (C3). On other systems there is no lock, as for the records.
      - Every route names its least role. Pages and reading answers: viewer; the test tab and its answers: analyst. A role too low gets a page "Not allowed" (it names the role needed and the user's own) or a JSON error, both with status 403. The header shows the user's role, and the Test tab only to analysts and admins.
      - `ids-dashboard -add-user NAME -role ROLE`, admin when left out; `-role` without `-add-user` is refused, since an admin changes roles on the Users page (stage 3).
   2. Checks:
      - `gofmt -l .` is empty; `go vet ./...` and `go test ./...` pass; `go test -race` passes for `internal/dashboard` and `cmd/ids-dashboard`; the code builds for Windows and macOS.
      - New tests: the ladder for every pair of roles; a user without a role reads as admin; bad roles refused; the last admin neither demoted nor removed, and both allowed with a second admin; a reset keeps role and time; every route as viewer, analyst and admin (15 routes); the role and the Test tab in the header; the refused page's text; a new role ends a session; the command's `-role`.
      - `TestUsersFileLock`: two readers of one state folder add 15 users each at the same time; all 31 users stay. With the lock taken out for a trial, the same test kept 16 of 31, so it catches a lost change.
3. Stage 3: users and the change log, 20 November 2026.
   1. What was built:
      - `dashboard.lock`: a second dashboard on the same state folder refuses to start, naming the folder (C4); `Server.Close` lets go of it, and `ids-dashboard` closes it when it stops.
      - `changes.jsonl`, appended to only (`admin.go`), one entry per action, never a password (G5).
      - The password check moved out of the login (`auth.verify`), so that a login and a password asked again before a change share the wait after five wrong passwords (C8). The log of logins writes the second kind as `confirm ok`, `confirm failed` and `confirm wait`.
      - `POST /api/users` (admin): add, remove, change a role, reset a password, each with the admin's password; a new password comes back once. `POST /api/account` (any role): the current password, the new one twice, 15 to 256 characters counted as Unicode code points (NIST); the session goes on with a new token, the user's other sessions end. `GET /api/log` (admin): the change log and the logins, newest first, by user and kind, 100 per page, unreadable lines counted.
      - The pages Users, Log and Your account; the header links the user's name to the account page, and shows Users and Log to admins. The footer says "records are read only" (C1). Success notifications got Carbon's green.
   2. Changes to the design above: the Log page reads both files on each request; they are small, and a page of 100 is answered. A user may remove or demote themselves when another admin remains; their session ends at their next request.
4. Stage 4: marks, 20 November 2026.
   1. What was built:
      - `marks.jsonl` (`marks.go`): read at the start, kept in memory, appended to with one write per action. A line that can't be read, or has an unknown verdict, is skipped and counted. The verdict `not_reviewed` takes a mark back; the history keeps both.
      - `POST /api/marks` (analyst): a verdict, a note of at most 1,000 characters, and either record IDs or the list's filter (its `page` and `sort` dropped); at most 10,000 records (C7). The change log entry is written first, so a mark is never without its entry; it keeps the filter, or the IDs of chosen records, and how many records had each verdict before. `GET /api/marks/{id}` (viewer): a record's verdict and history, also of a record that rotated away.
      - The store joins marks to records: a `verdict` per list row, a `review` filter, the overview's `not_reviewed` (alerts of the period nobody marked), each rule's `false_positives` on the Rules page (from the marks' summaries, so records that rotated away still count), and on the Engine page the number of marked records and of unreadable mark lines (C6).
      - The pages: a Review column on the alerts list and on the overview's latest alerts; a Review filter; for analysts and admins, boxes per row and for the page, and a bar "Mark as … / Mark N chosen / Mark all N that match" (the last one asks first); on an alert's page, a Review card with the verdict, who and when, the note, a form for analysts and admins, and the earlier marks; on the overview, "N not reviewed" under Alerts; on the Rules page, a "False positive" column that links to those records.
   2. Changes to the design above: with both the Status column (All records) and the Review column, the alerts list leaves out its Attack groups column, so that the request keeps room; the rules still name what matched.
5. Stage 5: the close, 20 November 2026.
   1. Documents: `docs/dashboard-state.md` (the state folder's files: users, the lock files, the log of logins, the change log, the marks), this plan, the dashboard UI plan, `docs/records-format.md` (where marks live), `context.md`, `docs/project-history.md`, the main plan (sections 1 and 11.32).
   2. Browser, four rounds with Playwright on a demo dashboard in the scratchpad (records of `ids-offline` with the CSIC profile and the built-in examples; an admin, an analyst and a viewer), 1440 and 1280 px, light and dark:
      - as the analyst: two chosen alerts marked false positive with a note, then all 8 alerts of rule 942100 as expected (after the question), one alert on its page as real attack and then undetermined, with its history; the review filter and its chip; "30 not reviewed" on the overview; the Rules page's false positives; the Users page refused ("needs the role admin or more");
      - as the viewer: the verdicts shown, no boxes, no bar, no form; Test, Users and Log not in the header; the account page refused a 9-character password and took a 26-character one, and the session went on;
      - as the admin: a user added (the password shown once), its role changed, its password reset; a wrong password refused; the last admin's removal refused; the Log page with every change and login, and its Kind filter;
      - nothing was wider than its space; the console showed only the deliberate refusals (403, 400, 409).
      - Fixed after the rounds: the alerts list's Request column had shrunk to one letter once the boxes and the Review column came (the columns were given new widths, and All records leaves out Attack groups); messages from the server began in lower case after the notification's title. A long attack-group name alone in its cell is still cut short, with its full name in the tooltip, as before (P23).
      - A mistake in the round's own script, not in the dashboard: its first selector for the Add button found the header's Log out button first.
   3. Checks, with temporary records and state folders:
      - `gofmt -l .` is empty in both modules (after one blank line in a new test file was removed); `go vet ./...` and `go test ./...` pass in both; `go test -race` passes for `internal/dashboard`, `cmd/ids-dashboard` and `internal/analysis`; the code builds for Windows and macOS.
      - `FuzzStoreReadsAnyFile`, which now also reads the same bytes as a marks file and lists by review, ran 60 seconds without a failure.
      - The repository's `records/` folder was the same, byte for byte, before and after.

