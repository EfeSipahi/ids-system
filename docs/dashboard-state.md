# Dashboard state format

Written: 20 November 2026, with marks, roles and the change log (decisions G1–G6, [development-plan-marks-users.md](development-plan-marks-users.md)).

The dashboard reads the IDS's record files ([records-format.md](records-format.md)) and never changes them. What it keeps itself is in its state folder, `state_dir` of `dashboard.json`: its users, its certificate, the log of logins, the change log and the marks. This document is the contract for those files, for backups and for tools that read them.

```
records/*.jsonl  ──read only──▶  ids-dashboard  ──writes──▶  dashboard-state/
(the IDS writes them)                                      users.json, auth.jsonl,
                                                           changes.jsonl, marks.jsonl, ...
```

## 1. Files

| File | Content | Written by |
| --- | --- | --- |
| `users.json` | The users, their roles and password hashes | the dashboard and the commands `-add-user`, `-reset-password`, `-remove-user` |
| `users.lock` | Empty. Held while `users.json` is changed (Linux `flock`), so that the dashboard and a command can't lose each other's change | both |
| `dashboard.lock` | Empty. Held while a dashboard runs; a second dashboard on the same folder refuses to start | the dashboard |
| `auth.jsonl` | The log of logins and of passwords asked again | the dashboard |
| `changes.jsonl` | The change log: every change made through the dashboard (G5) | the dashboard |
| `marks.jsonl` | The marks: one line per marked record per action (G6) | the dashboard |
| `cert.pem`, `key.pem` | The certificate the dashboard made for itself, when `dashboard.json` names none | the dashboard |
| `pending.json` | The pending changes to the IDS, per object (W7 of [development-plan-dashboard-control.md](development-plan-dashboard-control.md)); section 6 | the dashboard |
| `versions/` | A folder per applied change, with the files it replaced and wrote (W11); section 7 | the dashboard |

1. The folder has permission 0700 and every file 0600: the files name users and client addresses.
2. The `.jsonl` files are JSON Lines, as the records: one JSON object per line, in UTF-8, ending with `\n`, written whole with one write. They are only appended to; the one exception is `marks.jsonl`, which the dashboard writes again without the marks older than `marks_max_age_days` when that setting is given (section 5). Readers skip, and count, a line they can't read, and ignore fields they don't know.
3. No file holds a password, temporary or chosen. A test searches every file of the folder for the passwords it used (`noSecretInState` in `internal/dashboard`).
4. On systems other than Linux the lock files do nothing, as `records.lock` for the records.

## 2. `users.json`

```json
{"users": [
  {"name": "admin", "salt": "…", "key": "…", "iterations": 600000, "created": "2026-10-23T20:31:05Z", "role": "admin"}
]}
```

| Field | Content |
| --- | --- |
| `name` | 1 to 64 letters, digits, `.`, `_` or `-` |
| `salt`, `key` | Hex: a random 16-byte salt and the 32-byte PBKDF2-HMAC-SHA256 key of the password (V5) |
| `iterations` | The PBKDF2 work factor the key was made with, 600,000 for new passwords (OWASP's recommendation) |
| `created` | When the user was added; a password reset keeps it |
| `role` | `viewer`, `analyst` or `admin` (G3). A user written before roles existed has none and is an admin; any change of the file writes every user's role |

The file is replaced whole through a temporary file and a rename, so a reader never sees half of it. The last admin can't be removed or given a lower role.

## 3. `auth.jsonl`

One line per login event: `time` (UTC), `user` (as typed, at most 64 bytes), `result`, `ip` (the browser's connection).

| `result` | Meaning |
| --- | --- |
| `ok`, `failed`, `wait` | A login: the password was right, wrong, or not checked because of the wait after five wrong passwords |
| `logout` | A logout |
| `confirm ok`, `confirm failed`, `confirm wait` | A user asked for their password again before a change (G4): the same three outcomes. Wrong passwords here and at the login count together (C8) |

## 4. `changes.jsonl`

One line per action (G5).

| Field | Content |
| --- | --- |
| `id` | Random ID of the entry; a mark line names the entry of its action |
| `time`, `user` | When, and who made the change |
| `action` | `mark`, `user_added`, `user_removed`, `role_changed`, `password_reset` or `password_changed`; since 21 November 2026 also `change_added`, `change_proposed`, `change_dropped`, `change_turned_down`, `changes_applied` (changes to the IDS), `records_deleted`, `marks_pruned` and `dashboard_settings` |
| `target` | The user a user change is about |
| `role`, `old_role` | The role given, and the earlier one for `role_changed`; for `user_removed`, the role the user had |
| `verdict`, `note` | A mark: the verdict and the note given |
| `records` | A mark: how many records it marked |
| `filter` | A mark of all records that matched the alerts list's filter: the filter, as the list's address query |
| `ids` | A mark of chosen records: their IDs |
| `before` | A mark: how many of the records had each verdict before, for example `{"not_reviewed": 7, "false_positive": 1}` |
| `object` | A change to the IDS: `global` (every application) or `app:` and an application's name |
| `what` | A change to the IDS: what each change does, with its reach, such as "Rule 942100 off for csic-shop" |
| `reason` | The reason given; for a proposal turned down, why |
| `version` | `changes_applied`: the version it made (section 7) |

## 5. `marks.jsonl`

One line per marked record per action (G2, G6). A record's newest line is its mark; the older lines are its history. A record without a line is not reviewed.

| Field | Content |
| --- | --- |
| `record` | The record's `id` ([records-format.md](records-format.md), section 4) |
| `verdict` | `not_reviewed`, `real_attack`, `expected`, `false_positive` or `undetermined` (G1). `not_reviewed` takes a mistaken verdict back |
| `note` | Optional, at most 1,000 characters |
| `user`, `time` | Who marked it, and when |
| `change` | The `id` of the action's entry in `changes.jsonl` |
| `alert` | A summary of the record, kept so that counts survive the records' rotation: `time`, `alert`, `score`, `rules` (the rule IDs that matched), `path` (as recorded, secrets masked), `application`, `client` (the client address) |

1. One action marks at most 10,000 records (C7); a line is about 250 bytes.
2. The `alert` summary keeps the client address after its record has rotated away, so the records' retention does not bound how long it is kept (C6). Since 21 November 2026, `marks_max_age_days` in `dashboard.json` bounds it: once a day the dashboard drops the marks of alerts older than that and writes the file again (W19); without it they are kept.
3. The dashboard reads the file at its start and keeps it in memory; being its only writer, it adds what it writes.

## 6. `pending.json`

The changes to the IDS that wait to be applied (W7), by object:

```json
{"objects": {"app:csic-shop": [
  {"id": "k2x…", "kind": "rule_off", "rule": 942100, "reason": "…", "user": "ana", "time": "…", "proposal": true, "what": "Rule 942100 off for csic-shop"}
]}}
```

A change has its `kind` and the fields of that kind (`internal/dashboard/control.go`); `proposal` marks an analyst's proposal (W9). The file is written whole, with a rename, at each change.

## 7. `versions/`

One folder per applied change (W11), named by its number and a random part, such as `000003-ov6ot7`:

| File | Content |
| --- | --- |
| `meta.json` | `id`, `seq`, `object`, `time`, `user`, `reason`, the `changes` applied, the `files` (each with its `path`, `before_sha256`, `after_sha256`, and `created` for a file the change made), the configuration's `fingerprint` after it, and `undoes` for an undo |
| `before-N`, `after-N` | The Nth file before and after the change; a file the change made has no `before-N` |

Undo writes the `before-N` files back, as a new version. The IDS's own files are written in place, each with one rename, while a hidden lock file beside the configuration (`.csic-shop.json.lock`) is held, so that two dashboards never write it at once.

## 8. Settings of `dashboard.json` added on 21 November 2026

| Setting | Content |
| --- | --- |
| `ids_config` | The product configuration `ids-live` runs (W12). Without it, the dashboard changes nothing of the IDS and says so |
| `marks_max_age_days` | How long marks are kept, in days; 0 or left out keeps them (W19) |
| `cert_names` | More names and addresses for the dashboard's own certificate (W20) |

The Dashboard settings page writes `session_idle_minutes`, `marks_max_age_days`, `test_configs`, `test_requests_dir` and `cert_names` in place; the other settings are changed by hand (W21).

## 9. Rules for changes

New optional fields may be added. Renaming or removing a field, or changing its meaning, needs a note in this document and a reader that understands both.
