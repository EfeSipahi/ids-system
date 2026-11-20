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

1. The folder has permission 0700 and every file 0600: the files name users and client addresses.
2. The `.jsonl` files are JSON Lines, as the records: one JSON object per line, in UTF-8, ending with `\n`, written whole with one write. They are only ever appended to; the dashboard never changes or deletes a line. Readers skip, and count, a line they can't read, and ignore fields they don't know.
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
| `action` | `mark`, `user_added`, `user_removed`, `role_changed`, `password_reset` or `password_changed` |
| `target` | The user a user change is about |
| `role`, `old_role` | The role given, and the earlier one for `role_changed`; for `user_removed`, the role the user had |
| `verdict`, `note` | A mark: the verdict and the note given |
| `records` | A mark: how many records it marked |
| `filter` | A mark of all records that matched the alerts list's filter: the filter, as the list's address query |
| `ids` | A mark of chosen records: their IDs |
| `before` | A mark: how many of the records had each verdict before, for example `{"not_reviewed": 7, "false_positive": 1}` |

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
2. The `alert` summary keeps the client address after its record has rotated away, so the records' retention does not bound how long it is kept (C6). How long marks are kept is open, with A09; the Engine page shows how many there are.
3. The dashboard reads the file at its start and keeps it in memory; being its only writer, it adds what it writes.

## 6. Rules for changes

New optional fields may be added. Renaming or removing a field, or changing its meaning, needs a note in this document and a reader that understands both.
