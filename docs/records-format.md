# Record format

Written: 23 October 2026. Schema version: **1**.

This is the contract between the programs that write records and the programs that read them.

```
now:    request files ──▶ ids-offline ──writes──▶ records/*.jsonl ──reads──▶ ids-dashboard
later:  proxy copies  ──▶ ids (service) ─writes─▶ (same files)      ──reads──▶ ids-dashboard, webhook, syslog, MCP (I1)
```

The decisions behind it are R1–R7 and V4 (main plan, section 11.22). The code is in `internal/record`. A golden test, `internal/record/testdata/request-record.json`, pins the format of a request record.

## 1. Files

| File | Content |
| --- | --- |
| `records.jsonl` | The file being written now |
| `records-<UTC time>.jsonl` | A full file, renamed at rotation, for example `records-20261023T193646.751485264Z.jsonl`. The names sort from oldest to newest |
| `hash.key` | The installation key for cookie hashes (32 random bytes, hex). Made on the first run. Deleting it changes every later cookie hash |

1. **Folder and permissions.** The folder is set in the product configuration (`records.dir`) or with `ids-offline -records DIR`. The folder has permission 0700 and every file 0600, because records hold personal data such as IP addresses.
2. **Rotation (R5).** When `records.jsonl` would grow beyond `max_file_mb` (default 10 MB), it is renamed and a new one is started. The `start` record of the run is written again at the top of the new file, so each file can be read alone. The newest `keep_files` files are kept (default 10, the current one included); older ones are deleted.
3. **Writing.** Each record is written as one whole line with a single write. One writer per folder.

## 2. Lines

1. Each line is one JSON object in UTF-8, ending with `\n`.
2. The characters `<`, `>` and `&` are written as `<`, `>` and `&`. So a line can't be read as HTML by mistake.
3. Every line has `"type"` (`start`, `request` or `counts`) and `"schema": 1`.
4. **Rules for readers:**
   - A last line without `\n` is still being written. Read it on a later pass.
   - Ignore fields you don't know.
   - Skip, and count, lines that can't be read.
   - A `start` record appears again at the top of each rotated file; keep one per `run`.
   - A record's `id` is unique; a reader that meets it twice keeps the first.
5. **Schema changes.** New optional fields may be added under schema 1. Renaming or removing a field, or changing its meaning, needs schema 2.

## 3. `start`: one per run

Written when `ids-offline` (later `ids`) starts writing records.

| Field | Content |
| --- | --- |
| `run` | Random ID of this run (26 lower-case letters and digits) |
| `time` | Start time, UTC (RFC 3339) |
| `engine.version` | Version of the program, now `0.1.0-dev` |
| `engine.revision` | Git commit of the build, with `-modified` when the working tree had changes. Left out when unknown, for example with `go run` |
| `engine.crs` | Rule set signature, for example `OWASP_CRS/4.30.0` |
| `engine.paranoia_level` | Paranoia level the rules run at, 1–4 |
| `engine.config` | Fingerprint: `sha256:` over the configuration file, every rule file it loads and the paranoia level (R7). It changes when any of these changes |
| `rules[]` | Every rule: `id`, `file` (base name), `line`, `phase`, `paranoia_level` (left out when the rule has none), `active`, and `reason` when it is excluded |

## 4. `request`: one per request with a finding or an incomplete analysis (R1)

| Field | Content |
| --- | --- |
| `id`, `run`, `time` | Random ID of the record, the run, the time of the analysis (UTC) |
| `alert` | `true` when the score reached the threshold (R2) |
| `decided_by` | `"rule layer only"` for now. The decision mechanism (K3) replaces this later |
| `client.ip`, `client.port` | The address of the **connection**: today the offline input's `remote_addr`/`remote_port`, later the trusted proxy's. Never taken from `X-Forwarded-For` or any other header the client sends. Left out when unknown |
| `server.host`, `server.ip`, `server.port` | The `Host` header, and the address and port the request came to |
| `request.method`, `path`, `query`, `version` | The request line. Secret parameters in `query` are masked by name |
| `request.user_agent`, `referer`, `content_type` | These headers. Secret parameters in the Referer's query are masked |
| `request.body_length` | Body size in bytes |
| `request.header_names` | Header names in order, without values |
| `request.cookies[]` | `name` and `hash`: the first 12 hex digits of HMAC-SHA256 of the value with `hash.key`. The same session gives the same hash; the value can't be found from it |
| `analysis` | `complete`, `body` (`empty`, `inspected`, `partly inspected` or `not inspected`), `body_format`, `body_reason`, `issues[]` (M05) |
| `findings[]` | `rule_id`, `severity`, `message`, `location` (for example `ARGS:id`), `matched` (the matched value), `data` (the rule's log data), `action`, `tags` |
| `score` | `total`, `threshold`, `exceeded`, `categories` (score per attack group, for example `sql_injection`) |
| `engine` | The `engine` fields of the run's `start` record (R7) |
| `full` | Only when `full_requests` is on, and only for alerts: `headers` (`[name, value]` pairs in order) and `body`. Off by default |

**Maximum lengths.** Longer text is cut at a character boundary and ends with `…`.

| Field | Maximum |
| --- | --- |
| `matched`, `data` | 200 bytes |
| `message` | 512 bytes |
| `path`, `query` | 2 kB each |
| `user_agent` | 512 bytes |
| `referer` | 1 kB |
| header value in `full` | 8 kB |
| `body` in `full` | 64 kB |
| headers, cookies | 64 and 32 entries |

Control characters and invalid UTF-8 are written as escapes, as in the terminal output.

## 5. `counts`: what was analysed

| Field | Content |
| --- | --- |
| `run` | The run |
| `from`, `to` | The period counted |
| `analysed` | Requests analysed, with or without a record |
| `recorded`, `alerts`, `incomplete` | Of these: request records written, alerts, analyses that could not inspect everything |

A `counts` record is written when a request comes a minute or more after the start of the period being counted, and at the end of a run. (The live service will also write one every minute when no request comes.) This is how requests without a record are still counted (R1).

## 6. Masking (R4, M11)

1. **Never recorded:** the values of `Cookie`, `Authorization` and `Proxy-Authorization`, not even in `full`. Cookies appear only as name and hash.
2. **Secret names.** A parameter whose name contains one of these (any case) is secret:

   `pass`, `pwd`, `secret`, `token`, `session`, `sessid`, `auth`, `csrf`, `xsrf`, `apikey`, `api_key`, `api-key`, `access_key`, `private_key`, `card`, `cvv`

   This covers query, form, JSON (the last part of the name, for example `json.user.password`) and multipart fields. `records.secret_names` adds names.
3. **Findings at a secret place**, such as `ARGS:password`, `REQUEST_COOKIES:sid` or `REQUEST_HEADERS:Authorization`:
   - the rule and the location are kept;
   - `matched` and `data` become `[masked]`;
   - a message that can carry request content becomes `[hidden: contains request content]`.
4. **Clean-up pass.** Every secret value of the request is collected as received, decoded and lower-cased. These forms are replaced by `[masked]` in all recorded text, which also catches a password inside the User-Agent, a message or a Referer.
   - Values shorter than 4 characters are left out of this general pass, because a value like `1` would mask unrelated text everywhere.
   - They are still masked in a **whole text**: a finding at `QUERY_STRING`, `REQUEST_BODY`, `REQUEST_LINE`, `REQUEST_URI`, `REQUEST_URI_RAW`, `FULL_REQUEST` or `XML`, and the `full` body. Such a text holds every parameter, for example a three-digit card code.
5. **Tests.** `TestNoSecretReachesTheDashboard` runs the real CRS configuration on `testdata/requests/secrets.json` and checks the record files, every API answer and every page. `FuzzSecretsAreMasked` checks the same property for any secret and request around it.

**Known limits:**

1. A secret in the path itself, such as `/reset/8f3a…`, is recorded. Profiles (A04) can mask it later.
2. A secret that a rule has transformed beyond decoding and lower-casing, or captured only in part, can remain in a finding at a place that is not secret. Example: a `TX.0` capture that holds half of a password, found within `REQUEST_BODY`.
3. Masking can be wider than needed. A secret value of 4 or more characters is masked wherever it appears; in the CRS tests a password `test` turns the User-Agent `OWASP CRS test agent` into `OWASP CRS [masked] agent`. A short secret can do the same inside a whole text. This is the safe direction for M11.

## 7. Example

A request record, shortened (`internal/record/testdata/request-record.json` has the whole one):

```json
{"type":"request","schema":1,"id":"ohzuckaji67xdhha5g5mx5i7nw","run":"aaqrrwyoxmretmywstso33umqx",
 "time":"2026-10-23T19:36:59.1Z","alert":true,"decided_by":"rule layer only",
 "client":{"ip":"203.0.113.9","port":51234},"server":{"host":"shop.example.com"},
 "request":{"method":"POST","path":"/login","content_type":"application/x-www-form-urlencoded",
            "body_length":47,"header_names":["Host","User-Agent","Content-Type","Content-Length"]},
 "analysis":{"complete":true,"body":"inspected","body_format":"form"},
 "findings":[{"rule_id":942100,"severity":"CRITICAL","message":"SQL Injection Attack Detected via libinjection",
              "location":"ARGS:password","matched":"[masked]","data":"[masked]","action":"pass"}],
 "score":{"total":5,"threshold":5,"exceeded":true,"categories":{"sql_injection":5}},
 "engine":{"version":"0.1.0-dev","crs":"OWASP_CRS/4.30.0","paranoia_level":1,"config":"sha256:bae5…"}}
```
