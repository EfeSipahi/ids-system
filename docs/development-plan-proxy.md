# Development plan: live traffic through Caddy (A01)

Decided by the user on 26 October 2026, decisions T1–T12 (main plan section 11.27). This document is the plan of the work and its progress.

## Context

1. Why. The rule layer, the records, the dashboard and the hand-written profiles are done; the last step was committed on 25 October 2026 as `71ffe71`. Next in the user's order is the proxy and TLS step (A01, A08). Until now the IDS reads requests only from files (`ids-offline`). This step lets it analyse live traffic without ever delaying the site (M09).
2. Decided by the user (26 October 2026), T1–T12:

   | # | Decision |
   | --- | --- |
   | T1 | Caddy with our own small Go copier module first; the Nginx mirror input second; an Nginx module (C or Rust) later |
   | T2 | A Unix socket, our own frames, two-way: copies go to the IDS, decisions (K4) come back. The format must not depend on the road, so TCP can come later |
   | T3 | Request bodies are copied while they stream, with a 12.5 MB limit (Coraza's `SecRequestBodyLimit` 13,107,200). Past it, the first part is analysed and the record says "body partial", shown clearly, because Coraza warns that an attacker can pad an attack with junk past the limit |
   | T4 | Responses: status and headers always; the body only for `text/plain`, `text/html` and `text/xml` (changeable), up to 512 KB (Coraza's `SecResponseBodyLimit` 524,288), partial past that. The IDS unzips gzip and deflate |
   | T5 | The client IP comes only from Caddy's data (`trusted_proxies`, none trusted by default). The IDS never reads `X-Forwarded-For` itself. Records keep both the connection address and the client IP |
   | T6 | The application name comes from the Caddy config (`ids_copy { application shop }`), with Host plus path as the fallback (F3). An unknown name counts as "no application" and is shown in the dashboard |
   | T7 | A queue with a size limit (1,000 copies or 64 MB, to be measured in the lab). When it is full, copies are dropped and counted, and the dashboard shows "not analysed: N (queue full)". The IDS has its own queue with the same rule |
   | T8 | Fail-open: traffic keeps flowing. The copier reconnects every second and sends a gap record, for example "14:02–14:05: 1,240 requests not analysed" |
   | T9 | A lab all on this machine: Caddy built with `xcaddy`, `tls internal`, a tiny Go test app, and a replay tool over HTTPS. It measures the added time, drops under overload, an IDS stop and start, and checks that the 396 CSIC validation and test requests give the same results live as in `ids-offline` |
   | T10 | Caddy handles HTTPS when it is the front proxy (automatic certificates, the owner's own files, or `tls internal`), or listens on plain HTTP on `127.0.0.1` behind Nginx or a load balancer. HTTPS with certificate checks when the app is on another machine; never `tls_insecure_skip_verify`. Keys never reach the IDS, and copies stay in memory only. The TLS version, cipher, SNI and HTTP version are recorded, as record fields only, not ML inputs. TLS passthrough is not supported |
   | T11 | The dependency `github.com/caddyserver/caddy/v2` only in `caddy-module/`, with its own `go.mod`, plus the `xcaddy` tool. The IDS's own `go.mod` stays unchanged |
   | T12 | A new command, `cmd/ids-live` |

3. Still open, to be discussed after this plan; the user called them next steps:
   1. whether `ids-offline` keeps its name (A: keep it; B: rename it to `ids-analyze`; C: one `ids` program with subcommands);
   2. the user's idea of an installer, plus setup from the dashboard (main plan section 6.15, I3).

   Also noted for later in the main plan: records from several machines, a shared block list for K4, and the TCP option.
4. Consequences of the decisions, found while reading the code. They were approved with this plan:
   1. C1: the body limit. `internal/httpmodel/parse.go` parses bodies up to `DefaultBodyLimit`, 1 MiB, a first default (A02). A larger body was "not inspected" as a whole. T3 needs analysis up to 12.5 MB and "the first part past the limit". So the limit becomes the setting `request_body_limit`, default 13,107,200, and a body over it is parsed up to the limit and marked "partly inspected". This applies to `ids-offline` too, so both inputs follow one rule.
   2. C2: headers. Go's HTTP server, which Caddy uses, gives headers as a map with canonical names (`cache-control` becomes `Cache-Control`) and loses their order; `Host` and `Transfer-Encoding` are taken out of the map. The copier rebuilds them. This is the "proxy changes" item of M16. The T9 equality check shows whether it changes any result.
   3. C3: requests that Go's server rejects before any handler runs, such as a broken request line or headers that are too large, never reach the copier. They never reach the app either. This is documented, not counted.
   4. C4: the dashboard counts a record of an unknown type as unreadable (`internal/dashboard/store.go`). The new `gap` record therefore needs a dashboard change, and the readers' rule in `docs/records-format.md` becomes "skip a type you don't know".
   5. C5: "one writer per records folder" was a rule but not enforced. A long-running `ids-live` makes a second writer likely, so `record.Open` takes a lock file.
   6. C6: response bodies are copied and carried now (T4), but nothing reads them until the response rules (K8). Unzipping gzip and deflate is therefore built in the K8 step, where it is used. Records of this step show the response's status, type, sizes and encoding.
   7. C7: a copy is sent when the response ends. For a long response, the request part is sent after 10 seconds at the latest, with the response marked "not finished" (a default that can be changed, checked in the lab). A WebSocket or other upgrade is sent at the upgrade.
   8. C8: copies inside `ids-live`'s queue when it crashes are lost without a count, at most the queue size. A known limit, documented.

## Research behind T1 and T2 (25–26 October 2026)

1. Five proxies were compared from their documentation: Nginx, HAProxy, Envoy, Caddy and Traefik.

   | Proxy | How a copy is made | Does the client's request wait? | Response copy |
   | --- | --- | --- | --- |
   | Nginx | `mirror`, a second HTTP request | Not directly, but the next request on a kept-alive connection waits until the copy is done (an Nginx developer on the mailing list); the whole body is read first | No |
   | HAProxy | SPOE messages to an agent | Yes: each event waits for the agent's reply, up to `timeout processing` (`option async` is deprecated and ignored) | Headers, and only the first buffer of the body |
   | Envoy | mirror policy, or `ext_proc` in observability mode | No ("fire and forget", "Send and Go") | Only with `ext_proc`, over gRPC |
   | Caddy | our own Go module inside Caddy | No, when the module only queues the copy | Yes |
   | Traefik | `mirroring` service | No, but a body over `maxBodySize` is not copied at all, without notice | No |

2. How real products connect to an existing Nginx: a thin module plus a separate agent (Fastly's Next-Gen WAF, over a Unix socket or TCP); a copy by Nginx `mirror` (Wallarm's out-of-band mode, requests only); network capture (only where the traffic is not encrypted); or an extra proxy in the chain. Nginx is the most used web server, at 31.4 % of the sites whose server is known (W3Techs, August 2026).
3. Coraza runs inside the proxy (Caddy, Envoy, Traefik), except coraza-spoa for HAProxy, a separate program over TCP that takes the application's name from HAProxy, as T6 does. Coraza writes its audit logs per machine and can send them to a collector (`https`, `syslog`). Its persistent collections do not work: `initcol` does nothing in v3.8.1 (`internal/actions/initcol.go`), so it keeps no memory of an IP between requests.
4. Measured on this laptop, in its low-power mode:
   1. one extra local proxy hop (Go's standard reverse proxy standing in for Caddy, 10,000 requests × 3 rounds): 144–178 µs added for a 1 KB response, 273–324 µs for 64 KB;
   2. a Unix socket round trip (a frame there, one byte back, 10,000 × 3): 19 µs median for 1 KB, 26 µs for 16 KB; the slowest 1 in 100 were 29–105 µs. This is the cost of waiting for a separate IDS, should blocking before forwarding ever be wanted;
   3. Linux limits a Unix socket's path to about 108 bytes: the first measurement failed on a long path.

## Design

### The pieces

```
Client ==HTTPS==> [ caddy + ids_copy ] --HTTP--> app
                         |  frames over /run/ids/copy.sock (two-way)
                         v
                  [ ids-live ]  engine + profiles (as ids-offline)  -> records folder
                         |
                  [ ids-dashboard ]  reads the records (plus gaps and the new fields)
```

### Frame format: `docs/copy-format.md`, `internal/copyframe` (new)

1. A frame is a 4-byte big-endian length, a 1-byte type and the content. Types:
   - `hello`, both ways at connect: format version 1, the program and its version;
   - `copy`, from the copier: a JSON metadata part, then the request body bytes, then the response body bytes, each with a 4-byte length. Bodies are raw bytes, never base64;
   - `missed`, from the copier: from, to, count and reason (`queue full`, `not connected`);
   - `decision`, from the IDS: reserved for K4, not sent yet. An unknown type is skipped.
2. The metadata JSON is read strictly: an unknown field is an error, as in `internal/offline`. Its fields:
   - `id`, `time`, `duration_ms`, `application`;
   - `client` (Caddy's client IP and port), `connection` (the direct peer), `server`;
   - `tls` (version, cipher, server name, ALPN), left out for plain HTTP;
   - `request` (method, target as received, protocol, headers as [name, value] pairs like the offline files, body length, bytes copied, whether the body ended);
   - `response` (status, headers, content type, encoding, body length, bytes copied, and a note: "type not copied", "over the limit", "not finished" or "upgraded").
3. A frame larger than the IDS's `max_frame_mb` is refused with a clear error, and the connection is closed. The copier counts that copy as missed ("refused by the IDS").
4. The package lives in `internal/` and is shared by `ids-live` and the copier. The copier's module path, `github.com/EfeSipahi/ids-system/caddy-module`, lies inside this repository's path, so Go allows the import.

### Body limit and partial bodies: `internal/httpmodel`, `internal/config`, `internal/engine`

1. A product setting `request_body_limit` (bytes, default 13,107,200) replaces the fixed 1 MiB. `httpmodel` gets an option for the limit, which `WithBodyFormat` keeps.
2. A new field of `Received` gives the full length of a body when only its first part was copied. When the body was cut, by the copier or by the limit, the first part is parsed, `Status.Body` is `BodyPartlyInspected`, and `BodyReason` says so, for example "only the first 13107200 of 41943040 bytes were inspected".
3. Every place that reads the body for analysis uses that first part, including `rawBody` (`internal/engine/targets.go`).

### The live input: `internal/live` (new) and `cmd/ids-live` (new)

1. An optional `live` section in the product config: `socket`, `workers` (default 2), `queue_copies` (1,000), `queue_mb` (64), `max_frame_mb` (16). `ids-live` needs `live` and `records`; flags `-config`, `-socket`, `-records`.
2. The socket path is checked at start, and one that is too long gets a clear error. A stale socket file is removed only when nothing answers on it. The socket's permission is 0660.
3. `internal/live` is the socket input, next to `internal/offline`, the file input (M01). It accepts connections, answers `hello`, reads frames into a queue, and turns each copy into an `httpmodel.Request`. Missed copies become gap records. When its queue is full, a copy is dropped and counted ("IDS queue full").
4. Workers run what `ids-offline` runs for each request: the application by the copy's name, otherwise by Host and path; `EvaluateWith`; the profile check; `Recorder.Add`. The rule set is shared and read-only (M21); the recorder is safe for many goroutines.
5. `Recorder.Flush` runs every minute. On SIGTERM, `ids-live` stops reading, drains the queue within a deadline, and closes the recorder.
6. The startup report moves from `cmd/ids-offline` to `internal/result`, so both commands print the same report. `ids-offline`'s output stays byte-identical.

### Records: `internal/record`, `docs/records-format.md` (schema 1, additions only)

1. The `request` record gets optional `connection`, `tls` and `response`. `client` is Caddy's client IP (T5).
2. A new `gap` record: run, from, to, missed, reason, and source (`copier` or `ids`).
3. The `counts` record gets optional `unknown_applications` (names with counts, T6) and `copiers` (how many copiers were connected in the window), so "nothing arrives" can be told from "nothing happens".
4. The `start` record gets an optional `input` (kind `live` and the socket). `ids-offline` writes none, so its golden test is unchanged.
5. A lock file in the records folder makes a second writer fail with "the records folder is in use by another writer". It uses Linux `flock` from `syscall`; on other systems there is no lock, and the format document says so.
6. Masking is unchanged (M11). A new test sends a copy with a password, a secret cookie and a profile secret through `internal/live`, and checks that no value reaches the records.

### The copier: `caddy-module/` (new Go module)

1. A Caddy HTTP handler `http.handlers.ids_copy`, built as in Caddy's "Extending Caddy" example. It is placed first (`order ids_copy first`), so it sees the request before any rewrite.
2. Caddyfile: `application`, `socket`, and only when changed: `request_body_limit`, `response_body_limit`, `response_types`, `queue_copies`, `queue_mb`, `max_wait`.
3. For each request it:
   - wraps the request body, copying bytes as they pass, up to the limit, and counting the rest;
   - wraps the response writer (keeping Flush, Hijack and `Unwrap`), copying the body only for the listed types, up to the limit;
   - calls the next handler;
   - then builds the copy and puts it in the queue without waiting. When the queue is full, it only counts.

   Headers are rebuilt with `Host` first, then sorted by name, and `Transfer-Encoding` comes back from the request's field. The client IP is Caddy's own value, which follows `trusted_proxies`. TLS facts come from the request's TLS state.
4. There is one sender per socket path, shared across config reloads with `caddy.UsagePool`, because Caddy's documentation says module instances overlap during reloads. It connects, sends `hello`, then frames. When it can't connect, copies are dropped and counted with their time span, and it retries every second. On reconnecting it first sends a `missed` frame.
5. Its `go.mod` requires the latest Caddy v2 release at build time (pinned) and this repository, with `replace => ../`. Build:
   ```bash
   xcaddy build --with github.com/EfeSipahi/ids-system/caddy-module=./caddy-module --with github.com/EfeSipahi/ids-system=.
   ```
   The second `--with` is needed because `replace` lines in a dependency's `go.mod` don't apply.

### Dashboard: `internal/dashboard` (read-only, `el()` only, no inline script)

1. The store reads `gap` records. The overview gives the not-analysed total by reason, the latest gaps, unknown application names, and "no copier connected" when the last counts say 0.
2. The detail page shows the connection, TLS and response. The Engine page shows the input (a live socket or files).

### Lab: `lab/` (main module, no new dependency)

1. `lab/Caddyfile`:
   - `skip_install_trust`, so the system trust store is not touched;
   - `local_certs`, `auto_https disable_redirects`, `admin off`;
   - storage in a lab data folder, so nothing goes in the home folder;
   - `https://localhost:8080` with `ids_copy`, and `https://localhost:8443` without it, both in front of the same test app.
2. `lab/testapp` answers text, HTML, an image, a gzip response, a slow response and a WebSocket upgrade.
3. `lab/replay` sends offline example files over TLS as raw HTTP/1.1 bytes, exactly as written, with the order and case of headers kept. It trusts Caddy's local root certificate, and runs sequentially or in parallel. A few requests also go over HTTP/2 with Go's client, and over HTTP/3 with curl if this machine's curl supports it.
4. `lab/compare` compares the request records of two folders as multisets: request line, findings, score, profile kinds. Cookie hashes are left out, because each folder has its own key.
5. `lab/csic-live.json` is `configs/csic-shop.json` plus `records` and `live`. Lab outputs go to a temporary folder, never into the repository.

## Stages

Each stage ends with its tests passing and a note in the progress section.

1. Decision documents: this file; the main plan (A01 status, history 11.27, open items); `context.md`; the stale "not committed yet" lines in `context.md` and `docs/project-history.md`.
2. Frames: `docs/copy-format.md` and `internal/copyframe`, with round-trip tests, limit tests and `FuzzReadFrame` (no panic, no allocation past the limits).
3. Body limit: the `request_body_limit` setting and partial bodies, with tests for a cut form, JSON and multipart body. Unchanged counts: 2,916 CRS alerts at level 1, and 96 of 500 normal and 176 of 500 anomalous CSIC requests flagged at level 1.
4. Live input and records:
   - `internal/live`, `cmd/ids-live`, the `live` config;
   - the new record fields, `gap`, the lock file, the shared startup report;
   - tests with a fake copier writing frames into a test socket: requests with rule findings, profile findings, no application and an unknown name; a full queue, a broken frame, a frame too large, a version mismatch, shutdown draining;
   - a golden file for a live record, and the masking test.
5. Copier: `caddy-module/`, with unit tests using `httptest` and a next handler:
   - request bodies under, at and over the limit, and cut while streaming;
   - response types, sizes and `max_wait`;
   - an upgrade, a full queue, the IDS down and back (a `missed` frame), a config reload with the pool;
   - header rebuilding, and the client IP with and without `trusted_proxies`.

   Then `xcaddy build`.
6. Dashboard: gaps, not-analysed totals, unknown names, the copier status, and the detail and Engine fields. Go tests, then one batched browser check of demo records with gaps.
7. Lab and measurements (T9); see Verification, item 5.
8. Close: `docs/records-format.md`, `docs/copy-format.md`, `docs/project-history.md`, `context.md`, main plan history 11.28, the full checks. The commit only when the user asks.

## Rules for the work

1. Expected values come from the data, Caddy's or Coraza's documentation and source, or measurements; never guessed. Defaults marked "to be measured" are reported, and changed only with the user's approval.
2. The only new dependency is Caddy and what it pulls in, inside `caddy-module/` only, plus `xcaddy` as a tool (T11). The main `go.mod` is unchanged.
3. Copies never go to disk or into logs. `ids-live` never prints a request value. The dashboard stays read-only.
4. Browser checks: one batched call per round, on the dashboard tab only, after checking its address.
5. No commit unless the user asks; `proje_oneri_formu.docx` is never committed.
6. Lab sockets use short paths, because a socket path can't be longer than about 108 bytes.

## Verification

1. Commands:
   - `gofmt -l .`, `go vet ./...`, `go test ./...`;
   - `go test -race ./internal/live/... ./internal/copyframe/... ./internal/record/... ./internal/dashboard/... ./cmd/...`;
   - in `caddy-module/`: `go vet ./...` and `go test -race ./...`;
   - the engine race run, if `httpmodel` or `engine` changed: `go test -race -timeout 60m ./internal/engine/...`.
2. Unchanged numbers: without `live`, `ids-offline` gives the same output as before (golden tests), 2,916 CRS alerts at level 1, and CSIC 96 / 176. With `configs/csic-shop.json`, the numbers of the profile plan's note 17 are unchanged.
3. Fuzz: `FuzzReadFrame`, and `FuzzSecretsAreMasked` with live input, run for a fixed time without failures.
4. Dashboard: Go tests, and one batched browser check of gaps, not-analysed totals, the copier status and the TLS, connection and response fields, in dark and light, with no console errors and no overflow.
5. Lab (T9), with the results written into the notes below:
   1. Equality: the 396 CSIC validation and test requests sent through Caddy give the same request records in `ids-live` as `ids-offline` on the same files (`lab/compare`), and "analysed" is 396 in both. Any difference is examined and written down, never adjusted away.
   2. Added time: the median and the slowest 1 in 100, with and without `ids_copy`, for sequential and parallel replays, with `ids-live` running, stopped and slowed. The check: the site's times don't change when `ids-live` is stopped or slow (M09).
   3. Overload: a small queue and one slow worker under a burst. Every request is answered; the drops equal the gap counts; nothing is lost without a count.
   4. Stop and start: `ids-live` is stopped during a replay of a known number of requests. Every request is answered, and the gap record's count equals the requests sent while it was down.
   5. TLS and client IP: records show TLS 1.3 with its cipher and SNI. `X-Forwarded-For` from the replay is ignored without `trusted_proxies`, and used when `127.0.0.1` is trusted. HTTP/2 works, and HTTP/3 if curl supports it.
   6. Responses: text up to 512 KB is copied; an image is not; a slow response is sent after `max_wait`; an upgrade at the upgrade. Memory use under the burst is reported.

## Progress

| Stage | Status |
| --- | --- |
| 1. Decision documents | Done 26 October 2026 |
| 2. Frames | Done 26 October 2026 |
| 3. Body limit | Done 26 October 2026 |
| 4. Live input and records | Not started |
| 5. Copier | Not started |
| 6. Dashboard | Not started |
| 7. Lab and measurements | Not started |
| 8. Close | Not started |

### Notes from the work

1. Stage 1: this document, the main plan (sections 1, 6.1, 6.13, 6.15 and 11.27) and `context.md` were written on 26 October 2026.
2. Stage 2: `docs/copy-format.md` and `internal/copyframe` were written on 26 October 2026. Three changes to the design above, made while writing it:
   1. The request line and the headers are not in the JSON part. They travel as a list of raw byte strings (method, target, protocol, then names and values), because JSON can't hold bytes that are not UTF-8, such as a Latin-1 letter in a target (M16). Only plain-text facts, such as addresses, times and sizes, stay in the JSON part.
   2. The response's headers travel the same way. Its content type and encoding are read from those headers, so they are not repeated in the JSON part.
   3. There is no "bytes copied" field and no "over the limit" note: the length of the body in the frame is the bytes copied, and a body shorter than `body_length` was cut by the limit. The notes left are `type not copied`, `not finished` and `upgraded`.

   Checks: `go vet` and `go test` pass; gofmt is clean; `FuzzReadFrame` ran for 60 seconds (6.1 million inputs) without a failure. Every copy the fuzzer got accepted was written again and read back unchanged.
3. Stage 3: the body limit, 26 October 2026.
   1. What changed:
      - `httpmodel.DefaultBodyLimit` is now 13,107,200 bytes, the `SecRequestBodyLimit` of Coraza's recommended configuration. `httpmodel.NewWith` takes the limit as an option, and `WithBodyFormat` keeps it. The highest limit is 1 GiB, as in Coraza's `Validate`.
      - A body longer than the limit is parsed up to the limit and shows "partly inspected", for example "only the first 16 of 23 bytes were inspected". It was "not inspected" as a whole before. The received body is kept whole.
      - `Received` has two new fields for the live input: `BodyLength`, the length of the whole body when only its first part was copied, and `BodyUnfinished`, when the body was not received to its end. Both give "partly inspected" with a reason that says so.
      - `REQUEST_BODY` and `REQUEST_BODY_LENGTH` give the first part, as Coraza does with ProcessPartial (its urlencoded and raw readers set the length to what was buffered).
      - The record's `request.body_length` and the profile's content-type check use the length of the whole body.
      - The product setting `request_body_limit` (1 to 1,073,741,824; left out means the default) reaches the parser through `config.Product.Parsing` and `offline.LoadFileWith`. The product configurations don't set it, so their fingerprints are unchanged.
   2. What Coraza does that this does not: Coraza sets `INBOUND_DATA_ERROR` when a body reaches the limit, and `REQBODY_ERROR` when a reader stops early. The engine has neither variable, and no CRS 4.30.0 rule reads them; the request's status carries the same facts.
   3. A reader that stops where the body was cut gives both reasons, for example "only the first 17 of 4000 bytes were inspected, and the json reader stopped before their end: …". A JSON value cut in the middle of its string is not seen; a cut form or multipart value is seen up to the cut. This is the junk-padding risk Coraza warns about (T3).
   4. Checks:
      - new tests for a cut form, JSON and multipart body, an unfinished body, a body of which nothing was copied, the limit in the engine, and the setting;
      - `go vet` and `go test ./...` pass;
      - the full `-json` output of `ids-offline` and the request records are the same before and after (run IDs, times and cookie hashes left out) for four runs: the CRS tests at level 1 with `configs/crs-first-engine.json` (2,916 alerts) and at level 4 with `testdata/crs-tests.json`, and the 1,000 CSIC requests with `configs/crs-first-engine.json` (96 of 500 normal and 176 of 500 anomalous flagged) and with `configs/csic-shop.json`. No test request has a body over 1 MiB, so the old limit never applied to them.
