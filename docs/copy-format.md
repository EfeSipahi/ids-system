# Copy format

Written: 26 October 2026. Updated 18 November 2026, before any copier used version 1: the IDS's hello gives its frame limit (`max_frame`), and the copier fits each copy into it (decided by the user); the response note `handler error`. Updated 19 November 2026: what the lab showed about Caddy (section 4.3), and how to set up both sides (section 6). Format version: 1.

This is the contract between a proxy's copier and the IDS: how copies of requests and responses travel from the proxy to `ids-live`, and, later, how decisions travel back (K4).

```
Client ==HTTPS==> proxy + copier --HTTP--> application
                        |
                        | frames over a Unix socket, both ways
                        v
                    ids-live --writes--> records/*.jsonl --reads--> ids-dashboard
```

The decisions behind it are T2–T8 and T10 (main plan, section 11.27; [development-plan-proxy.md](development-plan-proxy.md)). The code is in `internal/copyframe`; the Caddy copier is in `caddy-module/`.

## 1. The connection

1. The copier connects to a Unix socket that `ids-live` listens on, set in the product configuration (`live.socket`). The socket has permission 0660: only the users that may send copies can connect. Anyone who can write to it can add records, so it must not be reachable by others.
2. A socket path can't be longer than about 108 bytes on Linux. `ids-live` checks the path when it starts.
3. Nothing in a frame depends on the connection (T2). A TCP connection could carry the same frames later; it would need TLS and authentication of its own, which are not part of version 1.
4. Each side first sends a `hello` frame: the copier first, then the IDS. When the IDS does not speak the copier's format version, its `hello` carries an `error` text and it closes the connection. Otherwise its `hello` gives the longest frame it accepts (`max_frame`), and the copier never sends a longer one (section 4.4).
5. After that the copier sends `copy` and `missed` frames. The IDS sends nothing more in version 1; `decision` frames are reserved for blocking (K4).
6. When the connection breaks, the copier counts the copies it could not send and reconnects (T8). Copies are never written to disk on either side (T10).

## 2. Frames

1. A frame is:

   | Bytes | Content |
   | --- | --- |
   | 4 | The length of the rest of the frame, big-endian: the type byte plus the content |
   | 1 | The type |
   | length − 1 | The content |

2. Types:

   | Type | Name | Sent by | Content |
   | --- | --- | --- | --- |
   | 1 | `hello` | both, first | JSON (section 3) |
   | 2 | `copy` | copier | one request and its response (section 4) |
   | 3 | `missed` | copier | JSON (section 5) |
   | 4 | `decision` | IDS | reserved for K4; not sent in version 1 |

3. Rules for readers:
   - A frame of a type you don't know is skipped.
   - A frame of length 0 has no type and is an error.
   - A frame longer than your limit is refused before it is read (`ids-live`: `live.max_frame_mb`, default 16 MB). Close the connection. A copier that keeps to the `max_frame` of the IDS's hello never sends one; the frames it sent after a refused one would be lost without a count.
   - A frame that breaks any rule below is an error, and the connection is closed. A copy is never "partly" accepted.
   - JSON parts are read strictly: a field you don't know is an error. New optional fields need a reader that knows them, so the format version changes with them.

## 3. `hello`

| Field | Meaning |
| --- | --- |
| `format` | The format version the sender speaks: `1` |
| `program` | The sender, for example `caddy ids_copy` or `ids-live`. 1–64 bytes of printable text |
| `version` | The sender's version. Optional; at most 64 bytes of printable text |
| `error` | Only from the IDS: why it refuses the connection. Optional; at most 1,024 bytes of printable text |
| `max_frame` | Only from the IDS: the longest frame it accepts, in bytes, as a frame's first 4 bytes count it (type byte and content). `ids-live` sends `live.max_frame_mb` × 1,048,576. Optional; 0 to 4,294,967,295; left out or 0 means the copier uses 16,777,216 |

"Printable text" here and below means UTF-8 without control characters.

## 4. `copy`

### 4.1. Layout of the content

The content is five parts in this order. A byte string is a 4-byte big-endian length and that many bytes. A list is a 4-byte big-endian count and that many byte strings.

| Part | Kind | Content |
| --- | --- | --- |
| metadata | byte string | JSON, at most 1 MiB (section 4.2) |
| request head | list | method, target, protocol, then a name and a value for each header |
| request body | byte string | the first part of the request body, up to the copier's limit |
| response head | list | a name and a value for each response header; empty when there is no response |
| response body | byte string | the first part of the response body; empty when it was not copied |

Nothing may follow the response body. The method, the target and the protocol may not be empty, and neither may a header's name. A header's value may be empty.

The request line and the headers are raw bytes, not JSON. JSON can't hold bytes that are not UTF-8, such as a Latin-1 letter in a target, and the IDS must see what the proxy received (M16).

### 4.2. Metadata

| Field | Meaning |
| --- | --- |
| `id` | The request's ID at the proxy (for Caddy, its request UUID), to find it in the proxy's logs. 1–64 bytes of printable text |
| `time` | When the proxy received the request, RFC 3339 in UTC |
| `duration_ms` | How long it took from then until the copy was made |
| `application` | The application's name from the proxy's configuration (T6). Optional; at most 64 bytes of printable text |
| `client.ip`, `client.port` | The client as the proxy determined it: the connection's address, or the one a trusted proxy in front of it gave (T5). Never a header the proxy does not trust |
| `connection.ip`, `connection.port` | The address the connection came from: the client itself, or a proxy in front |
| `server.ip`, `server.port` | The address the connection was made to |
| `tls.version`, `tls.cipher` | For a TLS connection: for example `TLS 1.3` and `TLS_AES_128_GCM_SHA256`. `tls` is left out for plain HTTP |
| `tls.server_name`, `tls.alpn` | The name the client asked for (SNI, at most 255 bytes), and the agreed protocol, such as `h2`. Optional |
| `request.body_length` | How many body bytes the client sent, as far as they were read |
| `request.body_complete` | `true` when the body was read to its end |
| `response.status` | The response's status, 100–999. `response` is left out when no response was written, for example because the client went away, or none had been started when the copy was sent (`max_wait`, C7) |
| `response.body_length` | How many body bytes the application sent |
| `response.note` | Why the copied body is not the response's body: `type not copied` (the copier copies only some types, T4), `not finished` (the copy was sent while the response was still running), `upgraded` (the connection became, for example, a WebSocket), `handler error` (the application's handler returned an error and the proxy wrote the response itself, after the copier's part: the status is the error's, and the copier saw no headers or body). Optional |

Rules:

1. Addresses are IPv4 or IPv6 addresses without a port; ports are 0–65535. Either may be left out when unknown.
2. The copied request body is never longer than `request.body_length`. When it is shorter, the copier's limit cut it (T3). When `body_complete` is false, the client stopped sending or the application stopped reading. Either way the IDS reports the analysis as incomplete (M05).
3. The copied response body is never longer than `response.body_length`.
4. A response head or body without `response` is an error.

### 4.3. What a copier keeps

1. The Caddy copier runs first among Caddy's handlers, so it copies the request before any rewrite. It registers that place itself (before `tracing`, the first of Caddy's standard order), so a Caddyfile needs no `order` option.
2. Caddy runs on Go's HTTP server, which keeps the headers in a map. So:
   - names are in Go's canonical form (`cache-control` becomes `Cache-Control`);
   - the order of different headers is lost, but repeated values of one name keep their order.

   The copier writes `Host` first, then the other headers sorted by name, with `Transfer-Encoding` restored from the request. Response headers are sorted by name too; when the application set no `Content-Type`, the copy has the one Go's server sniffs and sends. The lab compares results with the original requests (development plan, verification 5).
3. Requests that Go's server rejects before any handler runs, for example with a broken request line or headers that are too large, never reach the copier. They never reach the application either.
4. The protocol in the request head is Go's name for it: `HTTP/1.1`, `HTTP/2.0` or `HTTP/3.0`. The lab sent requests over all three through the copier (development plan, note 7).
5. Caddy's `reverse_proxy` asks the application for gzip itself when the client did not, and unzips the answer. The copier, which runs before it, then sees the plain body and no `Content-Encoding`, which is what the client gets. A client that accepts gzip gets the compressed body, and so does the copy, with its `Content-Encoding` (found in the lab).

### 4.4. Fitting a copy into the IDS's limit

A copier's limits (12.5 MB of request body, 512 KB of response body by default) keep a copy under 16 MB. When they are raised above the IDS's `max_frame`, the copier shortens a copy that would be too long before it sends it:

1. It cuts the end of the response body, which the IDS does not analyse yet (K8).
2. If that is not enough, it drops the response body and cuts the end of the request body.
3. `body_length` keeps the length of the whole body, so the IDS analyses the first part and reports the body as partly inspected, as for any long body (T3).
4. Only a copy whose metadata and heads alone are longer than `max_frame` is not sent. The copier counts it as missed, reason `refused by the IDS`.

## 5. `missed`

| Field | Meaning |
| --- | --- |
| `from`, `to` | The first and last time of the requests that were not copied. Both are required, and `to` may not be before `from` |
| `count` | How many, 1 or more |
| `reason` | `queue full` (the copier's queue was full, T7), `not connected` (the IDS could not be reached, T8), `refused by the IDS` (the copy does not fit into the IDS's `max_frame` even without its bodies, section 4.4). 1–64 bytes of printable text |

`ids-live` turns each `missed` frame into a `gap` record, which the dashboard shows (`docs/records-format.md`).

## 6. Setting it up

Added 19 November 2026. The defaults of the queues and of the waits are first values. The lab measured how the copier and `ids-live` behave with them (development plan, note 7), and they were not changed.

### 6.1. `ids-live`

`ids-live -config FILE` reads the product configuration, the same file `ids-offline` reads, with a `live` section:

```json
"live": {"socket": "/run/ids/copy.sock"}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `socket` | none, required | The socket's path. A relative path starts at the configuration file's folder. At most 107 bytes; an abstract name (`@…`) is refused, because it has no file permissions |
| `workers` | 2 | How many copies are analysed at the same time, 1–256 |
| `queue_copies` | 1,000 | The most copies `ids-live` holds, waiting or being analysed, 1–1,000,000. A copy past it is dropped and counted (`queue full`) |
| `queue_mb` | 64 | The same in MiB, 1–16,384 |
| `max_frame_mb` | 16 | The longest frame it accepts, in MiB (section 3, `max_frame`), 1–1,024 and not more than `queue_mb` |

The flags `-socket` and `-records` replace the configuration's socket and records folder; with them, the configuration needs no `live` or `records` section. SIGTERM or SIGINT stops it: it stops reading, gives the queued copies 10 seconds, and writes what is left as a gap (`IDS stopped`).

### 6.2. The Caddy copier

Caddy is built with the module by xcaddy (v0.4.7 was used), from this repository's root:

```bash
xcaddy build v2.11.9 --with github.com/EfeSipahi/ids-system/caddy-module=./caddy-module --replace github.com/EfeSipahi/ids-system=.
```

A site in the Caddyfile:

```
shop.example.com {
	ids_copy {
		application shop
		socket /run/ids/copy.sock
	}
	reverse_proxy 127.0.0.1:9000
}
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `socket` | none, required | `ids-live`'s socket, at most 107 bytes |
| `application` | none | The application's name in the IDS's configuration (T6). Left out, the IDS chooses the application by Host and path |
| `request_body_limit` | 13,107,200 bytes | How much of a request body is copied, up to 1 GiB, written as `12MiB` or `500KB` (`KiB` and `MiB` count in 1,024s, `KB` and `MB` in 1,000s) |
| `response_body_limit` | 524,288 bytes | The same for a response body |
| `response_types` | `text/plain text/html text/xml` | The media types whose response body is copied. Case and parameters such as `charset` do not matter |
| `queue_copies` | 1,000 | The most copies waiting to be sent, 1–1,000,000 |
| `queue_mb` | 64 | The same in MiB, 1–16,384 |
| `max_wait` | `10s` | How long a copy waits for its response to end before it is sent, marked `not finished` (C7) |

1. No `order` option is needed: the module places itself first (section 4.3).
2. Sites that name the same socket share one connection and one queue. The queue limits of the copier loaded last hold, which after a reload are the new configuration's.
3. The user Caddy runs as must be able to write to the socket, whose permission is 0660: the same user as `ids-live`, or a member of the socket's group.
4. The client's address follows Caddy's `trusted_proxies` server option, which trusts no proxy by default (T5). `lab/Caddyfile` is a working example with `ids_copy` and `trusted_proxies`.

