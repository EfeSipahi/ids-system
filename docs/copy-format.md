# Copy format

Written: 26 October 2026. Format version: 1.

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
4. Each side first sends a `hello` frame. When the IDS does not speak the copier's format version, its `hello` carries an `error` text and it closes the connection.
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
   - A frame longer than your limit is refused before it is read (`ids-live`: `live.max_frame_mb`, default 16 MB). Close the connection; the next frame's start is not known.
   - A frame that breaks any rule below is an error, and the connection is closed. A copy is never "partly" accepted.
   - JSON parts are read strictly: a field you don't know is an error. New optional fields need a reader that knows them, so the format version changes with them.

## 3. `hello`

| Field | Meaning |
| --- | --- |
| `format` | The format version the sender speaks: `1` |
| `program` | The sender, for example `caddy ids_copy` or `ids-live`. 1–64 bytes of printable text |
| `version` | The sender's version. Optional; at most 64 bytes of printable text |
| `error` | Only from the IDS: why it refuses the connection. Optional; at most 1,024 bytes of printable text |

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
| `response.status` | The response's status, 100–999. `response` is left out when no response was written, for example because the client went away |
| `response.body_length` | How many body bytes the application sent |
| `response.note` | Why the copied body is not the response's body: `type not copied` (the copier copies only some types, T4), `not finished` (the copy was sent while the response was still running), `upgraded` (the connection became, for example, a WebSocket). Optional |

Rules:

1. Addresses are IPv4 or IPv6 addresses without a port; ports are 0–65535. Either may be left out when unknown.
2. The copied request body is never longer than `request.body_length`. When it is shorter, the copier's limit cut it (T3). When `body_complete` is false, the client stopped sending or the application stopped reading. Either way the IDS reports the analysis as incomplete (M05).
3. The copied response body is never longer than `response.body_length`.
4. A response head or body without `response` is an error.

### 4.3. What a copier keeps

1. The Caddy copier runs first among Caddy's handlers, so it copies the request before any rewrite.
2. Caddy runs on Go's HTTP server, which keeps the headers in a map. So:
   - names are in Go's canonical form (`cache-control` becomes `Cache-Control`);
   - the order of different headers is lost, but repeated values of one name keep their order.

   The copier writes `Host` first, then the other headers sorted by name, with `Transfer-Encoding` restored from the request. The lab compares results with the original requests (development plan, verification 5).
3. Requests that Go's server rejects before any handler runs, for example with a broken request line or headers that are too large, never reach the copier. They never reach the application either.

## 5. `missed`

| Field | Meaning |
| --- | --- |
| `from`, `to` | The first and last time of the requests that were not copied. Both are required, and `to` may not be before `from` |
| `count` | How many, 1 or more |
| `reason` | `queue full` (the copier's queue was full, T7), `not connected` (the IDS could not be reached, T8), `refused by the IDS` (the IDS refused a frame, for example one over its size limit). 1–64 bytes of printable text |

`ids-live` turns each `missed` frame into a `gap` record, which the dashboard shows (`docs/records-format.md`).
