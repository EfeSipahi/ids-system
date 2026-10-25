# Profile format

Written: 25 October 2026.

This is the contract for hand-written application profiles (A04). The decisions behind it are F1–F11 (main plan, section 11.25). The code is in `internal/profile`; the plan is `docs/development-plan-profiles.md`.

A profile is a JSON file that describes one application:

1. **What its normal requests look like:** an allow list of endpoints, parameters, cookies and headers (F4). A request outside it gets a profile finding.
2. **Which CRS checks are wrong for it:** rule exceptions (F5). They are applied to the requests of that application only, on the one shared rule set.
3. **Its paranoia level** (F11) and **its mode** (F6): whether its findings are alerts.

The profile result is kept apart from the CRS score (M10). The records carry both (`docs/records-format.md`).

## 1. Applications in the product configuration

```json
"applications": [
  { "name": "csic-shop", "hosts": ["localhost:8080"], "profile": "../profiles/csic-shop.json" }
],
"require_profile": false
```

| Field | Content |
| --- | --- |
| `name` | Letters, digits, `.`, `-` and `_`, at most 64 characters. Unique. `none` is kept for requests of no application |
| `hosts` | The `Host` header values of its requests, with the port when the requests carry one. Compared without regard to case |
| `paths` | Optional path prefixes, for applications that share a host. Each starts with `/`. Left out: every path of the hosts |
| `profile` | The profile file, relative to the configuration file |
| `require_profile` | Optional, off by default. When on, a request of no application gets a `no_profile` finding (F7) |

1. **Choosing the application (F3).** A request belongs to the application whose host is the request's first `Host` header, with the longest path prefix that fits the decoded path. No other header is read, so a client cannot pick another application's profile. `ids-offline -application NAME` checks every request against one application instead.
2. **A request of no application** gets the rules only, at the configuration's level, and `application: none` in records. This is not an incomplete analysis (M05).
3. **Start.** A profile that cannot be read stops the start, with the file, the place in it and what to change (F7). So does a host with the same path prefix in two applications.
4. **Fingerprint.** The configuration fingerprint covers each application's name and profile file, so records tell which profiles produced them (R7).

## 2. The file

Reading is strict: an unknown field is an error, so a misspelled field cannot be a silent default. Every object may have a `note` field for the author's explanations; it is never checked.

| Field | Content |
| --- | --- |
| `mode` | `monitor` (the default): findings are recorded, not alerts. `alert`: a request with a finding is an alert, labelled `profile` (F6) |
| `paranoia_level` | 1–4, the level of this application's requests. Left out: the configuration's level. `ids-offline -paranoia-level` changes only the configuration's level |
| `endpoints[]` | The allow list of methods and paths (section 3) |
| `cookies` | Checked cookies, by name (section 5) |
| `headers[]` | Checked headers (section 5) |
| `exceptions[]` | Rule exceptions (section 6) |

## 3. Endpoints

| Field | Content |
| --- | --- |
| `method` or `methods` | One HTTP method in upper case, or a list. Not both |
| `path` | `/a/b.jsp` exactly this path; `/item/{id}` one path part of any text, named `id`; `/images/*` everything below `/images/` (at least one more part) |
| `content_type` | Optional list of media types in lower case, without parameters, such as `application/json`. A request with a body of another type gets a `content_type` finding |
| `other_params` | `finding` (the default): a parameter the endpoint does not name is a finding. `allow`: it is not |
| `params` | The parameters, by name (section 4) |
| `path_params` | Values of the `{name}` parts, by name (section 4, without `in`, `required` and `repeat`) |

1. **Which endpoint.** Paths are compared with the request's path decoded once. Of the endpoints that fit the path and take the method, the most specific wins: an exact path, then `{name}` paths, then `*` paths; among those of one kind, the one with more literal parts, then the one written first. Two endpoints with the same method and path are an error.
2. **`.` and `..` are not resolved.** A path with such a part fits no endpoint and is an `unknown_endpoint`, because the application would resolve `/img/../admin.php` to `/admin.php`.
3. **Method.** A path that fits only endpoints of other methods gets a `method` finding that names the allowed ones.

## 4. Values: parameters and path parts

| Field | Content |
| --- | --- |
| `in` | `args` (the default): the query or a form body, as CRS's `ARGS`. `query`: the query only. `body`: a form body only, normal or multipart. `json`: a field of a JSON body, by its dotted path, such as `user.name`; `*` stands for any list index, as in `items.*.id` |
| `type` | `string` (the default), `integer`, `number`, `boolean` or `enum` |
| `required` | The parameter must be sent |
| `repeat` | It may be sent more than once. A JSON path with `*` may always repeat |
| `secret` | Its value is masked in records (F8), like a password |
| `min_length`, `max_length` | For `string`: bytes after URL decoding |
| `pattern` | For `string`: a Go regular expression that must match the whole value. Go's expressions run in time linear in the value |
| `min`, `max` | For `integer` and `number` |
| `values` | For `enum`: the allowed values |

1. `integer` is digits with an optional `-`. `number` is a decimal number, with an optional exponent. `boolean` is `true`, `false`, `1` or `0`.
2. **A body that was not read to its end** (M05) is not judged: its parameters are not reported as unknown, and a parameter that may come in the body is not reported as missing. The result says `body_checked: false`.
3. Multipart file fields are not checked (known limit).

## 5. Cookies and headers (F4h)

```json
"cookies": { "JSESSIONID": { "pattern": "[0-9A-F]{32}", "required": true } },
"headers": [ { "name": "X-API-Key", "paths": ["/api/*"], "methods": ["POST"], "required": true, "max_length": 64, "secret": true } ]
```

1. A cookie is written like a parameter, without `in`. A cookie the profile does not name is allowed.
2. A header check has a `name`, optional `paths` (path patterns with `*`, not `{name}`) and `methods`, and the value fields of section 4, without `in`. A header the profile does not name is always allowed.
3. Records never hold a cookie's value. A secret header's value is never written, as with `Authorization`.

## 6. Rule exceptions (F5)

Each exception has exactly one kind and a `reason`, which the startup report and the dashboard show next to it.

| Kind | Form | Effect |
| --- | --- | --- |
| 1. A CRS setting | `{"setting": "crs_validate_utf8_encoding", "value": "0", "reason": "…"}` | The application's requests start with this value |
| 2. Skip variables | `{"rule": 932350, "skip": ["ARGS_NAMES:pwd", "ARGS:/^json\\./"], "reason": "…"}` | The rule stops looking at these variables, as `SecRuleUpdateTargetById` does; for a chain, only its first rule |
| 3. Rule off | `{"rule": 920230, "off": true, "reason": "…"}` | The rule does not run for the application |

1. **Settings** a profile may change are CRS's per-application policy settings of `crs-setup.conf.example`:
   - text: `allowed_methods`, `allowed_request_content_type`, `allowed_request_content_type_charset`, `allowed_http_versions`, `restricted_extensions`, `restricted_headers_basic`, `restricted_headers_extended`;
   - `0` or `1`: `crs_validate_utf8_encoding`, `allow_method_override_parameter`;
   - a whole number of at least 1: `arg_name_length`, `arg_length`, `total_arg_length`, `max_num_args`, `max_file_size`, `combined_file_sizes`.

   Any other setting is an error that lists these. The paranoia level has its own field. Thresholds and scores wait for the decision mechanism (A06). `enforce_bodyproc_urlencoded` stays off (decision of 16 October 2026). A setting that an active rule of the configuration also sets while a request runs is an error that names the rule, because its value would replace the application's.
2. **Skip entries** are one variable each, written as in a SecRule but without `!` (skipping already means leaving it out) and without `&` (a count cannot be skipped).
3. **Protected rules (5c).** Rules of `REQUEST-901-INITIALIZATION.conf` (CRS's setup: the threshold and the starting values) and `REQUEST-949-BLOCKING-EVALUATION.conf` (the sum of the attack score) cannot be excepted. The error says why and what to do instead:
   ```
   profiles/shop.json: exceptions[1]: rule 949052 cannot be excepted.
   It is in REQUEST-949-BLOCKING-EVALUATION.conf, which adds up the attack score; without it this application would never raise an alert.
   Remove this exception, or except the attack rule that causes the false alarm.
   ```
4. **Errors:** a rule that is in none of the loaded files; two exceptions of one rule; the same setting twice; a bad skip entry; a value of the wrong kind.
5. **Notes, not errors (5d):** a rule excluded by the configuration, or above the application's level, changes nothing now; the note says so (`no_effect`). So does skipping a variable the rule never looks at.
6. **Equivalence.** The exceptions give the same rule results as the same changes made when the rules load: a `SecAction` with the settings, `SecRuleUpdateTargetById` lines for the skips, and the configuration's `exclude` list for rules that are off. This was tested on all 5,072 CRS tests at levels 1–4 (`TestTuningEqualsConfigureTimeExclusions`).

## 7. Findings

A finding has `kind`, `location` (where, in CRS's names) and `message`. A message never holds a value of the request (M11); one finding of each kind is kept per location.

| Kind | Meaning | Location, for example |
| --- | --- | --- |
| `unknown_endpoint` | No endpoint fits the path | `REQUEST_FILENAME` |
| `method` | Endpoints fit the path, but not with this method | `REQUEST_METHOD` |
| `content_type` | A body of a type the endpoint does not take | `REQUEST_HEADERS:Content-Type` |
| `unknown_param` | A parameter the endpoint does not name | `ARGS_GET:x`, `ARGS_POST:json.extra` |
| `missing` | A required parameter, cookie or header is not there | `ARGS_GET:id`, `REQUEST_COOKIES:sid` |
| `repeated` | Sent more than once without `repeat` | `ARGS_GET:q` |
| `wrong_type` | Not an integer, a number or a boolean | `ARGS_POST:id` |
| `too_long`, `too_short` | Outside `max_length` or `min_length` | `ARGS_GET:q` |
| `out_of_range` | Below `min` or above `max` | `ARGS_GET:page` |
| `pattern` | Does not match `pattern` | `REQUEST_HEADERS:X-Key` |
| `not_in_list` | Not one of the `enum` values | `ARGS_GET:sort` |
| `no_profile` | With `require_profile`: the request belongs to no application | `REQUEST_HEADERS:Host` |

A path part's location is `REQUEST_FILENAME:{name}`.

## 8. Writing a profile: `ids-offline -endpoints`

`ids-offline -endpoints -requests FILE` lists the method, path and count of each endpoint in the requests, and for each parameter and cookie: where it came from, how many requests sent it, whether one request repeated it, its greatest length and whether every value was an integer (F4g). JSON list indexes are written as `*`. Values are never shown; paths are, as received, so run it on your own data. It runs no rules and writes no records.

## 9. Known limits

1. File fields of multipart bodies are not checked.
2. A secret path part can only be masked when the path fits an endpoint of the profile.
3. Exceptions apply to the whole application, not to one endpoint (5b).
4. Profiles are written by hand from normal traffic. Learned profiles come later (main plan, order step 5).

## 10. Example

```json
{
  "note": "The shop of the CSIC 2010 data set.",
  "mode": "monitor",
  "paranoia_level": 2,
  "endpoints": [
    { "method": "GET", "path": "/tienda1/publico/anadir.jsp",
      "params": { "id": { "in": "query", "type": "integer", "required": true } } },
    { "method": "POST", "path": "/tienda1/publico/autenticar.jsp",
      "content_type": ["application/x-www-form-urlencoded"],
      "params": { "pwd": { "in": "body", "max_length": 64, "secret": true } } },
    { "method": "GET", "path": "/reset/{token}", "path_params": { "token": { "secret": true } } },
    { "method": "GET", "path": "/tienda1/imagenes/*" }
  ],
  "cookies": { "JSESSIONID": { "pattern": "[0-9A-F]{32}" } },
  "exceptions": [
    { "setting": "crs_validate_utf8_encoding", "value": "0", "reason": "the shop sends Latin-1 text" },
    { "rule": 932350, "skip": ["ARGS_NAMES:pwd", "ARGS_NAMES:id"], "reason": "parameter names, not commands" }
  ]
}
```
