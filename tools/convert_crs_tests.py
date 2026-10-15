#!/usr/bin/env python3
"""Convert CRS regression tests to the example format of ids-offline.

The CRS project keeps its tests as YAML files, one per rule, under
tests/regression/tests/. This script reads the tests of chosen rule files,
at all paranoia levels, and writes one JSON file per rule.

Usage, from the project directory:

    python3 tools/convert_crs_tests.py --files 930 941 942

Requires PyYAML (python3 -m pip install pyyaml).

The CRS test runner, go-ftw, completes a request before it sends it. The
same steps are applied here, so that a converted request is what the rules
would have seen. They follow go-ftw's ftwhttp/request.go:

  0. go-ftw reads data as a Go template. The only template the tests use is
     {{ "x" | repeat N }}, which is expanded here; any other stops the
     script.
  1. Missing method, uri and version become GET, / and HTTP/1.1.
  2. With a body and no Content-Type header, the header
     "Content-Type: application/x-www-form-urlencoded" is added.
  3. A form body that is not percent-encoded yet is encoded, key and value
     separately.
  4. In a multipart body every line feed becomes carriage return + line feed.
  5. "Connection: close" and "Content-Length" are added when absent.

Steps 2, 3 and 5 are skipped for a test that sets autocomplete_headers to
false.

The web server then reads the request before the rule engine sees it. Two
things it does are applied here too, because the tests are written for it:

  6. The length of the body (RFC 9112, section 6.3). With
     "Transfer-Encoding: chunked" the chunks are joined and Content-Length
     is dropped. Otherwise Content-Length says how many bytes belong to the
     body. A request with neither header has no body; bytes sent after the
     headers are not part of it.
  7. A request line without a version is kept without one ("version": "").
     The engine reads it as HTTP/0.9, as the web server does.

A test can give the whole request as bytes (encoded_request) in place of
the single fields. go-ftw sends those bytes as they are. Here they are split
into request line, headers and body, and a chunked body is put together, as
a web server does before a rule engine sees the request.

tools/crs-test-overrides.yaml changes a few tests, each with a reason.

What a test expects:

  expect_ids, no_expect_ids      kept
  match_regex, no_match_regex    kept as expect_log and no_expect_log: a
                                 pattern for the text of a log line
  status, expect_error           dropped. They describe the answer of the
                                 web server, which an offline engine does
                                 not have. A test that expects nothing else
                                 is left out and counted in the output.

The script stops with an error on any test field it does not know, so a new
kind of test cannot be converted wrongly without notice.
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote_plus

import yaml

FORM = "application/x-www-form-urlencoded"

KNOWN_INPUT_KEYS = {
    "dest_addr", "port", "protocol",  # where go-ftw sends the request; not part of it
    "method", "uri", "version", "headers", "data",
    "autocomplete_headers", "encoded_request",
}
KNOWN_OUTPUT_KEYS = {"log", "status", "expect_error"}
LOG_KEYS = {
    "expect_ids": "expect_ids",
    "no_expect_ids": "no_expect_ids",
    "match_regex": "expect_log",
    "no_match_regex": "no_expect_log",
}


def parse_raw_request(raw, where):
    """Split the bytes of a whole request into the fields of an example."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        sys.exit(f"{where}: encoded_request has no empty line after its headers")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        sys.exit(f"{where}: cannot read the request line {lines[0]!r}")
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon:
            sys.exit(f"{where}: cannot read the header line {line!r}")
        headers.append([name, value.strip()])
    return parts[0], parts[1], parts[2], headers, body


def join_chunks(body, where):
    """Return the content of a chunked body: each chunk is a length in hex on
    one line, then that many bytes; a chunk of length 0 ends the body."""
    out = b""
    while True:
        size_line, separator, rest = body.partition(b"\r\n")
        if not separator:
            sys.exit(f"{where}: the chunked body ends early")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            return out
        out += rest[:size]
        body = rest[size + 2:]


def header_values(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


def needs_encoding(data):
    """go-ftw encodes a form body only when unescaping it changes nothing."""
    if "+" in data:
        return False
    if re.search(r"%[0-9A-Fa-f]{2}", data):
        return False
    if "%" in data:
        # A broken escape makes Go's QueryUnescape fail; go-ftw then leaves
        # the body alone.
        return False
    return True


def encode_form(data):
    parts = []
    for token in data.split("&"):
        if "=" in token:
            key, value = token.split("=", 1)
            parts.append(quote_plus(key, safe="") + "=" + quote_plus(value, safe=""))
        else:
            parts.append(quote_plus(token, safe=""))
    return "&".join(parts)


def apply_framing(headers, body):
    """Return the headers and body as the web server reads them (step 6)."""
    if any(v.strip().lower() == "chunked" for v in header_values(headers, "Transfer-Encoding")):
        headers = [h for h in headers if h[0].lower() != "content-length"]
        return headers, join_chunks(body, "chunked body")
    lengths = header_values(headers, "Content-Length")
    if not lengths:
        return headers, b""
    try:
        length = int(lengths[0])
    except ValueError:
        return headers, body
    return headers, body[:length] if 0 <= length < len(body) else body


def convert_stage(stage, where):
    """Return the example for one stage, or None when the stage expects
    nothing that an offline engine can check."""
    inp = stage["input"]
    unknown = set(inp) - KNOWN_INPUT_KEYS
    if unknown:
        sys.exit(f"{where}: unknown input fields {sorted(unknown)}")
    out = stage["output"]
    log = out.get("log") or {}
    if set(out) - KNOWN_OUTPUT_KEYS or set(log) - set(LOG_KEYS):
        sys.exit(f"{where}: unknown output fields {out}")
    if not log:
        return None

    if "encoded_request" in inp:
        raw = base64.b64decode(inp["encoded_request"])
        method, uri, version, headers, data = parse_raw_request(raw, where)
    else:
        method, uri, version, headers, data = complete_request(inp, where)
        data = data.encode("utf-8")
    headers, data = apply_framing(headers, data)

    example = {"method": method, "uri": uri, "version": version, "headers": headers}
    if isinstance(data, bytes):
        # JSON holds text only, so a body that is not UTF-8 text is
        # written in base64.
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            example["body_base64"] = base64.b64encode(data).decode("ascii")
            data = ""
    if data:
        example["body"] = data
    for key, name in LOG_KEYS.items():
        if key in log:
            example[name] = log[key]
    return example


REPEAT = re.compile(r'\{\{\s*"([^"]*)"\s*\|\s*repeat\s+(\d+)\s*\}\}')


def expand_templates(data, where):
    """Expand {{ "x" | repeat N }} as go-ftw's template engine does."""
    data = REPEAT.sub(lambda m: m.group(1) * int(m.group(2)), data)
    if "{{" in data:
        sys.exit(f"{where}: data holds a template this script cannot expand")
    return data


def complete_request(inp, where):
    """Build the request from its single fields, as go-ftw does."""
    method = inp.get("method", "GET")
    headers = [[str(k), str(v)] for k, v in (inp.get("headers") or {}).items()]
    data = inp.get("data") or ""
    if not isinstance(data, str):
        sys.exit(f"{where}: data is not text")
    data = expand_templates(data, where)
    autocomplete = inp.get("autocomplete_headers", True)

    if data and autocomplete:
        if not header_values(headers, "Content-Type"):
            headers.append(["Content-Type", FORM])
        if any(v.lower() == FORM for v in header_values(headers, "Content-Type")) and needs_encoding(data):
            data = encode_form(data)

    if any("multipart/form-data;" in v.lower() for v in header_values(headers, "Content-Type")):
        data = data.replace("\n", "\r\n")

    if autocomplete:
        if not header_values(headers, "Connection"):
            headers.append(["Connection", "close"])
        # go-ftw's pattern is written exactly like this.
        has_body_method = re.search(r"^POST|PUT|PATCH|DELETE$", method) is not None
        if not header_values(headers, "Content-Length") and (data or has_body_method):
            headers.append(["Content-Length", str(len(data.encode("utf-8")))])
    return method, inp.get("uri", "/"), inp.get("version", "HTTP/1.1"), headers, data


def load_overrides(path):
    """Return the overrides by (rule id, test id)."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out = {}
    for o in doc.get("test_overrides") or []:
        if not o.get("reason"):
            sys.exit(f"{path}: an override of rule {o.get('rule_id')} has no reason")
        for test_id in o["test_ids"]:
            out[(str(o["rule_id"]), test_id)] = o["output"]
    return out


OVERRIDES = {}


def convert_rule(test_path):
    """Return the examples of one test file and the number of stages left out."""
    doc = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    if not doc or not doc.get("tests"):
        return [], 0
    # The file name is the rule id. One CRS file (933200.yaml) carries a
    # mistyped rule_id field, so the field is only reported, not trusted.
    rule_id = test_path.stem
    if str(doc.get("rule_id")) != rule_id:
        print(f"{test_path.name}: its rule_id field says {doc.get('rule_id')}; the file name is used")
    examples = []
    left_out = 0
    for test in doc["tests"]:
        stages = test["stages"]
        for number, stage in enumerate(stages, start=1):
            label = f"{rule_id}-{test['test_id']}"
            if len(stages) > 1:
                label += f" stage {number}"
            override = OVERRIDES.pop((rule_id, test["test_id"]), None)
            if override is not None:
                stage = dict(stage, output=override)
            converted = convert_stage(stage, f"{test_path} test {test['test_id']}")
            if converted is None:
                left_out += 1
                continue
            example = {"name": f"CRS {label}: {(test.get('desc') or '').strip()}".rstrip(": ")}
            example.update(converted)
            examples.append(example)
    return examples, left_out


def main():
    parser = argparse.ArgumentParser(description="Convert CRS regression tests to ids-offline examples.")
    parser.add_argument("--crs", default="coreruleset-4.30.0", help="CRS source directory")
    parser.add_argument("--out", default="testdata/requests/crs", help="output directory")
    parser.add_argument("--overrides", default="tools/crs-test-overrides.yaml", help="override file")
    parser.add_argument("--files", nargs="+", required=True, metavar="NUMBER",
                        help="rule file numbers, for example 930 941 942")
    args = parser.parse_args()

    OVERRIDES.update(load_overrides(args.overrides))
    crs = Path(args.crs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_rules = total_tests = total_left_out = 0
    for number in args.files:
        matches = sorted((crs / "rules").glob(f"REQUEST-{number}-*.conf"))
        if len(matches) != 1:
            sys.exit(f"expected one rule file REQUEST-{number}-*.conf in {crs / 'rules'}, found {len(matches)}")
        tests_dir = crs / "tests" / "regression" / "tests" / matches[0].stem
        rules = tests = 0
        for test_path in sorted(tests_dir.glob("*.yaml")):
            examples, left_out = convert_rule(test_path)
            total_left_out += left_out
            if not examples:
                print(f"{test_path.name}: nothing to convert")
                continue
            with open(out_dir / f"{test_path.stem}.json", "w", encoding="utf-8") as f:
                json.dump(examples, f, indent=2, ensure_ascii=False)
                f.write("\n")
            rules += 1
            tests += len(examples)
        print(f"{number}: {rules} rules, {tests} tests")
        total_rules += rules
        total_tests += tests
    print(f"{total_rules} rules, {total_tests} tests written to {out_dir}")
    if total_left_out:
        print(f"{total_left_out} tests left out: they expect only an answer of the web server")
    for rule_id, test_id in sorted(k for k in OVERRIDES if k[0][:3] in args.files):
        sys.exit(f"the override of {rule_id}-{test_id} matches no test")


if __name__ == "__main__":
    main()
