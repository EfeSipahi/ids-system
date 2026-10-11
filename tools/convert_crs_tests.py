#!/usr/bin/env python3
"""Convert CRS regression tests to the example format of ids-offline.

The CRS project keeps its tests as YAML files, one per rule, under
tests/regression/tests/. This script reads the tests of the rules at one
paranoia level in chosen rule files and writes one JSON file per rule.

Usage, from the project directory:

    python3 tools/convert_crs_tests.py --files 930 941 942

Requires PyYAML (python3 -m pip install pyyaml).

The CRS test runner, go-ftw, completes a request before it sends it. The
same steps are applied here, so that a converted request is what the rules
would have seen. They follow go-ftw's ftwhttp/request.go:

  1. Missing method, uri and version become GET, / and HTTP/1.1.
  2. With a body and no Content-Type header, the header
     "Content-Type: application/x-www-form-urlencoded" is added.
  3. A form body that is not percent-encoded yet is encoded, key and value
     separately.
  4. In a multipart body every line feed becomes carriage return + line feed.
  5. "Connection: close" and "Content-Length" are added when absent.

Steps 2, 3 and 5 are skipped for a test that sets autocomplete_headers to
false. The script stops with an error on any test field it does not know,
so a new kind of test cannot be converted wrongly without notice.
"""

import argparse
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
    "autocomplete_headers",
}
KNOWN_LOG_KEYS = {"expect_ids", "no_expect_ids"}


def rule_ids(conf_path, level):
    """Return the ids of the rules tagged with the paranoia level, in file order."""
    text = conf_path.read_text(encoding="utf-8").replace("\\\n", "")
    ids = []
    for line in text.split("\n"):
        line = line.strip()
        if not line.startswith("SecRule") or f"paranoia-level/{level}'" not in line:
            continue
        match = re.search(r"\bid:(\d+)", line)
        if match:
            ids.append(int(match.group(1)))
    return ids


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


def convert_stage(stage, where):
    inp = stage["input"]
    unknown = set(inp) - KNOWN_INPUT_KEYS
    if unknown:
        sys.exit(f"{where}: unknown input fields {sorted(unknown)}")
    out = stage["output"]
    if set(out) != {"log"} or set(out["log"]) - KNOWN_LOG_KEYS:
        sys.exit(f"{where}: unknown output fields {out}")

    method = inp.get("method", "GET")
    headers = [[str(k), str(v)] for k, v in (inp.get("headers") or {}).items()]
    data = inp.get("data") or ""
    if not isinstance(data, str):
        sys.exit(f"{where}: data is not text")
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

    example = {
        "method": method,
        "uri": inp.get("uri", "/"),
        "version": inp.get("version", "HTTP/1.1"),
        "headers": headers,
    }
    if data:
        example["body"] = data
    for key in ("expect_ids", "no_expect_ids"):
        if key in out["log"]:
            example[key] = out["log"][key]
    return example


def convert_rule(test_path, rule_id):
    doc = yaml.safe_load(test_path.read_text(encoding="utf-8"))
    if doc.get("rule_id") != rule_id:
        sys.exit(f"{test_path}: rule_id is {doc.get('rule_id')}, expected {rule_id}")
    examples = []
    for test in doc["tests"]:
        stages = test["stages"]
        for number, stage in enumerate(stages, start=1):
            label = f"{rule_id}-{test['test_id']}"
            if len(stages) > 1:
                label += f" stage {number}"
            example = {"name": f"CRS {label}: {test.get('desc', '').strip()}".rstrip(": ")}
            example.update(convert_stage(stage, f"{test_path} test {test['test_id']}"))
            examples.append(example)
    return examples


def main():
    parser = argparse.ArgumentParser(description="Convert CRS regression tests to ids-offline examples.")
    parser.add_argument("--crs", default="coreruleset-4.30.0", help="CRS source directory")
    parser.add_argument("--out", default="testdata/requests/crs", help="output directory")
    parser.add_argument("--files", nargs="+", required=True, metavar="NUMBER",
                        help="rule file numbers, for example 930 941 942")
    parser.add_argument("--paranoia-level", type=int, default=1)
    args = parser.parse_args()

    crs = Path(args.crs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_rules = total_tests = 0
    for number in args.files:
        matches = sorted((crs / "rules").glob(f"REQUEST-{number}-*.conf"))
        if len(matches) != 1:
            sys.exit(f"expected one rule file REQUEST-{number}-*.conf in {crs / 'rules'}, found {len(matches)}")
        conf = matches[0]
        tests_dir = crs / "tests" / "regression" / "tests" / conf.stem
        for rule_id in rule_ids(conf, args.paranoia_level):
            test_path = tests_dir / f"{rule_id}.yaml"
            if not test_path.exists():
                print(f"rule {rule_id}: no test file, skipped")
                continue
            examples = convert_rule(test_path, rule_id)
            with open(out_dir / f"{rule_id}.json", "w", encoding="utf-8") as f:
                json.dump(examples, f, indent=2, ensure_ascii=False)
                f.write("\n")
            total_rules += 1
            total_tests += len(examples)
    print(f"{total_rules} rules, {total_tests} tests written to {out_dir}")


if __name__ == "__main__":
    main()
