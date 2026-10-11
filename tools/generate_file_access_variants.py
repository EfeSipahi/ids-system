#!/usr/bin/env python3
"""Generate request variants for rules 930120, 930130 and 930140.

Those rules look for the names of sensitive files (/etc/passwd, .env,
.git/config, ...) in parameters, parameter names, cookies and the request
path. This script takes names from the CRS data files, rewrites them in
ways an attacker might (backslashes, doubled slashes, "/./", upper case,
percent-encoding) and puts them in different places of a request.

Like tools/generate_traversal_variants.py, the requests carry no
expectation; the reference engine decides what is right for each.

Usage, from the project directory:

    python3 tools/generate_file_access_variants.py

The output is the same on every run.
"""

import json
import random
from pathlib import Path

CRS_RULES = Path("coreruleset-4.30.0/rules")
OUT = Path("testdata/requests/generated/file-access-variants.json")
COUNT = 400

HARMLESS = ["report.pdf", "index.html", "kitap", "images/logo.png", "a/b/c", "etc", "environment", "passwords", ""]


def phrases(name):
    lines = (CRS_RULES / name).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def disguise(rng, text):
    choice = rng.random()
    if choice < 0.35:
        return text
    if choice < 0.50:
        return text.replace("/", "\\")
    if choice < 0.60:
        return text.replace("/", "//")
    if choice < 0.70:
        return text.replace("/", "/./")
    if choice < 0.80:
        return text.upper()
    if choice < 0.90:
        return text.replace(".", "%2e").replace("/", "%2f")
    return text.replace("/", "/x/../")


def as_uri_part(text):
    return text.replace(" ", "+").replace("#", "%23").replace("&", "%26")


def request(rng, number, sensitive):
    headers = [["Host", "localhost"], ["User-Agent", "variant test"]]
    place = rng.choice(["query", "query", "arg name", "path", "path", "path end", "cookie", "cookie name", "form", "header"])
    word = rng.choice(sensitive) if rng.random() < 0.8 else rng.choice(HARMLESS)
    p = disguise(rng, word)
    example = {"name": f"file access variant {number} ({place})", "method": "GET", "uri": "/", "version": "HTTP/1.1", "headers": headers}

    if place == "query":
        example["uri"] = "/download?file=" + as_uri_part(p)
    elif place == "arg name":
        example["uri"] = "/download?" + as_uri_part(p).replace("=", "%3d") + "=1"
    elif place == "path":
        example["uri"] = "/" + as_uri_part(p).lstrip("/").replace("?", "%3f")
    elif place == "path end":
        example["uri"] = "/static/" + as_uri_part(p).lstrip("/").replace("?", "%3f") + "?v=1"
    elif place == "cookie":
        headers.append(["Cookie", "session=abc; last=" + p.replace(";", "")])
    elif place == "cookie name":
        headers.append(["Cookie", p.replace(";", "").replace("=", "") + "=1; theme=dark"])
    elif place == "header":
        headers.append(["X-Original-File", p])
    else:
        example["method"] = "POST"
        example["uri"] = "/upload"
        body = "name=" + as_uri_part(p) + "&ok=1"
        headers.append(["Content-Type", "application/x-www-form-urlencoded"])
        headers.append(["Content-Length", str(len(body.encode("utf-8")))])
        example["body"] = body
    return example


def main():
    rng = random.Random(930120)
    sensitive = []
    for name in ("lfi-os-files.data", "restricted-files.data", "ai-critical-artifacts.data"):
        found = phrases(name)
        sensitive += rng.sample(found, min(40, len(found)))
    examples = [request(rng, n, sensitive) for n in range(1, COUNT + 1)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"{len(examples)} requests written to {OUT}")


if __name__ == "__main__":
    main()
