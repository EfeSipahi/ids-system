#!/usr/bin/env python3
"""Generate request variants for comparing our engine with a reference engine.

The CRS regression tests hold only a handful of requests that match rules
930100 and 930110. To compare two engines on scores and match counts, many
more matching and nearly matching requests are needed. This script builds
them from pieces: ways to write a path separator, ways to write a dot, and
places in a request to put the result.

The requests carry no expectation. What is right for each of them is decided
by running them through the reference engine (tools/coraza-reference).

Usage, from the project directory:

    python3 tools/generate_traversal_variants.py

The output is the same on every run.
"""

import json
import random
from pathlib import Path

OUT = Path("testdata/requests/generated/traversal-variants.json")
COUNT = 400

SEPARATORS = ["/", "/", "/", "\\", ";", "%2f", "%2F", "%5c", "%5C", "%252f", "%255c", "%c0%af", "%c1%9c",
              "%u2215", "%u2216", "%uEFC8", "%uF025", "%u002f", "0x2f", "0x5c", "%e0%80%af", "／", "%00/"]
DOTS = [".", ".", ".", ".", "%2e", "%2E", "%252e", "%c0%ae", "%uff0e", "%u002e", "%u2024", "0x2e",
        ".%00", ".%01", ".?", "?", "．", "%ff."]
WORDS = ["etc", "passwd", "ETC", "WINDOWS", "win.ini", "a", "kitap", "Program Files", "x y", "o'neil",
         'say "hi"', "c^md", "a,b;c", "çay", "%zz", "100%", "", "..", "..."]


def payload(rng):
    parts = []
    for _ in range(rng.randint(1, 4)):
        kind = rng.random()
        if kind < 0.55:
            parts.append(rng.choice(SEPARATORS) if rng.random() < 0.6 else "")
            parts.append("".join(rng.choice(DOTS) for _ in range(rng.choice([1, 2, 2, 2, 3, 3, 4]))))
            parts.append(rng.choice(SEPARATORS) if rng.random() < 0.8 else "")
        else:
            parts.append(rng.choice(WORDS))
            if rng.random() < 0.5:
                parts.append(rng.choice(SEPARATORS))
    return "".join(parts)


def request(rng, number):
    headers = [["Host", "localhost"], ["User-Agent", "variant test"]]
    place = rng.choice(["query", "query", "query", "two params", "path", "header", "referer", "form", "form", "mixed"])
    p = payload(rng)
    example = {"name": f"variant {number} ({place})", "method": "GET", "uri": "/", "version": "HTTP/1.1", "headers": headers}

    def as_uri_part(text):
        # A request target cannot hold a raw space.
        return text.replace(" ", "+")

    if place == "query":
        example["uri"] = "/get?arg=" + as_uri_part(p)
    elif place == "two params":
        example["uri"] = "/get?a=" + as_uri_part(p) + "&a=" + as_uri_part(payload(rng)) + "&b=1"
    elif place == "path":
        example["uri"] = "/files/" + as_uri_part(p).replace("?", "%3f")
    elif place == "header":
        headers.append(["X-Path", p])
    elif place == "referer":
        # Both rules exclude the Referer header.
        headers.append(["Referer", "http://localhost/" + p])
    else:
        example["method"] = "POST"
        example["uri"] = "/post" if place == "form" else "/post?q=" + as_uri_part(payload(rng))
        body = "file=" + as_uri_part(p) + "&note=" + as_uri_part(rng.choice(WORDS))
        headers.append(["Content-Type", "application/x-www-form-urlencoded"])
        headers.append(["Content-Length", str(len(body.encode("utf-8")))])
        example["body"] = body
    return example


def main():
    rng = random.Random(930110)
    examples = [request(rng, n) for n in range(1, COUNT + 1)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"{len(examples)} requests written to {OUT}")


if __name__ == "__main__":
    main()
