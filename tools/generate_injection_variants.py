#!/usr/bin/env python3
"""Generate SQL injection and XSS request variants.

Each request takes a known attack string, or a harmless one, rewrites it
with an encoding that the rules are meant to see through (HTML entities,
JavaScript and CSS escapes, SQL comments, percent-encoding, mixed case,
white space) and puts it in a parameter, a cookie, a JSON value, a form
field or the path.

Like the other generators, the requests carry no expectation; the reference
engine decides what is right for each (tools/coraza-reference).

Usage, from the project directory:

    python3 tools/generate_injection_variants.py

The output is the same on every run.
"""

import json
import random
from pathlib import Path
from urllib.parse import quote

OUT = Path("testdata/requests/generated/injection-variants.json")
COUNT = 500

SQLI = [
    "1' OR '1'='1", "1 UNION SELECT username, password FROM users", "'; DROP TABLE users--",
    "1 AND SLEEP(5)", "admin'--", "1; WAITFOR DELAY '0:0:5'", "' OR 1=1#", "1 OR pg_sleep(5)",
    "x' AND 1=CONVERT(int,@@version)--", "1 AND BENCHMARK(1000000,MD5(1))", "' UNION ALL SELECT NULL,NULL--",
    "1' AND extractvalue(1,concat(0x7e,version()))--", "select load_file('/etc/passwd')", "1/**/OR/**/1=1",
    "'||(SELECT 1 FROM dual)||'", "{\"$ne\": null}", "1e1union select",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>", "\"><script>fetch('//x')</script>", "<iframe src=javascript:alert(1)>",
    "<body onload=eval(atob('YQ=='))>", "<a href=\"javascript:confirm(1)\">x</a>", "';alert(String.fromCharCode(88))//",
    "<input onfocus=alert(1) autofocus>", "<div style=\"width:expression(alert(1))\">", "{{constructor.constructor('alert(1)')()}}",
    "<script src=//evil.example/x.js></script>", "document.write('<b>')", "setTimeout(alert,1)", "<!--[if gte IE 4]><script>alert(1)</script><![endif]-->",
]
HARMLESS = [
    "kitap", "O'Brien", "select a colour", "a < b and b > c", "1+1=2", "user@example.com", "The union of two sets",
    "script writing course", "price: 10-20", "https://example.com/a?b=c", "It's 5 o'clock", "drop me a line", "", "2026-10-11",
]


def html_entities(rng, text):
    out = []
    for ch in text:
        if ch.isalnum() or rng.random() < 0.6:
            out.append(ch)
        else:
            out.append(rng.choice([f"&#{ord(ch)};", f"&#x{ord(ch):x};", f"&#{ord(ch)}"]))
    return "".join(out).replace("<", rng.choice(["<", "&lt;", "&LT"])).replace(":", rng.choice([":", "&colon;"]))


def js_escapes(rng, text):
    return "".join(ch if rng.random() < 0.7 else rng.choice([f"\\x{ord(ch):02x}", f"\\u{ord(ch):04x}", f"\\{ord(ch):o}"])
                   for ch in text)


def css_escapes(rng, text):
    return "".join(ch if rng.random() < 0.75 else f"\\{ord(ch):x} " for ch in text)


def sql_comments(rng, text):
    return text.replace(" ", rng.choice(["/**/", "/*x*/", " ", "\t", "\n", "  "]))


def mixed_case(rng, text):
    return "".join(ch.upper() if rng.random() < 0.5 else ch.lower() for ch in text)


def double_encode(rng, text):
    return quote(text, safe="")


def spaced(rng, text):
    return text.replace("=", " = ").replace("(", " (")


REWRITES = [html_entities, js_escapes, css_escapes, sql_comments, mixed_case, double_encode, spaced]


def request(rng, number):
    kind = rng.random()
    text = rng.choice(SQLI) if kind < 0.4 else rng.choice(XSS) if kind < 0.8 else rng.choice(HARMLESS)
    for _ in range(rng.choice([0, 0, 1, 1, 1, 2])):
        text = rng.choice(REWRITES)(rng, text)

    headers = [["Host", "localhost"], ["User-Agent", "variant test"]]
    place = rng.choice(["query", "query", "query", "arg name", "cookie", "form", "form", "json", "path", "header"])
    example = {"name": f"injection variant {number} ({place})", "method": "GET", "uri": "/", "version": "HTTP/1.1", "headers": headers}
    encoded = quote(text, safe="")

    if place == "query":
        example["uri"] = "/item?id=" + encoded
    elif place == "arg name":
        example["uri"] = "/item?" + encoded + "=1"
    elif place == "path":
        example["uri"] = "/page/" + encoded
    elif place == "cookie":
        headers.append(["Cookie", "session=abc; pref=" + text.replace(";", "%3b").replace("\n", " ")])
    elif place == "header":
        headers.append(["X-Comment", text.replace("\n", " ")])
    elif place == "json":
        body = json.dumps({"user": {"name": text}, "tags": ["a", text]}, ensure_ascii=False)
        example.update(method="POST", uri="/api/item", body=body)
        headers.append(["Content-Type", "application/json"])
        headers.append(["Content-Length", str(len(body.encode("utf-8")))])
    else:
        body = "comment=" + encoded + "&ok=1"
        example.update(method="POST", uri="/comment", body=body)
        headers.append(["Content-Type", "application/x-www-form-urlencoded"])
        headers.append(["Content-Length", str(len(body.encode("utf-8")))])
    return example


def main():
    rng = random.Random(941942)
    examples = [request(rng, n) for n in range(1, COUNT + 1)]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"{len(examples)} requests written to {OUT}")


if __name__ == "__main__":
    main()
