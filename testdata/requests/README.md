# Example requests

| Path | Content |
| --- | --- |
| `path-traversal.json` | Hand-picked starter examples: four CRS cases and two normal requests |
| `crs/` | The CRS 4.30.0 regression tests of the rule files that are finished: 911, 913, 930 to 934 and 941 to 944, at all paranoia levels. 207 files, one per rule, 4,479 tests. All must pass |
| `crs-pending/` | The same for the rule files that are not finished yet: 83 files, 594 tests. Most fail today, because their rule files are not loaded |
| `generated/` | 1,300 generated requests without expectations, used to compare our engine with a reference engine: path traversal, file access, and SQLi/XSS variants. Written by the three `tools/generate_*_variants.py` scripts |

What a request can expect:

| Field | Meaning |
| --- | --- |
| `expect_ids` | Rules that must match |
| `no_expect_ids` | Rules that must not match |
| `expect_log` | A pattern that the log line of at least one match must contain |
| `no_expect_log` | A pattern that no log line may contain |

A log line is built from a match in the bracket form of ModSecurity:
`[id "930110"] [msg "Path Traversal Attack (/../)"] [data "Matched Data: ..."]`.

A body is given as text in `body`, or in base64 in `body_base64` when it is
not UTF-8 text.

## The `crs/` and `crs-pending/` directories

These files are generated. Do not edit them by hand; change the script and
run it again from the project directory:

```
python3 tools/convert_crs_tests.py --files 911 913 930 931 932 933 934 941 942 943 944
python3 tools/convert_crs_tests.py --out testdata/requests/crs-pending \
    --files 901 920 921 922 949
```

The script reads `coreruleset-4.30.0/tests/regression/tests/` and applies the
same steps to each request that the CRS test runner (go-ftw) applies before
it sends one, for example adding a `Content-Type` header to a body that has
none. The steps are listed at the top of the script.

21 CRS tests are not converted. They expect only an answer of the web server
(a status code), which an offline engine does not have. All are in file 920.

When the work on a rule file is finished, its tests move from `crs-pending/`
to `crs/`.

The CRS project runs its tests at paranoia level 4, so that every rule is
switched on. To see how many tests of each rule the engine passes:

```
go run ./cmd/ids-offline -requests testdata/requests/crs -summary -paranoia-level 4
```

All rules are active and all 4,479 tests pass. (File `944000` is named after no rule; its one test is about a `text/plain` body.) A test would count as "not
inspected" if its expectation were not met and its body could not be read to
its end.
