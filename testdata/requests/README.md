# Example requests

| Path | Content |
| --- | --- |
| `path-traversal.json` | Hand-picked starter examples: four CRS cases and two normal requests |
| `common-exceptions.json` | Hand-written examples for rule file 905, which has no CRS tests: the exceptions for Apache's own health-check requests |
| `crs/` | The CRS 4.30.0 regression tests of the rule files that are finished: 901, 911, 913, 920, 921, 930 to 934, 941 to 944 and 949, at all paranoia levels. 286 files, one per rule, 5,025 tests. All must pass with `testdata/crs-tests.json` |
| `crs-pending/` | The same for file 922, which is not finished yet: 4 files, 47 tests |
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
python3 tools/convert_crs_tests.py --files 901 911 913 920 921 930 931 932 933 934 941 942 943 944 949
python3 tools/convert_crs_tests.py --out testdata/requests/crs-pending --files 922
```

The script reads `coreruleset-4.30.0/tests/regression/tests/` and applies the
same steps to each request that the CRS test runner (go-ftw) applies before
it sends one, for example adding a `Content-Type` header to a body that has
none. The steps are listed at the top of the script.

22 CRS tests are not converted. They expect only an answer of the web server
(a status code), which an offline engine does not have. All are in files 920
and 921. `tools/crs-test-overrides.yaml` changes two tests, each with a reason.

When the work on a rule file is finished, its tests move from `crs-pending/`
to `crs/`.

The CRS tests are written for a test setup: paranoia level 4 and rule 900005
of the CRS test README, which sets limits such as the length of arguments.
`testdata/crs-tests.json` is the product configuration plus that rule (in
`testdata/crs-test-setup.conf`). To see how many tests of each rule the engine
passes:

```
go run ./cmd/ids-offline -config testdata/crs-tests.json -requests testdata/requests/crs -summary
```

All rules are active and all 5,025 tests pass. (File `944000` is named after no rule; its one test is about a `text/plain` body.) A test would count as "not
inspected" if its expectation were not met and its body could not be read to
its end.
