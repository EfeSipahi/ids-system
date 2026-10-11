# Example requests

| File | Content |
| --- | --- |
| `path-traversal.json` | Hand-picked starter examples: four CRS cases and two normal requests |
| `crs-930-regression.json` | The CRS 4.30.0 regression tests of rules 930100 and 930110 that the first engine can inspect |
| `crs-930-regression-not-yet-supported.json` | The remaining tests of those rules. Their payload is in an XML or multipart body, which the engine does not parse yet. The engine test checks that they are reported as not inspected |

The two `crs-930-*` files were converted on 11 October 2026 from
`coreruleset-4.30.0/tests/regression/tests/REQUEST-930-APPLICATION-ATTACK-LFI/930100.yaml`
and `930110.yaml`. Method, URI, headers, body and expected rule IDs are
unchanged, with one addition: when a test has a body and no `Content-Type`
header, `Content-Type: application/x-www-form-urlencoded` was added, because
the CRS test runner (go-ftw) adds that header itself before sending.

`expect_ids` are rules that must match; `no_expect_ids` are rules that must
not.
