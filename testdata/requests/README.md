# Example requests

| Path | Content |
| --- | --- |
| `path-traversal.json` | Hand-picked starter examples: four CRS cases and two normal requests |
| `crs/` | The CRS 4.30.0 regression tests of every PL1 rule in files 930, 941 and 942: 51 files, one per rule, 687 tests |
| `generated/` | 1,300 generated requests without expectations, used to compare our engine with a reference engine: path traversal, file access, and SQLi/XSS variants. Written by the three `tools/generate_*_variants.py` scripts |

`expect_ids` are rules that must match a request; `no_expect_ids` are rules
that must not.

## The `crs/` directory

These files are generated. Do not edit them by hand; change the script and
run it again from the project directory:

```
python3 tools/convert_crs_tests.py --files 930 941 942
```

The script reads `coreruleset-4.30.0/tests/regression/tests/` and applies the
same steps to each request that the CRS test runner (go-ftw) applies before
it sends one, for example adding a `Content-Type` header to a body that has
none. The steps are listed at the top of the script.

To see how many tests of each rule the engine passes:

```
go run ./cmd/ids-offline -requests testdata/requests/crs -summary
```

All 51 rules are active and all 687 tests pass. A test would count as "not
inspected" if its expectation were not met and its body could not be read to
its end.
