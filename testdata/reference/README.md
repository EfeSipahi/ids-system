# Reference results

`coraza-first-engine.json` and `coraza-first-engine-pl4.json` hold what the
Coraza WAF engine found for our example requests at paranoia level 1 and at
level 4: for each request, the matched rules, the places they
matched, and the total anomaly score. The test `TestAgainstCoraza` in
`internal/engine` compares our engine with it.

The files are generated. Do not edit them by hand. To produce them again,
from `tools/coraza-reference/`:

```
go run -tags coraza.rule.no_regex_multiline . -config ../../configs/crs-first-engine.json \
    -requests ../../testdata/requests/path-traversal.json,../../testdata/requests/crs,../../testdata/requests/generated \
    -out ../../testdata/reference/coraza-first-engine.json

go run -tags coraza.rule.no_regex_multiline . -config ../../configs/crs-first-engine.json \
    -requests ../../testdata/requests/path-traversal.json,../../testdata/requests/crs,../../testdata/requests/generated \
    -paranoia-level 4 -out ../../testdata/reference/coraza-first-engine-pl4.json
```

The `-tags` option matters. Without it Coraza adds the multi-line flag to
every pattern, so that `^` and `$` also match at a line break inside a value.
ModSecurity does not, and the CRS patterns are written for ModSecurity.
Coraza's README names this option as the way to get the behaviour CRS
expects and says it becomes the default in the next major version.

Produce it again whenever the example requests or the engine configuration
change. The comparison test stops with a message when the file no longer
belongs to the current example files.

| Fact | Value |
| --- | --- |
| Reference engine | Coraza v3.8.1, detection-only mode |
| Rule files | The fifteen files of `configs/crs-first-engine.json`, unmodified |
| Build option | `coraza.rule.no_regex_multiline` |
| Paranoia level | 1 in the first file, 4 in the second, set with rule 900000 as `crs-setup.conf.example` describes |
| Added before the rule files | The two rules of `coraza.conf-recommended` that choose the XML and JSON body readers |
| Requests | 5,785: 6 starter examples, 4,479 converted CRS tests, 1,300 generated variants |
| Produced on | 16 October 2026 |

For a chained rule the file lists what the last rule of the chain matched.

Coraza is a second implementation of the language ModSecurity defined. It is
an independent engine to compare with, not a definition of what is right:
where the two engines differ, the difference is examined and either fixed in
our engine or written down with its reason.

One difference between the engines is known and checked by its own rule in
the test. For a body of a type that has no reader, such as `text/plain`,
Coraza splits the body into parameters as if it were a form. ModSecurity
with the CRS defaults does not, and neither do we: the rules get the body as
one text, `REQUEST_BODY`. On such a request Coraza may therefore have more
matches, all in `ARGS` or `ARGS_NAMES`, and a higher score.
