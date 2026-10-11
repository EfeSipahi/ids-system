# Reference results

`coraza-first-engine.json` holds what the Coraza WAF engine found for our
example requests: for each request, the matched rules, the places they
matched, and the total anomaly score. The test `TestAgainstCoraza` in
`internal/engine` compares our engine with it.

The file is generated. Do not edit it by hand. To produce it again, from
`tools/coraza-reference/`:

```
go run . -config ../../configs/crs-first-engine.json \
    -requests ../../testdata/requests/path-traversal.json,../../testdata/requests/crs,../../testdata/requests/generated \
    -out ../../testdata/reference/coraza-first-engine.json
```

Produce it again whenever the example requests or the engine configuration
change. The comparison test stops with a message when the file no longer
belongs to the current example files.

| Fact | Value |
| --- | --- |
| Reference engine | Coraza v3.8.1, detection-only mode |
| Rule files | The seven files of `configs/crs-first-engine.json`, unmodified |
| Added before the rule files | The two rules of `coraza.conf-recommended` that choose the XML and JSON body readers |
| Left out | The `SecRuleUpdateTargetById` line for rule 932240, which is not loaded; Coraza refuses such a line, our engine ignores and reports it |
| Requests | 1,993: 6 starter examples, 687 converted CRS tests, 1,300 generated variants |
| Produced on | 11 October 2026 |

For a chained rule the file lists what the last rule of the chain matched.

Coraza is a second implementation of the language ModSecurity defined. It is
an independent engine to compare with, not a definition of what is right:
where the two engines differ, the difference is examined and either fixed in
our engine or written down with its reason.
