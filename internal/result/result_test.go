package result

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

func loadRules(t *testing.T, text string, exclude ...engine.Exclusion) *engine.RuleSet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := engine.Load(engine.Config{Files: []string{path}, Exclude: exclude})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

const testRules = `
SecComponentSignature "TEST/1"
SecAction "id:1,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.lfi_score=0,setvar:tx.xss_score=0"
SecRule ARGS|XML:/* "@rx (\.\./)+" "id:2,phase:2,log,pass,capture,severity:'CRITICAL',tag:'attack-lfi',msg:'Traversal in %{MATCHED_VAR_NAME}',logdata:'Matched Data: %{TX.0}',setvar:tx.lfi_score=+5,setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule ARGS "@rx secret" "id:3,phase:2,log,deny,msg:'Saw %{MATCHED_VAR}'"
SecRule RESPONSE_BODY "@rx a" "id:4,phase:2,log,pass"
`

func record(t *testing.T, req *httpmodel.Request, opt Options) Record {
	t.Helper()
	rs := loadRules(t, testRules, engine.Exclusion{ID: 4, Reason: "responses are not inspected"})
	return NewRecord(req, rs.Evaluate(req), opt)
}

func attack() *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{Method: "GET", Target: "/get?file=../../etc/passwd&note=my-secret-token"})
}

// By default a record explains the result without repeating request content.
func TestRecordHidesRequestContent(t *testing.T) {
	rec := record(t, attack(), Options{})

	want := []Finding{
		{RuleID: 2, Severity: "CRITICAL", Message: "Traversal in ARGS:file", Location: "ARGS:file", Action: "pass", Tags: []string{"attack-lfi"}},
		// This rule's message is built from the matched value.
		{RuleID: 3, Message: Hidden, Location: "ARGS:note", Action: "deny"},
	}
	if !reflect.DeepEqual(rec.Findings, want) {
		t.Errorf("findings = %+v\nwant       %+v", rec.Findings, want)
	}
	if rec.Method != "GET" || rec.URI != "" {
		t.Errorf("method = %q, uri = %q", rec.Method, rec.URI)
	}

	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"etc/passwd", "../", "my-secret-token", "secret", "/get"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("the record contains %q: %s", secret, out)
		}
	}
	for _, key := range []string{`"value"`, `"data"`, `"uri"`} {
		if strings.Contains(string(out), key) {
			t.Errorf("the record has a %s field: %s", key, out)
		}
	}
}

func TestRecordWithShowValues(t *testing.T) {
	rec := record(t, attack(), Options{ShowValues: true})

	if rec.URI != "/get?file=../../etc/passwd&note=my-secret-token" {
		t.Errorf("uri = %q", rec.URI)
	}
	f := rec.Findings[0]
	if f.Value == nil || *f.Value != "../../etc/passwd" || f.Data == nil || *f.Data != "Matched Data: ../../" {
		t.Errorf("finding = %+v", f)
	}
	f = rec.Findings[1]
	if f.Message != "Saw my-secret-token" || *f.Value != "my-secret-token" || f.Data != nil {
		t.Errorf("finding = %+v", f)
	}
}

func TestScore(t *testing.T) {
	rec := record(t, attack(), Options{})
	want := Score{Total: 5, Threshold: 5, Exceeded: true, Categories: map[string]int{"lfi": 5}}
	if !reflect.DeepEqual(rec.Score, want) {
		t.Errorf("score = %+v, want %+v", rec.Score, want)
	}

	rec = record(t, httpmodel.New(httpmodel.Received{Method: "GET", Target: "/get?q=kitap"}), Options{})
	if !reflect.DeepEqual(rec.Score, Score{Threshold: 5}) || len(rec.Findings) != 0 || rec.Findings == nil {
		t.Errorf("score = %+v, findings = %#v", rec.Score, rec.Findings)
	}

	// Without a threshold nothing counts as exceeded.
	rs := loadRules(t, `SecAction "id:1,phase:1,nolog,pass,setvar:tx.blocking_inbound_anomaly_score=9"`)
	req := httpmodel.New(httpmodel.Received{Method: "GET", Target: "/"})
	if s := NewRecord(req, rs.Evaluate(req), Options{}).Score; s.Total != 9 || s.Exceeded {
		t.Errorf("score = %+v", s)
	}
}

func TestAnalysis(t *testing.T) {
	tests := []struct {
		name string
		rec  httpmodel.Received
		want Analysis
	}{
		{"no body", httpmodel.Received{Method: "GET", Target: "/"}, Analysis{Complete: true, Body: "empty"}},
		{
			"form body",
			httpmodel.Received{Method: "POST", Target: "/", Headers: []httpmodel.Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}}, Body: []byte("a=1")},
			Analysis{Complete: true, Body: "inspected", BodyFormat: "form"},
		},
		{
			"text body",
			httpmodel.Received{Method: "POST", Target: "/", Headers: []httpmodel.Header{{Name: "Content-Type", Value: "text/plain"}}, Body: []byte(`file=../../x`)},
			Analysis{Complete: false, Body: "not inspected", BodyReason: `content type "text/plain" is not parsed`},
		},
		{
			"broken json body",
			httpmodel.Received{Method: "POST", Target: "/", Headers: []httpmodel.Header{{Name: "Content-Type", Value: "application/json"}}, Body: []byte(`{"a": "b", `)},
			Analysis{Complete: false, Body: "partly inspected", BodyFormat: "json", BodyReason: "the json body could not be read to its end: the document ends early"},
		},
		{
			"malformed encoding",
			httpmodel.Received{Method: "GET", Target: "/?a=%zz"},
			Analysis{Complete: true, Body: "empty", Issues: []Issue{{Part: "query", Message: "1 names or values contain malformed percent-encoding; it was kept as written"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := record(t, httpmodel.New(tt.rec), Options{}).Analysis; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("analysis = %+v\nwant       %+v", got, tt.want)
			}
		})
	}

	// An attack in a body that is not parsed gives no finding. The record
	// must say that the analysis is incomplete instead of looking clean.
	rec := record(t, httpmodel.New(tests[2].rec), Options{})
	if len(rec.Findings) != 0 || rec.Analysis.Complete {
		t.Errorf("record = %+v", rec)
	}
}

func TestStartup(t *testing.T) {
	rs := loadRules(t, testRules, engine.Exclusion{ID: 4, Reason: "responses are not inspected"})
	got := NewStartup(rs)
	want := Startup{
		Ruleset:              "TEST/1",
		ActiveRules:          3,
		ExcludedRules:        []ExcludedRule{{ID: 4, File: "rules.conf", Line: 6, Reason: "responses are not inspected"}},
		IgnoredTargetUpdates: []int{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("startup = %+v\nwant      %+v", got, want)
	}

	// Empty lists are written as [] and not as null.
	out, _ := json.Marshal(NewStartup(loadRules(t, `SecAction "id:1,phase:1,nolog,pass"`)))
	if string(out) != `{"ruleset":"","active_rules":1,"excluded_rules":[],"ignored_target_updates":[]}` {
		t.Errorf("startup JSON = %s", out)
	}
}

func TestPrintable(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"../../etc/passwd", "../../etc/passwd"},
		{"şifre çok gizli", "şifre çok gizli"},
		{"a\x00b", `a\x00b`},
		{"a\nb\tc", `a\nb\tc`},
		{"a\xffb", `a\xffb`},
		{"\x1b[31mred", `\x1b[31mred`},
	}
	for _, tt := range tests {
		if got := printable(tt.in); got != tt.want {
			t.Errorf("printable(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	// Bytes that are not text stay visible in a record.
	req := httpmodel.New(httpmodel.Received{Method: "GET", Target: "/?file=..%2f..%2f%00%ff"})
	rec := record(t, req, Options{ShowValues: true})
	if got := *rec.Findings[0].Value; got != `../../\x00\xff` {
		t.Errorf("value = %q", got)
	}
}
