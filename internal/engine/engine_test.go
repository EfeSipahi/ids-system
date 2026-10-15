package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// loadRules writes each text to its own file and loads them in order.
func loadRules(t *testing.T, texts ...string) *RuleSet {
	t.Helper()
	rs, err := Load(rulesConfig(t, texts...))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rs
}

func rulesConfig(t *testing.T, texts ...string) Config {
	t.Helper()
	dir := t.TempDir()
	var cfg Config
	for i, text := range texts {
		path := filepath.Join(dir, "rules"+string(rune('a'+i))+".conf")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Files = append(cfg.Files, path)
	}
	return cfg
}

func get(target string, headers ...httpmodel.Header) *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{Method: "GET", Target: target, Version: "HTTP/1.1", Headers: headers})
}

func wantVars(t *testing.T, res *Result, want map[string]string) {
	t.Helper()
	for name, value := range want {
		got, ok := res.Variables[name]
		switch {
		case value == "<unset>" && ok:
			t.Errorf("tx.%s = %q, want it unset", name, got)
		case value != "<unset>" && (!ok || got != value):
			t.Errorf("tx.%s = %q (set: %v), want %q", name, got, ok, value)
		}
	}
}

func TestPhasesRunInOrder(t *testing.T) {
	// The phase 2 rule comes first in the file but runs second.
	rs := loadRules(t, `
SecAction "id:1,phase:2,nolog,pass,setvar:'tx.seq=%{tx.seq}b'"
SecAction "id:2,phase:1,nolog,pass,setvar:'tx.seq=%{tx.seq}a'"
SecAction "id:3,nolog,pass,setvar:'tx.seq=%{tx.seq}c'"
`)
	res := rs.Evaluate(get("/"))
	// Rule 3 names no phase, so it is a phase 2 rule.
	wantVars(t, res, map[string]string{"seq": "abc"})
	if len(res.Matches) != 0 {
		t.Errorf("matches = %+v, want none because the rules say nolog", res.Matches)
	}
}

func TestSkipAfter(t *testing.T) {
	rs := loadRules(t, `
SecAction "id:1,phase:1,nolog,pass,skipAfter:END"
SecAction "id:2,phase:1,nolog,pass,setvar:tx.skipped=1"
SecAction "id:3,phase:2,nolog,pass,setvar:tx.other_phase=1"
SecMarker END
SecAction "id:4,phase:1,nolog,pass,setvar:tx.after=1"
SecRule ARGS:go "@eq 0" "id:5,phase:2,nolog,pass,skipAfter:END2"
SecAction "id:6,phase:2,nolog,pass,setvar:tx.kept=1"
SecMarker END2
`)
	// The jump of rule 1 belongs to phase 1 only. Rule 5 does not match,
	// so it does not jump.
	res := rs.Evaluate(get("/?go=1"))
	wantVars(t, res, map[string]string{"skipped": "<unset>", "other_phase": "1", "after": "1", "kept": "1"})

	res = rs.Evaluate(get("/?go=0"))
	wantVars(t, res, map[string]string{"kept": "<unset>"})
}

func TestChain(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS:a "@rx ^x" "id:1,phase:2,log,pass,msg:'both',setvar:tx.first=+1,chain"
    SecRule ARGS:b "@rx ^y" "setvar:tx.second=+1,chain"
    SecRule ARGS:c "@rx ^z" "setvar:tx.third=+1"
`)
	tests := []struct {
		target  string
		matched bool
		vars    map[string]string
	}{
		{"/?a=x&b=y&c=z", true, map[string]string{"first": "1", "second": "1", "third": "1"}},
		// A setvar on one rule of the chain runs as soon as that rule
		// matches, even when a later rule stops the chain.
		{"/?a=x&b=y&c=n", false, map[string]string{"first": "1", "second": "1", "third": "<unset>"}},
		{"/?a=x&b=n&c=z", false, map[string]string{"first": "1", "second": "<unset>", "third": "<unset>"}},
		{"/?a=n&b=y&c=z", false, map[string]string{"first": "<unset>", "second": "<unset>"}},
		{"/?a=x", false, map[string]string{"first": "1", "second": "<unset>"}},
	}
	for _, tt := range tests {
		res := rs.Evaluate(get(tt.target))
		if got := len(res.Matches) == 1; got != tt.matched {
			t.Errorf("%s: matches = %+v, want matched %v", tt.target, res.Matches, tt.matched)
		}
		wantVars(t, res, tt.vars)
	}

	// The match is reported with the id and message of the first rule and
	// the value of the last.
	m := rs.Evaluate(get("/?a=x&b=y&c=z")).Matches[0]
	if m.RuleID != 1 || m.Message != "both" || m.VarName != "ARGS:c" || m.Value != "z" {
		t.Errorf("match = %+v", m)
	}
}

func TestMultiMatch(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS:a "@rx \.\./" "id:1,phase:2,log,pass,t:none,t:urlDecodeUni,t:removeNulls,multiMatch,setvar:tx.multi=+1"
SecRule ARGS:a "@rx \.\./" "id:2,phase:2,log,pass,t:none,t:urlDecodeUni,t:removeNulls,setvar:tx.single=+1"
`)
	// The request parser decodes the query once, so %25 arrives as "%".
	tests := []struct {
		target string
		arg    string // what ARGS:a holds
		multi  string
		single string
	}{
		{"/?a=../", "../", "1", "1"},
		{"/?a=..%252f", "..%2f", "1", "1"},
		{"/?a=..%2500%252f", "..%00%2f", "1", "1"},
		// Matches as received and again after decoding changed it.
		{"/?a=../%2541", "../%41", "2", "1"},
		// Only the first step shows the pattern; the single rule tests
		// the last value and still sees it.
		{"/?a=kitap", "kitap", "<unset>", "<unset>"},
	}
	for _, tt := range tests {
		req := get(tt.target)
		if got := req.Parsed.Query[0].Value; got != tt.arg {
			t.Fatalf("%s: ARGS:a = %q, want %q", tt.target, got, tt.arg)
		}
		wantVars(t, rs.Evaluate(req), map[string]string{"multi": tt.multi, "single": tt.single})
	}
}

// With multiMatch a pattern can be seen at a step that a later
// transformation destroys. Without it the rule only sees the final value.
func TestMultiMatchSeesIntermediateValues(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS:a "@rx \.\.\x5c" "id:1,phase:2,log,pass,t:none,t:urlDecodeUni,t:cmdLine,multiMatch"
SecRule ARGS:a "@rx \.\.\x5c" "id:2,phase:2,log,pass,t:none,t:urlDecodeUni,t:cmdLine"
`)
	res := rs.Evaluate(get(`/?a=..%255cwin`)) // ARGS:a is "..%5cwin"
	if got := res.MatchedIDs(); !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("matched = %v, want only rule 1", got)
	}
	if res.Matches[0].Value != `..\win` {
		t.Errorf("matched value = %q", res.Matches[0].Value)
	}
}

func TestCaptureAndLogdata(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS "@rx (\d+)-(\d+)" "id:1,phase:2,log,pass,capture,msg:'range in %{MATCHED_VAR_NAME}',logdata:'%{TX.0}|%{TX.1}|%{tx.2}|%{TX.3}|%{MATCHED_VAR}'"
SecRule ARGS "@rx (\d+)-(\d+)" "id:2,phase:2,log,pass,logdata:'%{TX.0}'"
`)
	res := rs.Evaluate(get("/?q=a12-34b"))
	if len(res.Matches) != 2 {
		t.Fatalf("matches = %+v", res.Matches)
	}
	m := res.Matches[0]
	if m.Message != "range in ARGS:q" || m.Data != "12-34|12|34||a12-34b" || m.VarName != "ARGS:q" || m.Value != "a12-34b" {
		t.Errorf("match = %+v", m)
	}
	wantVars(t, res, map[string]string{"0": "12-34", "1": "12", "2": "34", "3": "<unset>"})

	// Rule 2 has no capture action, so it does not write TX.0 itself. It
	// still sees what rule 1 left there.
	if res.Matches[1].Data != "12-34" {
		t.Errorf("rule 2 data = %q", res.Matches[1].Data)
	}

	// Without rule 1's match nothing is in TX.0.
	rs = loadRules(t, `SecRule ARGS "@rx (\d+)" "id:2,phase:2,log,pass,logdata:'[%{TX.0}]'"`)
	if got := rs.Evaluate(get("/?q=7")).Matches[0].Data; got != "[]" {
		t.Errorf("data without capture = %q", got)
	}
}

func TestVariables(t *testing.T) {
	rs := loadRules(t, `
SecRule &ARGS:q "@eq 2" "id:1,phase:2,log,pass"
SecRule &ARGS "@eq 3" "id:2,phase:2,log,pass"
SecRule REQUEST_HEADERS|!REQUEST_HEADERS:Referer "@rx evil" "id:3,phase:2,log,pass"
SecRule ARGS:missing "!@rx x" "id:4,phase:2,log,pass"
SecRule ARGS:Q "!@rx zzz" "id:5,phase:2,log,pass"
SecRule &TX:nothing "@eq 0" "id:6,phase:2,log,pass"
SecRule REQUEST_URI_RAW "@rx %2e" "id:7,phase:2,log,pass"
SecRule ARGS "@rx %2e" "id:8,phase:2,log,pass"
SecRule REQUEST_HEADERS:x-a "@rx ^fine$" "id:9,phase:2,log,pass"
`)
	res := rs.Evaluate(get("/p?q=1&q=2&r=%2e", httpmodel.Header{Name: "Referer", Value: "evil"}, httpmodel.Header{Name: "X-A", Value: "fine"}))
	// 3: the only header with "evil" is excluded. 4: no value, so nothing
	// is tested, even with a negated operator. 7: the raw URI keeps %2e.
	// 8: the parsed argument does not.
	if got := res.MatchedIDs(); !reflect.DeepEqual(got, []int{1, 2, 5, 6, 7, 9}) {
		t.Errorf("matched = %v, want [1 2 5 6 7 9]", got)
	}

	names := map[int][]string{}
	for _, m := range res.Matches {
		names[m.RuleID] = append(names[m.RuleID], m.VarName+"="+m.Value)
	}
	want := map[int][]string{
		1: {"&ARGS:q=2"},
		2: {"&ARGS=3"},
		5: {"ARGS:q=1", "ARGS:q=2"}, // one match for each value
		6: {"&TX:nothing=0"},
		7: {"REQUEST_URI_RAW=/p?q=1&q=2&r=%2e"},
		9: {"REQUEST_HEADERS:X-A=fine"},
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("match locations = %v\nwant %v", names, want)
	}

	res = rs.Evaluate(get("/", httpmodel.Header{Name: "X-A", Value: "evil"}))
	if len(res.Matches) != 2 || res.Matches[0].RuleID != 3 || res.Matches[0].VarName != "REQUEST_HEADERS:X-A" {
		t.Errorf("matches = %+v, want rule 3 on X-A and rule 6", res.Matches)
	}
}

func TestArgsIncludeTheFormBody(t *testing.T) {
	rs := loadRules(t, `SecRule ARGS "@rx ^\.\./" "id:1,phase:2,log,pass"`)
	post := func(contentType, body string) *httpmodel.Request {
		return httpmodel.New(httpmodel.Received{
			Method:  "POST",
			Target:  "/post?x=1",
			Headers: []httpmodel.Header{{Name: "Content-Type", Value: contentType}},
			Body:    []byte(body),
		})
	}

	res := rs.Evaluate(post("application/x-www-form-urlencoded", "arg=..%2Fetc"))
	if len(res.Matches) != 1 || res.Matches[0].VarName != "ARGS:arg" || res.Matches[0].Value != "../etc" {
		t.Errorf("matches = %+v", res.Matches)
	}

	// The values of a JSON body are arguments too, named by their path.
	res = rs.Evaluate(post("application/json", `{"user": {"files": ["a", "../etc"]}}`))
	if len(res.Matches) != 1 || res.Matches[0].VarName != "ARGS:json.user.files.1" {
		t.Errorf("matches = %+v", res.Matches)
	}

	// A body that is not parsed gives no ARGS. The request's own status
	// says so; the engine reports no match.
	req := post("text/plain", `arg=../etc`)
	if got := rs.Evaluate(req).Matches; len(got) != 0 || req.Status.Body != httpmodel.BodyNotInspected {
		t.Errorf("matches = %+v, body status = %v", got, req.Status.Body)
	}
}

func TestSetvar(t *testing.T) {
	rs := loadRules(t, `
SecAction "id:1,phase:1,nolog,pass,setvar:tx.a=5,setvar:tx.a=+3,setvar:tx.b=-4,setvar:tx.c,setvar:tx.D=x,setvar:!tx.d,setvar:'tx.e=%{tx.A}%{tx.nope}!',setvar:tx.f=abc,setvar:tx.f=+2,setvar:TX.g=+%{tx.a},setvar:tx.h=10,setvar:tx.h=-%{tx.c}"
`)
	wantVars(t, rs.Evaluate(get("/")), map[string]string{
		"a": "8",       // set, then added to
		"b": "0",       // a counter does not go below zero
		"c": "1",       // no value means 1
		"d": "<unset>", // set under another spelling, then removed
		"e": "8!",      // a variable that does not exist expands to nothing
		"f": "2",       // text counts as 0 when a number is added
		"g": "8",
		"h": "9",
	})
}

func TestDefaultActions(t *testing.T) {
	rs := loadRules(t, `
SecDefaultAction "phase:2,nolog,deny,t:urlDecodeUni"
SecRule ARGS "@rx /" "id:1,phase:2,block,log,msg:'inherits the default transformation'"
SecRule ARGS "@rx /" "id:2,phase:2,pass,log,t:none"
SecRule ARGS "@rx /" "id:3,phase:2,setvar:tx.quiet=1"
SecRule ARGS "@rx /" "id:4,phase:1,log"
`)
	res := rs.Evaluate(get("/?a=%252f")) // ARGS:a is "%2f"
	// 2 dropped the inherited decoding. 3 matched but the default says
	// nolog. 4 is in phase 1, which has no SecDefaultAction here, so it
	// does not decode.
	if got := res.MatchedIDs(); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("matched = %v, want [1]", got)
	}
	// block takes the default's deny. It is only recorded.
	if res.Matches[0].Action != "deny" || res.Matches[0].Value != "/" {
		t.Errorf("match = %+v", res.Matches[0])
	}
	wantVars(t, res, map[string]string{"quiet": "1"})
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		msgs  []string
	}{
		{"action", []string{`SecAction "id:7,phase:1,pass,initcol:ip=x"`}, []string{"rulesa.conf:1: rule 7: action initcol is not supported"}},
		{"ctl", []string{`SecAction "id:7,phase:1,pass,ctl:ruleEngine=Off"`}, []string{"rule 7: ctl:ruleEngine=Off: only ctl:ruleEngine=DetectionOnly is supported"}},
		{"ctl unknown", []string{`SecAction "id:7,phase:1,pass,ctl:debugLogLevel=9"`}, []string{"rule 7: ctl:debugLogLevel=9: ctl:debugLogLevel is not supported"}},
		{"ctl bad id", []string{`SecAction "id:7,phase:1,pass,ctl:ruleRemoveById=5-2"`}, []string{`ctl:ruleRemoveById=5-2: "5-2" is not a rule id or a range of ids`}},
		{"ctl body processor", []string{`SecAction "id:7,phase:1,pass,ctl:requestBodyProcessor=RAW"`}, []string{`body processor "RAW" is not supported`}},
		{"ip list", []string{`SecRule REMOTE_ADDR "@ipMatch 10.0.0.1,10.0.0.300" "id:7,phase:1"`}, []string{`rule 7: @ipMatch: "10.0.0.300" is not an address or network`}},
		{"ctl without variable", []string{`SecAction "id:7,phase:1,pass,ctl:ruleRemoveTargetByTag=x"`}, []string{"expected TAG;VARIABLE"}},
		{"operator", []string{`SecRule ARGS "@rbl zen.example" "id:7,phase:2"`}, []string{"rule 7: operator @rbl is not supported"}},
		{"data file", []string{`SecRule ARGS "@pmFromFile x.data" "id:7,phase:2"`}, []string{"rule 7: @pmFromFile: open ", "x.data"}},
		{"regex", []string{`SecRule ARGS "@rx (?=a)" "id:7,phase:2"`}, []string{"rule 7: @rx: "}},
		{"transformation", []string{`SecRule ARGS "@rx a" "id:7,phase:2,t:none,t:sha1"`}, []string{`rule 7: transformation "sha1" is not supported`}},
		{"variable", []string{`SecRule RESPONSE_BODY "@rx a" "id:7,phase:2"`}, []string{"rule 7: variable RESPONSE_BODY is not supported"}},
		{"regex selector", []string{`SecRule ARGS:/(a/ "@rx a" "id:7,phase:2"`}, []string{"rule 7: variable ARGS:/(a/: error parsing regexp"}},
		{"bad regex selector on tx", []string{`SecRule TX:/a(/ "@rx a" "id:7,phase:2"`}, []string{"rule 7: variable TX:/a(/"}},
		{"selector on single value", []string{`SecRule REQUEST_FILENAME:x "@rx a" "id:7,phase:2"`}, []string{"variable REQUEST_FILENAME takes no selector"}},
		{"update with unsupported variable", []string{"SecRule ARGS \"@rx a\" \"id:7,phase:2\"\nSecRuleUpdateTargetById 7 \"!GEO:x\""}, []string{"rulesa.conf:2: SecRuleUpdateTargetById 7: variable GEO is not supported"}},
		{"tx without name", []string{`SecRule TX "@rx a" "id:7,phase:2"`}, []string{"TX without a variable name"}},
		{"phase", []string{`SecRule ARGS "@rx a" "id:7,phase:4"`}, []string{"rule 7: phase 4 is not supported"}},
		{"marker", []string{`SecAction "id:7,phase:1,pass,skipAfter:NOWHERE"`}, []string{"rulesa.conf:1: skipAfter names marker NOWHERE"}},
		{"macro", []string{`SecAction "id:7,phase:1,pass,setvar:'tx.a=%{REMOTE_PORT}'"`}, []string{"macro %{REMOTE_PORT} is not supported"}},
		{"macro in msg", []string{`SecRule ARGS "@rx a" "id:7,phase:2,msg:'%{REMOTE_PORT}'"`}, []string{"rule 7: msg: macro %{REMOTE_PORT} is not supported"}},
		{"macro in operator", []string{`SecRule ARGS "@eq %{GEO.x}" "id:7,phase:2"`}, []string{"operator argument: macro %{GEO.x} is not supported"}},
		{"setvar collection", []string{`SecAction "id:7,phase:1,pass,setvar:ip.count=+1"`}, []string{"setvar:ip.count=+1: only tx.name variables are supported"}},
		{"setvar macro name", []string{`SecAction "id:7,phase:1,pass,setvar:'tx.a_%{GEO.x}=1'"`}, []string{"rule 7: setvar:tx.a_%{GEO.x}=1: macro %{GEO.x} is not supported"}},
		{"chained action", []string{"SecRule ARGS \"@rx a\" \"id:7,phase:2,chain\"\n    SecRule ARGS \"@rx b\" \"msg:'x'\""}, []string{"rulesa.conf:2: rule 7: action msg is not supported on a chained rule"}},
		{"default action", []string{`SecDefaultAction "phase:2,log,pass,ctl:ruleEngine=Off"`}, []string{"SecDefaultAction: action ctl is not supported"}},
		{"duplicate id in two files", []string{`SecAction "id:7,phase:1,pass"`, `SecAction "id:7,phase:1,pass"`}, []string{"rulesb.conf:1: rule id 7 is already used at", "rulesa.conf:1"}},
		// Every problem is reported, not only the first.
		{"several", []string{"SecAction \"id:7,phase:1,pass,initcol:ip=x\"\nSecRule ARGS \"@rbl a\" \"id:8,phase:2,t:md5\""},
			[]string{"rule 7: action initcol", "rule 8: operator @rbl", `rule 8: transformation "md5"`}},
		{"syntax", []string{`SecRuleEngine On`}, []string{"rulesa.conf:1: unsupported directive SecRuleEngine"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(rulesConfig(t, tt.rules...))
			if err == nil {
				t.Fatal("Load succeeded")
			}
			for _, msg := range tt.msgs {
				if !strings.Contains(err.Error(), msg) {
					t.Errorf("error does not contain %q:\n%v", msg, err)
				}
			}
		})
	}

	if _, err := Load(Config{Files: []string{"does-not-exist.conf"}}); err == nil {
		t.Error("no error for a missing rule file")
	}
	if _, err := Load(Config{}); err == nil {
		t.Error("no error for a configuration without files")
	}
}

func TestExclusions(t *testing.T) {
	cfg := rulesConfig(t, `
SecAction "id:1,phase:1,nolog,pass,setvar:tx.one=1"
SecRule RESPONSE_BODY "@within a b" "id:2,phase:2,t:sha1,chain"
    SecRule ARGS "@within a" "initcol:ip=x"
SecAction "id:3,phase:2,nolog,pass,setvar:tx.three=1"
`)
	cfg.Exclude = []Exclusion{{ID: 2, Reason: "not needed here"}}
	rs, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The excluded chain is dropped as a whole and the rest runs.
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"one": "1", "three": "1"})

	statuses := rs.Statuses()
	if len(statuses) != 3 {
		t.Fatalf("statuses = %+v", statuses)
	}
	if s := statuses[1]; s.ID != 2 || s.Active || s.Reason != "not needed here" || s.Pos.Line != 3 || s.Phase != 2 {
		t.Errorf("status of rule 2 = %+v", s)
	}
	if !statuses[0].Active || !statuses[2].Active || statuses[0].Reason != "" {
		t.Errorf("statuses = %+v", statuses)
	}

	cfg.Exclude = append(cfg.Exclude, Exclusion{ID: 99, Reason: "typo"})
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "excluded rule 99 is in none of the loaded files") {
		t.Errorf("error = %v", err)
	}
	cfg.Exclude = []Exclusion{{ID: 2}}
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "exclusion of rule 2 has no reason") {
		t.Errorf("error = %v", err)
	}
}

func TestFilesAndXMLVariables(t *testing.T) {
	rs := loadRules(t, `
SecComponentSignature "TEST/1"
SecRule FILES "@rx \.\./" "id:1,phase:2,log,pass"
SecRule FILES_NAMES "@rx ^doc$" "id:2,phase:2,log,pass"
SecRule ARGS "@rx ^hello$" "id:3,phase:2,log,pass"
SecRule XML:/* "@rx \.\./" "id:4,phase:2,log,pass"
SecRule XML://@* "@rx \.\./" "id:5,phase:2,log,pass"
SecRule ARGS|!XML:/* "@rx zzz" "id:6,phase:2,log,pass"
`)
	if rs.Signature() != "TEST/1" {
		t.Errorf("signature = %q", rs.Signature())
	}
	locations := func(req *httpmodel.Request) []string {
		var out []string
		for _, m := range rs.Evaluate(req).Matches {
			out = append(out, fmt.Sprintf("%d %s=%s", m.RuleID, m.VarName, m.Value))
		}
		return out
	}
	post := func(contentType, body string) *httpmodel.Request {
		return httpmodel.New(httpmodel.Received{
			Method:  "POST",
			Target:  "/upload",
			Headers: []httpmodel.Header{{Name: "Content-Type", Value: contentType}},
			Body:    []byte(body),
		})
	}

	multipart := "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" +
		"--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"../../x.txt\"\r\n\r\nfile content ../ here\r\n--B--\r\n"
	want := []string{
		// The file name is inspected with its path; the file content is not.
		"1 FILES:doc=../../x.txt",
		"2 FILES_NAMES:doc=doc",
		"3 ARGS:note=hello",
	}
	if got := locations(post("multipart/form-data; boundary=B", multipart)); !reflect.DeepEqual(got, want) {
		t.Errorf("multipart matches = %q\nwant %q", got, want)
	}

	xml := `<?xml version="1.0"?><order ref="a/../b"><item>../../etc</item><item>fine</item></order>`
	want = []string{"4 XML:/*=../../etc", "5 XML://@*=a/../b"}
	if got := locations(post("application/xml", xml)); !reflect.DeepEqual(got, want) {
		t.Errorf("xml matches = %q\nwant %q", got, want)
	}

	// Other XPath expressions are refused when the rules are loaded.
	if _, err := Load(rulesConfig(t, `SecRule XML:/order/item "@rx a" "id:1,phase:2"`)); err == nil || !strings.Contains(err.Error(), "only XML:/* and XML://@* are supported") {
		t.Errorf("error = %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("r.conf", `SecAction "id:1,phase:1,nolog,pass,setvar:tx.ok=1"`)

	cfg, err := LoadConfig(write("ok.json", `{"files": ["r.conf"], "exclude": []}`))
	if err != nil {
		t.Fatal(err)
	}
	// A relative path is taken from the directory of the configuration.
	if cfg.Files[0] != filepath.Join(dir, "r.conf") {
		t.Errorf("file = %q", cfg.Files[0])
	}
	rs, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"ok": "1"})

	bad := []struct{ content, msg string }{
		{`{"files": []}`, "no rule files are listed"},
		{`{"files": ["r.conf"], "exclude": [{"id": 1}]}`, "exclusion of rule 1 has no reason"},
		{`{"files": ["r.conf"], "exclude": [{"id": 0, "reason": "x"}]}`, "invalid rule id 0"},
		{`{"files": ["r.conf"], "exclude": [{"id": 1, "reason": "x"}, {"id": 1, "reason": "y"}]}`, "rule 1 is excluded twice"},
		{`{"files": ["r.conf"], "excluded": []}`, `unknown field "excluded"`},
		{`{"files": ["r.conf"], "paranoia_level": 5}`, "paranoia level 5 is not supported; it must be 1 to 4"},
		{`{"files": ["r.conf"], "paranoia_level": -1}`, "paranoia level -1 is not supported"},
		{`{"files": ["r.conf"]} {}`, "unexpected content"},
		{`not json`, "invalid JSON"},
	}
	for _, tt := range bad {
		if _, err := LoadConfig(write("bad.json", tt.content)); err == nil || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("LoadConfig(%s): error = %v, want one containing %q", tt.content, err, tt.msg)
		}
	}
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("no error for a missing configuration file")
	}
}

// The paranoia level of the configuration becomes the TX variable that the
// CRS files read. Without a level it is 1, the CRS default.
func TestParanoiaLevel(t *testing.T) {
	rule := `SecRule TX:blocking_paranoia_level "@ge 3" "id:1,phase:1,pass,nolog,tag:'paranoia-level/3',setvar:tx.high=1"`
	cfg := rulesConfig(t, rule)

	rs, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rs.ParanoiaLevel() != 1 {
		t.Errorf("level = %d, want 1", rs.ParanoiaLevel())
	}
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"blocking_paranoia_level": "1"})
	if s := rs.Statuses()[0]; s.ParanoiaLevel != 3 {
		t.Errorf("level of the rule = %d, want 3", s.ParanoiaLevel)
	}

	cfg.ParanoiaLevel = 3
	rs, err = Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"blocking_paranoia_level": "3", "high": "1"})
	// The starting values are copied for each request, not shared.
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"blocking_paranoia_level": "3", "high": "1"})

	cfg.ParanoiaLevel = 5
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "paranoia level 5 is not supported") {
		t.Errorf("level 5: error = %v", err)
	}
}

// A log line has the bracket form that the CRS tests look for.
func TestLogLine(t *testing.T) {
	rs := loadRules(t, `SecRule ARGS "@rx b(.)d" "id:7,phase:2,pass,log,capture,msg:'Found \"%{tx.1}\"',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}'"`)
	res := rs.Evaluate(get("/?x=bad"))
	want := []string{`[id "7"] [msg "Found \"a\""] [data "Matched Data: bad found within ARGS:x"]`}
	if got := res.LogLines(); !reflect.DeepEqual(got, want) {
		t.Errorf("log lines = %q\nwant        %q", got, want)
	}
}

func TestParseTemplate(t *testing.T) {
	tx := &transaction{vars: map[string]string{"a": "1", "b": ""}, matchedVar: "V", matchedVarName: "N"}
	tests := []struct {
		in    string
		want  string
		macro bool
	}{
		{"", "", false},
		{"plain", "plain", false},
		{"%{tx.a}", "1", true},
		{"x%{TX.A}y%{tx.a}", "x1y1", true},
		{"[%{tx.b}][%{tx.none}]", "[][]", true},
		{"%{MATCHED_VAR_NAME}=%{matched_var}", "N=V", true},
		// A "%" that starts no complete macro is text.
		{"100%", "100%", false},
		{"%{tx.a", "%{tx.a", false},
		{"%{}%{tx.a}", "%{}1", true},
		{"50% of %{tx.a}%", "50% of 1%", true},
	}
	for _, tt := range tests {
		tmpl, err := parseTemplate(tt.in)
		if err != nil {
			t.Errorf("parseTemplate(%q): %v", tt.in, err)
			continue
		}
		if got := tmpl.expand(tx); got != tt.want || tmpl.macro != tt.macro {
			t.Errorf("parseTemplate(%q): expands to %q with macro %v, want %q with macro %v", tt.in, got, tmpl.macro, tt.want, tt.macro)
		}
	}
	for _, in := range []string{"%{tx}", "%{REMOTE_PORT}", "%{MATCHED_VAR.x}", "%{REQUEST_LINE.x}", "%{GEO.a}"} {
		if _, err := parseTemplate(in); err == nil {
			t.Errorf("parseTemplate(%q): no error", in)
		}
	}
}

func TestSensitiveTexts(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS "@rx (a+)" "id:1,phase:2,log,pass,capture,msg:'found in %{MATCHED_VAR_NAME}, score %{tx.score}',logdata:'%{TX.0}',setvar:tx.score=+5,setvar:'tx.copy=%{MATCHED_VAR}',setvar:'tx.copy2=x%{tx.copy}'"
SecRule ARGS "@rx a" "id:2,phase:2,log,pass,msg:'value %{MATCHED_VAR}',logdata:'fixed text'"
SecRule ARGS "@rx a" "id:3,phase:2,log,pass,msg:'via %{tx.copy2}',logdata:'score %{tx.score}'"
SecAction "id:4,phase:2,log,pass,msg:'always'"
`)
	res := rs.Evaluate(get("/?q=aa"))
	if len(res.Matches) != 4 {
		t.Fatalf("matches = %+v", res.Matches)
	}
	want := []struct{ msg, data bool }{
		{false, true}, // the location and a score are not request content; a capture is
		{true, false},
		{true, false}, // tx.copy2 was filled from tx.copy, which holds the matched value
		{false, false},
	}
	for i, m := range res.Matches {
		if m.MessageSensitive != want[i].msg || m.DataSensitive != want[i].data {
			t.Errorf("rule %d: message sensitive %v, data sensitive %v; want %v, %v", m.RuleID, m.MessageSensitive, m.DataSensitive, want[i].msg, want[i].data)
		}
	}
	if res.Matches[2].Message != "via xaa" {
		t.Errorf("rule 3 message = %q", res.Matches[2].Message)
	}
	// A SecAction tests nothing, so it reports no location or value, even
	// though the rule before it matched one.
	if m := res.Matches[3]; m.VarName != "" || m.Value != "" {
		t.Errorf("SecAction match = %+v", m)
	}
}

func TestRequestVariables(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_COOKIES "@rx \.\./" "id:1,phase:2,log,pass"
SecRule REQUEST_COOKIES_NAMES "@rx ^sess" "id:2,phase:2,log,pass"
SecRule REQUEST_COOKIES:THEME "@rx ^dark$" "id:3,phase:2,log,pass"
SecRule ARGS_NAMES "@rx \[" "id:4,phase:2,log,pass"
SecRule REQUEST_FILENAME "@rx \.env$" "id:5,phase:2,log,pass"
SecRule REQUEST_BASENAME "@rx ^\.env$" "id:6,phase:2,log,pass"
SecRule REQUEST_FILENAME "@rx secret" "id:7,phase:2,log,pass"
SecRule &REQUEST_COOKIES "@eq 3" "id:8,phase:2,log,pass"
SecRule ARGS_NAMES:user[name] "@rx ." "id:9,phase:2,log,pass"
`)
	req := get("/app/config/.env?user[name]=efe&secret=1",
		httpmodel.Header{Name: "Cookie", Value: "session=abc; theme=dark; path=a/../b"})
	res := rs.Evaluate(req)

	got := map[int]string{}
	for _, m := range res.Matches {
		got[m.RuleID] = m.VarName + "=" + m.Value
	}
	want := map[int]string{
		1: "REQUEST_COOKIES:path=a/../b",
		2: "REQUEST_COOKIES_NAMES:session=session",
		3: "REQUEST_COOKIES:theme=dark",
		4: "ARGS_NAMES:user[name]=user[name]",
		// The file name is the path without the query string, so the
		// parameter called "secret" does not make rule 7 match.
		5: "REQUEST_FILENAME=/app/config/.env",
		6: "REQUEST_BASENAME=.env",
		8: "&REQUEST_COOKIES=3",
		9: "ARGS_NAMES:user[name]=user[name]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %v\nwant      %v", got, want)
	}
}

// The variables of the request line and the body.
func TestRequestLineAndBodyVariables(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,log,pass"
SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" "id:2,phase:1,log,pass"
SecRule REQUEST_LINE "@rx ." "id:3,phase:1,log,pass"
SecRule REQUEST_URI "@rx ." "id:4,phase:1,log,pass"
SecRule QUERY_STRING "@rx ." "id:5,phase:1,log,pass"
SecRule REQUEST_BODY "@rx ." "id:6,phase:2,log,pass"
SecRule REQUEST_HEADERS_NAMES "@rx ^x-" "id:7,phase:1,log,pass,t:lowercase"
SecRule ARGS_GET "@rx ." "id:8,phase:2,log,pass"
SecRule ARGS_POST "@rx ." "id:9,phase:2,log,pass"
SecRule ARGS_GET_NAMES "@rx ." "id:10,phase:2,log,pass"
SecRule ARGS_POST_NAMES "@rx ." "id:11,phase:2,log,pass"
SecRule &REQUEST_BODY "@eq 1" "id:12,phase:2,log,pass"
`)
	matchesOf := func(req *httpmodel.Request) map[int]string {
		got := map[int]string{}
		for _, m := range rs.Evaluate(req).Matches {
			got[m.RuleID] = m.VarName + "=" + m.Value
		}
		return got
	}

	form := httpmodel.New(httpmodel.Received{
		Method: "POST", Target: "http://shop.test/a%20b?q=1%2B1", Version: "HTTP/1.0",
		Headers: []httpmodel.Header{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}, {Name: "X-Test", Value: "1"}},
		Body:    []byte("p=%41"),
	})
	want := map[int]string{
		1: "REQUEST_METHOD=POST",
		2: "REQUEST_PROTOCOL=HTTP/1.0",
		// The line as sent, and the URI without scheme and host. Neither
		// is decoded.
		3:  "REQUEST_LINE=POST http://shop.test/a%20b?q=1%2B1 HTTP/1.0",
		4:  "REQUEST_URI=/a%20b?q=1%2B1",
		5:  "QUERY_STRING=q=1%2B1",
		6:  "REQUEST_BODY=p=%41",
		7:  "REQUEST_HEADERS_NAMES:X-Test=x-test",
		8:  "ARGS_GET:q=1+1",
		9:  "ARGS_POST:p=A",
		10: "ARGS_GET_NAMES:q=q",
		11: "ARGS_POST_NAMES:p=p",
		12: "&REQUEST_BODY=1",
	}
	if got := matchesOf(form); !reflect.DeepEqual(got, want) {
		t.Errorf("form body: matches = %v\nwant              %v", got, want)
	}

	// REQUEST_BODY is the body as one text when it is a form or of a type
	// that has no reader. A JSON body is given to the rules in parts only.
	body := func(contentType, body string) *httpmodel.Request {
		return httpmodel.New(httpmodel.Received{
			Method: "POST", Target: "/", Version: "HTTP/1.1",
			Headers: []httpmodel.Header{{Name: "Content-Type", Value: contentType}},
			Body:    []byte(body),
		})
	}
	if got := matchesOf(body("text/plain", "a=b"))[6]; got != "REQUEST_BODY=a=b" {
		t.Errorf("text/plain: rule 6 = %q", got)
	}
	if got := matchesOf(body("text/plain", "a=b")); got[9] != "" || got[11] != "" {
		t.Errorf("text/plain: the body was split into parameters: %v", got)
	}
	for _, contentType := range []string{"application/json", "text/xml", "multipart/form-data; boundary=x"} {
		got := matchesOf(body(contentType, `{"a": "b"}`))
		if got[6] != "" || got[12] != "" {
			t.Errorf("%s: REQUEST_BODY has a value: %v", contentType, got)
		}
	}
	if got := matchesOf(get("/")); got[6] != "" || got[5] != "" || got[4] != "REQUEST_URI=/" {
		t.Errorf("no body, no query: %v", got)
	}
}

// A setvar name may be built from a macro, a pattern on TX selects the
// variables made that way, and a macro may name any variable of the request.
// This is the shape of CRS rules 931130 and 943110.
func TestDynamicNamesAndRequestMacros(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS "@rx ^https?://([^/]*)" "id:1,phase:2,log,pass,capture,msg:'link to %{tx.1} on %{request_headers.host}',\
    setvar:'tx.link_%{MATCHED_VAR_NAME}=.%{tx.1}',chain"
    SecRule TX:/^link_/ "!@endsWith .%{request_headers.host}" "setvar:tx.off_domain=+1"
SecRule &TX:/^link_/ "@gt 0" "id:2,phase:2,pass,nolog,setvar:tx.links=%{MATCHED_VAR}"
SecRule ARGS:a "@rx ." "id:3,phase:2,pass,nolog,chain"
    SecRule MATCHED_VAR "@beginsWith http" "setvar:tx.matched_var=%{MATCHED_VAR_NAME}"
SecRule REQUEST_METHOD "@streq %{ARGS.m}" "id:4,phase:2,pass,nolog,setvar:tx.method_matches=1"
`)
	host := httpmodel.Header{Name: "Host", Value: "shop.test"}

	res := rs.Evaluate(get("/?a=http://img.shop.test/x&B=https://evil.example/y&m=GET", host))
	wantVars(t, res, map[string]string{
		// Names are kept in lower case.
		"link_args:a":    ".img.shop.test",
		"link_args:b":    ".evil.example",
		"off_domain":     "1",
		"links":          "2",
		"matched_var":    "MATCHED_VAR",
		"method_matches": "1",
	})
	if len(res.Matches) != 1 || res.Matches[0].Message != "link to evil.example on shop.test" || res.Matches[0].VarName != "TX:link_args:b" {
		t.Errorf("matches = %+v", res.Matches)
	}
	if !res.Matches[0].MessageSensitive {
		t.Error("a message built from a request header is not marked as sensitive")
	}

	res = rs.Evaluate(get("/?a=http://img.shop.test/x&m=POST", host))
	wantVars(t, res, map[string]string{"off_domain": "<unset>", "links": "1", "method_matches": "<unset>"})
	if len(res.Matches) != 0 {
		t.Errorf("matches = %+v", res.Matches)
	}
}

// ctl:ruleRemoveById and ctl:ruleRemoveByTag switch rules off for the rest
// of the request, in this phase and the next. Other requests are not
// affected.
func TestRuleRemoval(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS:off "@streq id" "id:1,phase:1,pass,nolog,ctl:ruleRemoveById=3,ctl:ruleRemoveById=10-11"
SecRule ARGS:off "@streq tag" "id:2,phase:1,pass,nolog,chain"
    SecRule ARGS:also "@streq yes" "ctl:ruleRemoveByTag=^attack-(?:xss|sqli)$"
SecAction "id:3,phase:1,pass,nolog,setvar:tx.r3=1"
SecAction "id:4,phase:2,pass,nolog,tag:'attack-xss',setvar:tx.r4=1"
SecAction "id:5,phase:2,pass,nolog,tag:'attack-sqli-extra',setvar:tx.r5=1"
SecAction "id:10,phase:2,pass,nolog,setvar:tx.r10=1"
SecAction "id:11,phase:2,pass,nolog,setvar:tx.r11=1"
SecAction "id:12,phase:2,pass,nolog,setvar:tx.r12=1"
`)
	all := map[string]string{"r3": "1", "r4": "1", "r5": "1", "r10": "1", "r11": "1", "r12": "1"}
	wantVars(t, rs.Evaluate(get("/")), all)
	wantVars(t, rs.Evaluate(get("/?off=id")), map[string]string{"r3": "<unset>", "r4": "1", "r10": "<unset>", "r11": "<unset>", "r12": "1"})
	// The ctl of a chained rule runs only when the chain gets that far.
	wantVars(t, rs.Evaluate(get("/?off=tag")), all)
	// The pattern must match a whole tag here because of ^ and $:
	// "attack-sqli-extra" does not.
	wantVars(t, rs.Evaluate(get("/?off=tag&also=yes")), map[string]string{"r3": "1", "r4": "<unset>", "r5": "1", "r12": "1"})
	wantVars(t, rs.Evaluate(get("/")), all)
}

// ctl:requestBodyProcessor in phase 1 chooses the reader for the body,
// which is then read again before phase 2. REQBODY_PROCESSOR shows the
// choice. The request passed in is not changed.
func TestRequestBodyProcessor(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/vnd\.test\+json" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_PROCESSOR "@rx ." "id:2,phase:1,pass,nolog,setvar:tx.p1=%{MATCHED_VAR}"
SecRule REQBODY_PROCESSOR "@rx ." "id:3,phase:2,pass,nolog,setvar:tx.p2=%{MATCHED_VAR}"
SecRule ARGS:json.a "@streq b" "id:4,phase:2,pass,log"
`)
	post := func(contentType string) *httpmodel.Request {
		return httpmodel.New(httpmodel.Received{
			Method: "POST", Target: "/", Version: "HTTP/1.1", Body: []byte(`{"a":"b"}`),
			Headers: []httpmodel.Header{{Name: "Content-Type", Value: contentType}},
		})
	}
	req := post("application/vnd.test+json")
	res := rs.Evaluate(req)
	wantVars(t, res, map[string]string{"p1": "JSON", "p2": "JSON"})
	if ids := res.MatchedIDs(); !reflect.DeepEqual(ids, []int{4}) {
		t.Errorf("matched %v", ids)
	}
	if req.Status.BodyFormat != "" || res.Request == req || res.Request.Status.BodyFormat != "json" {
		t.Errorf("request status %+v, result request status %+v", req.Status, res.Request.Status)
	}

	// Without the ctl the type has no reader.
	res = rs.Evaluate(post("application/other+json"))
	wantVars(t, res, map[string]string{"p1": "<unset>", "p2": "<unset>"})
	if len(res.Matches) != 0 || res.Request.Status.Body != httpmodel.BodyNotInspected {
		t.Errorf("matches %v, status %+v", res.Matches, res.Request.Status)
	}
	// A form is known from the headers, before the body is read.
	res = rs.Evaluate(post("application/x-www-form-urlencoded"))
	wantVars(t, res, map[string]string{"p1": "URLENCODED", "p2": "URLENCODED"})
}

// The variables about sizes and the client.
func TestSizeAndClientVariables(t *testing.T) {
	rs := loadRules(t, `
SecRule ARGS_COMBINED_SIZE "@rx ." "id:1,phase:2,pass,nolog,setvar:tx.args=%{MATCHED_VAR}"
SecRule FILES_COMBINED_SIZE "@rx ." "id:2,phase:2,pass,nolog,setvar:tx.files=%{MATCHED_VAR}"
SecRule REQUEST_BODY_LENGTH "@rx ." "id:3,phase:2,pass,nolog,setvar:tx.body=%{MATCHED_VAR}"
SecRule REMOTE_ADDR "@ipMatch 192.0.2.0/24" "id:4,phase:1,pass,nolog,setvar:tx.client=%{REMOTE_ADDR}"
`)
	body := "--b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n12345678\r\n" +
		"--b\r\nContent-Disposition: form-data; name=\"g\"; filename=\"b.txt\"\r\n\r\n12\r\n--b--\r\n"
	req := httpmodel.New(httpmodel.Received{
		Method: "POST", Target: "/?q=abc", Version: "HTTP/1.1", RemoteAddr: "192.0.2.10", Body: []byte(body),
		Headers: []httpmodel.Header{{Name: "Content-Type", Value: "multipart/form-data; boundary=b"}},
	})
	wantVars(t, rs.Evaluate(req), map[string]string{
		// q=abc and note=hello: 1+3 and 4+5 bytes.
		"args": "13",
		// The two files, 8 and 2 bytes; the text field is not a file.
		"files":  "10",
		"body":   strconv.Itoa(len(body)),
		"client": "192.0.2.10",
	})
	wantVars(t, rs.Evaluate(get("/")), map[string]string{"args": "0", "files": "0", "body": "0", "client": "<unset>"})
}

// A request line without a version is an HTTP/0.9 request. Like Apache,
// the engine gives the rules the line as sent.
func TestHTTP09(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_LINE "@rx ." "id:1,phase:1,pass,nolog,setvar:tx.line=%{MATCHED_VAR}"
SecRule REQUEST_PROTOCOL "@rx ." "id:2,phase:1,pass,nolog,setvar:tx.protocol=%{MATCHED_VAR}"
`)
	req := httpmodel.New(httpmodel.Received{Method: "GET", Target: "/"})
	wantVars(t, rs.Evaluate(req), map[string]string{"line": "GET /", "protocol": "HTTP/0.9"})
	wantVars(t, rs.Evaluate(get("/a")), map[string]string{"line": "GET /a HTTP/1.1", "protocol": "HTTP/1.1"})
}

func TestRegexSelectors(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_COOKIES:/^_ga/ "@rx ." "id:1,phase:2,log,pass"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/^_GA(?:_\w+)?$/ "@rx evil" "id:2,phase:2,log,pass"
SecRule &ARGS:/^item\d+$/ "@eq 2" "id:3,phase:2,log,pass"
SecRule ARGS:/a|b/ "@rx ^1$" "id:4,phase:2,log,pass"
`)
	req := get("/?item1=x&item22=y&items=z&b=1&c=1",
		httpmodel.Header{Name: "Cookie", Value: "_ga=evil; _ga_ABC=evil; _gax=evil; other=fine"})
	res := rs.Evaluate(req)

	var got []string
	for _, m := range res.Matches {
		got = append(got, fmt.Sprintf("%d %s", m.RuleID, m.VarName))
	}
	want := []string{
		"1 REQUEST_COOKIES:_ga", "1 REQUEST_COOKIES:_ga_ABC", "1 REQUEST_COOKIES:_gax",
		// The exclusion is matched without regard to case and removes
		// _ga and _ga_ABC, but not _gax.
		"2 REQUEST_COOKIES:_gax",
		"3 &ARGS:^item\\d+$",
		// A "|" inside the selector belongs to the pattern.
		"4 ARGS:b",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %q\nwant      %q", got, want)
	}
}

func TestUpdateTargetByID(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_COOKIES|ARGS "@rx evil" "id:1,phase:2,log,pass"
SecRule REQUEST_COOKIES "@rx evil" "id:2,phase:2,log,pass"
SecRule REQUEST_COOKIES "@rx evil" "id:3,phase:2,log,pass"
SecRuleUpdateTargetById 1 "!REQUEST_COOKIES:/^_ga/"
SecRuleUpdateTargetById 1 "!REQUEST_COOKIES:consent|!XML:/*"
SecRuleUpdateTargetById 2 "REQUEST_HEADERS:X-Extra"
SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:/^_ga/"
SecRuleUpdateTargetById 942100 "!REQUEST_COOKIES:x"
SecRuleUpdateTargetById 932240 "!REQUEST_COOKIES:y"
`)
	req := get("/?q=evil",
		httpmodel.Header{Name: "Cookie", Value: "_ga=evil; consent=evil; real=evil"},
		httpmodel.Header{Name: "X-Extra", Value: "evil"})
	res := rs.Evaluate(req)

	var got []string
	for _, m := range res.Matches {
		got = append(got, fmt.Sprintf("%d %s", m.RuleID, m.VarName))
	}
	want := []string{
		// Two cookies were taken out of rule 1; its other variable stays.
		"1 REQUEST_COOKIES:real", "1 ARGS:q",
		// Rule 2 got one more place to look.
		"2 REQUEST_COOKIES:_ga", "2 REQUEST_COOKIES:consent", "2 REQUEST_COOKIES:real", "2 REQUEST_HEADERS:X-Extra",
		// Rule 3 was not touched.
		"3 REQUEST_COOKIES:_ga", "3 REQUEST_COOKIES:consent", "3 REQUEST_COOKIES:real",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %q\nwant      %q", got, want)
	}
	// Updates for rules that are not loaded change nothing and are listed.
	if got := rs.IgnoredTargetUpdates(); !reflect.DeepEqual(got, []int{932240, 942100}) {
		t.Errorf("ignored updates = %v", got)
	}
}

func TestMatchedVars(t *testing.T) {
	// The second rule tests what the first rule matched, not the whole
	// request: here, whether a parameter with "select" also has "from".
	rs := loadRules(t, `
SecRule ARGS "@rx (?i)select" "id:1,phase:2,log,pass,t:none,t:lowercase,chain"
    SecRule MATCHED_VARS "@rx from" "t:none"
SecRule ARGS:q "@rx ." "id:2,phase:2,log,pass,chain"
    SecRule MATCHED_VARS "@rx ^zzz$"
SecRule MATCHED_VARS "@rx ." "id:3,phase:2,log,pass"
`)
	res := rs.Evaluate(get("/?a=SELECT+1&b=Select+x+from+t&c=from&q=1"))
	var got []string
	for _, m := range res.Matches {
		got = append(got, fmt.Sprintf("%d %s=%s", m.RuleID, m.VarName, m.Value))
	}
	// Only b has both words. The value is the one the first rule tested,
	// so it is in lower case. Rule 3 is no chain: nothing has matched
	// before it, and what rules 1 and 2 matched is gone.
	want := []string{"1 MATCHED_VARS:ARGS:b=select x from t"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matches = %q, want %q", got, want)
	}
}

func TestRemoveTargetByTag(t *testing.T) {
	rs := loadRules(t, `
SecRule REQUEST_FILENAME "!@validateByteRange 45-57,65-90,95,97-122" "id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=skip-plain-path;REQUEST_FILENAME"
SecRule ARGS|REQUEST_FILENAME "@rx admin" "id:2,phase:2,log,pass,tag:'group-a',tag:'skip-plain-path'"
SecRule ARGS|REQUEST_FILENAME "@rx admin" "id:3,phase:2,log,pass,tag:'group-a'"
`)
	locations := func(target string) []string {
		var out []string
		for _, m := range rs.Evaluate(get(target)).Matches {
			out = append(out, fmt.Sprintf("%d %s", m.RuleID, m.VarName))
		}
		return out
	}
	// A path of plain characters: rule 1 matches and takes the path away
	// from the rule with the tag, for this request only.
	if got, want := locations("/admin/list?q=admin"), []string{"2 ARGS:q", "3 ARGS:q", "3 REQUEST_FILENAME"}; !reflect.DeepEqual(got, want) {
		t.Errorf("plain path: %q, want %q", got, want)
	}
	// A path with other characters: rule 1 does not match, nothing is
	// removed. The request before left nothing behind.
	if got, want := locations("/admin/<list>?q=admin"), []string{"2 ARGS:q", "2 REQUEST_FILENAME", "3 ARGS:q", "3 REQUEST_FILENAME"}; !reflect.DeepEqual(got, want) {
		t.Errorf("other path: %q, want %q", got, want)
	}
}
