package engine

import (
	"os"
	"path/filepath"
	"reflect"
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

	// A body that is not parsed gives no ARGS. The request's own status
	// says so; the engine reports no match.
	req := post("application/json", `{"arg":"../etc"}`)
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
		{"action", []string{`SecAction "id:7,phase:1,pass,ctl:ruleEngine=Off"`}, []string{"rulesa.conf:1: rule 7: action ctl is not supported"}},
		{"operator", []string{`SecRule ARGS "@pmFromFile x.data" "id:7,phase:2"`}, []string{"rule 7: operator @pmFromFile is not supported"}},
		{"regex", []string{`SecRule ARGS "@rx (?=a)" "id:7,phase:2"`}, []string{"rule 7: @rx: "}},
		{"transformation", []string{`SecRule ARGS "@rx a" "id:7,phase:2,t:none,t:sha1"`}, []string{`rule 7: transformation "sha1" is not supported`}},
		{"variable", []string{`SecRule REQUEST_COOKIES "@rx a" "id:7,phase:2"`}, []string{"rule 7: variable REQUEST_COOKIES is not supported"}},
		{"regex selector", []string{`SecRule ARGS:/^a/ "@rx a" "id:7,phase:2"`}, []string{"regular expression selectors are not supported"}},
		{"tx without name", []string{`SecRule TX "@rx a" "id:7,phase:2"`}, []string{"TX without a variable name"}},
		{"phase", []string{`SecRule ARGS "@rx a" "id:7,phase:4"`}, []string{"rule 7: phase 4 is not supported"}},
		{"marker", []string{`SecAction "id:7,phase:1,pass,skipAfter:NOWHERE"`}, []string{"rulesa.conf:1: skipAfter names marker NOWHERE"}},
		{"macro", []string{`SecAction "id:7,phase:1,pass,setvar:'tx.a=%{REMOTE_ADDR}'"`}, []string{"macro %{REMOTE_ADDR} is not supported"}},
		{"macro in msg", []string{`SecRule ARGS "@rx a" "id:7,phase:2,msg:'%{REQUEST_HEADERS.Host}'"`}, []string{"rule 7: msg: macro %{REQUEST_HEADERS.Host} is not supported"}},
		{"macro in operator", []string{`SecRule ARGS "@eq %{ARGS.x}" "id:7,phase:2"`}, []string{"operator argument: macro %{ARGS.x} is not supported"}},
		{"setvar collection", []string{`SecAction "id:7,phase:1,pass,setvar:ip.count=+1"`}, []string{"setvar:ip.count=+1: only tx.name variables are supported"}},
		{"setvar macro name", []string{`SecAction "id:7,phase:1,pass,setvar:'tx.%{tx.a}=1'"`}, []string{"macro in the variable name"}},
		{"chained action", []string{"SecRule ARGS \"@rx a\" \"id:7,phase:2,chain\"\n    SecRule ARGS \"@rx b\" \"msg:'x'\""}, []string{"rulesa.conf:2: rule 7: action msg is not supported on a chained rule"}},
		{"default action", []string{`SecDefaultAction "phase:2,log,pass,ctl:ruleEngine=Off"`}, []string{"SecDefaultAction: action ctl is not supported"}},
		{"duplicate id in two files", []string{`SecAction "id:7,phase:1,pass"`, `SecAction "id:7,phase:1,pass"`}, []string{"rulesb.conf:1: rule id 7 is already used at", "rulesa.conf:1"}},
		// Every problem is reported, not only the first.
		{"several", []string{"SecAction \"id:7,phase:1,pass,ctl:x=y\"\nSecRule ARGS \"@within a\" \"id:8,phase:2,t:md5\""},
			[]string{"rule 7: action ctl", "rule 8: operator @within", `rule 8: transformation "md5"`}},
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
SecRule REQUEST_COOKIES "@pmFromFile x.data" "id:2,phase:2,t:sha1,chain"
    SecRule ARGS "@within a" "ctl:x=y"
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

func TestVariablesNotProvided(t *testing.T) {
	rs := loadRules(t, `
SecComponentSignature "TEST/1"
SecRule ARGS|FILES|XML:/*|XML://@* "@rx a" "id:1,phase:2,log,pass"
SecRule ARGS|!XML:/* "@rx a" "id:2,phase:2,log,pass"
SecRule XML:/* "@rx a" "id:3,phase:2,log,pass"
`)
	statuses := rs.Statuses()
	if got := statuses[0].NotInspected; !reflect.DeepEqual(got, []string{"FILES", "XML"}) {
		t.Errorf("rule 1 not inspected = %v", got)
	}
	// Excluding something that is not provided loses nothing.
	if got := statuses[1].NotInspected; got != nil {
		t.Errorf("rule 2 not inspected = %v", got)
	}
	if got := rs.NotInspected(); !reflect.DeepEqual(got, []string{"FILES", "XML"}) {
		t.Errorf("rule set not inspected = %v", got)
	}
	if rs.Signature() != "TEST/1" {
		t.Errorf("signature = %q", rs.Signature())
	}
	// Rule 3 has nothing left to test; it is active but can never match.
	if got := rs.Evaluate(get("/?x=a")).MatchedIDs(); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("matched = %v", got)
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
	for _, in := range []string{"%{tx}", "%{REMOTE_ADDR}", "%{MATCHED_VAR.x}", "%{ARGS.a}"} {
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
