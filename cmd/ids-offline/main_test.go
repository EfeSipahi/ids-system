package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	config   = "../../configs/crs-first-engine.json"
	examples = "../../testdata/requests/path-traversal.json"
)

func runTool(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestTextOutput(t *testing.T) {
	code, out, errOut := runTool(t, "-config", config, "-requests", examples)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"Rules: OWASP_CRS/4.30.0, 179 active, 7 excluded",
		"Target updates for 1 rules that are not active were ignored",
		"[2] CRS 930110-2: traversal in the query string",
		"930110  CRITICAL  ARGS:arg ",
		"Inbound Anomaly Score Exceeded (Total Score: 25)",
		"score 25, threshold 5: THRESHOLD EXCEEDED",
		"[5] normal: search with a repeated parameter",
		"no findings",
		"score 0, threshold 5: below threshold",
		"expectation: met",
		"6 requests, 0 with an expectation that was not met",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q", want)
		}
	}
	if strings.Contains(out, "NOT MET") || strings.Contains(out, "excluded 901340") {
		t.Errorf("unexpected text in output:\n%s", out)
	}
}

// M11: without -show-values no content of the requests is printed, in
// either format.
func TestOutputHidesRequestContent(t *testing.T) {
	// "../" alone is not in this list: the fixed message of the rules,
	// "Path Traversal Attack (/../) or (/.../)", contains it.
	secrets := []string{"etc/passwd", "master.passwd", "win.ini", "../..", "WINDOWS", "kitap", "gizli", "/get", "/giris"}
	for _, format := range [][]string{nil, {"-json"}} {
		args := append([]string{"-config", config, "-requests", examples}, format...)
		code, out, _ := runTool(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d", format, code)
		}
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%v: output contains %q", format, secret)
			}
		}
	}

	_, out, _ := runTool(t, "-config", config, "-requests", examples, "-show-values")
	for _, want := range []string{
		"request: GET /get?arg=../../../etc/passwd, body empty",
		"value: ../../../etc/passwd",
		"data:  Matched Data: ../ found within ARGS:arg: ../../../etc/passwd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-show-values output does not contain %q", want)
		}
	}
}

func TestJSONOutput(t *testing.T) {
	code, out, _ := runTool(t, "-config", config, "-requests", examples, "-json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Startup struct {
			Ruleset       string `json:"ruleset"`
			ActiveRules   int    `json:"active_rules"`
			ExcludedRules []struct {
				ID     int    `json:"id"`
				Reason string `json:"reason"`
			} `json:"excluded_rules"`
		} `json:"startup"`
		Requests []struct {
			Index    int    `json:"index"`
			Name     string `json:"name"`
			Method   string `json:"method"`
			Analysis struct {
				Complete bool   `json:"complete"`
				Body     string `json:"body"`
			} `json:"analysis"`
			Findings []struct {
				RuleID   int    `json:"rule_id"`
				Location string `json:"location"`
				Action   string `json:"action"`
			} `json:"findings"`
			Score struct {
				Total      int            `json:"total"`
				Exceeded   bool           `json:"exceeded"`
				Categories map[string]int `json:"categories"`
			} `json:"score"`
			Expectation struct {
				Met bool `json:"met"`
			} `json:"expectation"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Startup.Ruleset != "OWASP_CRS/4.30.0" || doc.Startup.ActiveRules != 179 || len(doc.Startup.ExcludedRules) != 7 || doc.Startup.ExcludedRules[6].ID != 901450 {
		t.Errorf("startup = %+v", doc.Startup)
	}
	if len(doc.Requests) != 6 {
		t.Fatalf("%d requests", len(doc.Requests))
	}
	r := doc.Requests[2]
	if r.Index != 3 || r.Method != "POST" || r.Analysis.Body != "inspected" || !r.Analysis.Complete ||
		len(r.Findings) != 4 || r.Findings[0].RuleID != 930100 || r.Findings[0].Location != "ARGS:arg" ||
		r.Findings[2].RuleID != 930120 || r.Findings[3].RuleID != 949110 || r.Findings[3].Action != "deny" ||
		r.Score.Total != 15 || !r.Score.Exceeded || r.Score.Categories["lfi"] != 15 || !r.Expectation.Met {
		t.Errorf("request 3 = %+v", r)
	}
	if n := doc.Requests[4]; len(n.Findings) != 0 || n.Score.Total != 0 || n.Score.Exceeded {
		t.Errorf("request 5 = %+v", n)
	}
}

func TestStartupOnly(t *testing.T) {
	code, out, _ := runTool(t, "-config", config)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"Rules: OWASP_CRS/4.30.0, 179 active, 7 excluded",
		"excluded 901340 (REQUEST-901-INITIALIZATION.conf:375): Body processor control",
		"excluded 901450 (REQUEST-901-INITIALIZATION.conf:517): Sampling is not implemented",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "requests,") {
		t.Errorf("unexpected request summary:\n%s", out)
	}
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExpectationNotMet(t *testing.T) {
	requests := write(t, "r.json", `[
		{"name": "wrongly expects a match", "method": "GET", "uri": "/?q=kitap", "expect_ids": [930110]},
		{"name": "wrongly forbids a match", "method": "GET", "uri": "/?q=../../x", "no_expect_ids": [930110, 930100]},
		{"name": "fine", "method": "GET", "uri": "/?q=../../x", "expect_ids": [930110]},
		{"name": "expects nothing", "method": "GET", "uri": "/"}
	]`)
	code, out, _ := runTool(t, "-config", config, "-requests", requests)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	for _, want := range []string{
		"expectation: NOT MET, did not match [930110]",
		"expectation: NOT MET, must not match [930110 930100]",
		"4 requests, 2 with an expectation that was not met",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "expectation: met") != 1 {
		t.Errorf("want exactly one met expectation:\n%s", out)
	}
}

func TestIncompleteAnalysisIsShown(t *testing.T) {
	requests := write(t, "r.json", `[
		{"name": "a body with no parser", "method": "POST", "uri": "/", "headers": [["Content-Type", "text/plain"]], "body": "file=../../etc/passwd", "expect_ids": [930110]},
		{"name": "JSON that breaks off", "method": "POST", "uri": "/", "headers": [["Content-Type", "application/json"]], "body": "{\"file\": \"../../x\", \"more\": ", "expect_ids": [930110]},
		{"name": "complete JSON", "method": "POST", "uri": "/", "headers": [["Content-Type", "application/json"]], "body": "{\"file\": \"../../x\"}", "expect_ids": [930110]}
	]`)
	code, out, _ := runTool(t, "-config", config, "-requests", requests)
	// The first payload cannot be seen. The second is found in the part
	// that was read, and the output still says the rest was not.
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if strings.Count(out, "ANALYSIS INCOMPLETE") != 2 || strings.Count(out, "expectation: NOT MET") != 1 ||
		!strings.Contains(out, `body not inspected (content type "text/plain" is not parsed)`) ||
		!strings.Contains(out, "body partly inspected as json (the json body could not be read to its end") ||
		!strings.Contains(out, "body inspected as json\n") {
		t.Errorf("output:\n%s", out)
	}
}

// The summary over the converted CRS tests of all 51 PL1 rules in scope:
// 5 in file 930, 26 in 941 and 20 in 942, with 72 + 242 + 373 tests. The
// numbers were counted independently from the CRS files. Every rule is
// active and every test must pass.
func TestSummaryOfCRSTests(t *testing.T) {
	code, out, _ := runTool(t, "-config", config, "-requests", "../../testdata/requests/crs", "-summary", "-json")
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	var doc struct {
		Requests []json.RawMessage `json:"requests"`
		Summary  []struct {
			Source       string `json:"source"`
			RuleStatus   string `json:"rule_status"`
			Tests        int    `json:"tests"`
			Passed       int    `json:"passed"`
			Failed       int    `json:"failed"`
			NotInspected int    `json:"not_inspected"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if doc.Requests != nil {
		t.Error("the summary also lists the requests")
	}
	if len(doc.Summary) != 51 {
		t.Fatalf("%d files, want 51", len(doc.Summary))
	}
	tests := map[string]int{}
	for _, g := range doc.Summary {
		tests[g.Source[:3]] += g.Tests
		if g.RuleStatus != "active" || g.Passed != g.Tests || g.Failed != 0 || g.NotInspected != 0 {
			t.Errorf("rule %s: %+v", g.Source, g)
		}
	}
	if want := map[string]int{"930": 72, "941": 242, "942": 373}; !reflect.DeepEqual(tests, want) {
		t.Errorf("tests per rule file = %v, want %v", tests, want)
	}
	if first := doc.Summary[0]; first.Source != "930100" || first.Tests != 5 {
		t.Errorf("first row = %+v", first)
	}
}

func TestSummaryText(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"b-attacks.json": `[{"method": "GET", "uri": "/?q=../../x", "expect_ids": [930110]}, {"method": "GET", "uri": "/?q=kitap", "expect_ids": [930110]}]`,
		"a-normal.json":  `[{"method": "GET", "uri": "/"}]`,
		"901320.json":    `[{"method": "POST", "uri": "/", "headers": [["Content-Type", "text/plain"]], "body": "x", "expect_ids": [901320]}]`,
		"notes.txt":      `not a request file`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := runTool(t, "-config", config, "-requests", dir, "-summary")
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	// Files are read in name order; only *.json files count.
	lines := strings.Split(out, "\n")
	var rows []string
	for _, line := range lines {
		if f := strings.Fields(line); len(f) > 0 && (strings.HasSuffix(f[0], "901320") || strings.Contains(f[0], "-") || f[0] == "total") {
			rows = append(rows, strings.Join(f, " "))
		}
	}
	want := []string{
		"901320 excluded 1 0 0 0 1",
		"a-normal - 1 0 1 0 0",
		"b-attacks - 2 1 1 1 0",
		"total 4 1 2 1 1",
	}
	if strings.Join(rows, "|") != strings.Join(want, "|") {
		t.Errorf("rows = %q\nwant   %q\n%s", rows, want, out)
	}

	// Without -summary the same directory gives every request.
	_, out, _ = runTool(t, "-config", config, "-requests", dir)
	if !strings.Contains(out, "4 requests, 2 with an expectation that was not met") {
		t.Errorf("output:\n%s", out)
	}

	if code, _, errOut := runTool(t, "-config", config, "-requests", t.TempDir()); code != 2 || !strings.Contains(errOut, "no .json files") {
		t.Errorf("empty directory: exit %d, stderr %q", code, errOut)
	}
}

func TestLoadFailures(t *testing.T) {
	rules := write(t, "bad.conf", `SecRule ARGS "@within a b" "id:7,phase:2"`)
	badRules := write(t, "c.json", `{"files": ["`+rules+`"]}`)

	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"missing config", []string{"-config", "no-such-file.json"}, "no-such-file.json"},
		{"unsupported rule", []string{"-config", badRules}, "rule 7: operator @within is not supported"},
		{"missing requests", []string{"-config", config, "-requests", "no-such-file.json"}, "no-such-file.json"},
		{"bad requests", []string{"-config", config, "-requests", write(t, "r.json", `[{"uri": "/"}]`)}, "method is missing"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"stray argument", []string{"-config", config, "extra"}, `unexpected argument "extra"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runTool(t, tt.args...)
			if code != 2 || !strings.Contains(errOut, tt.msg) {
				t.Errorf("exit %d, stderr %q; want exit 2 and %q", code, errOut, tt.msg)
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}
		})
	}
}
