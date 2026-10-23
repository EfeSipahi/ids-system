package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	productConfig = "../../configs/crs-first-engine.json"
	examples      = "../../testdata/requests/path-traversal.json"
)

// runTool runs the tool. Unless the arguments name a records directory, the
// records go to a temporary one, not to the one of the configuration.
func runTool(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	if !slices.Contains(args, "-records") {
		args = append([]string{"-records", t.TempDir()}, args...)
	}
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestTextOutput(t *testing.T) {
	code, out, errOut := runTool(t, "-config", productConfig, "-requests", examples)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"Rules: OWASP_CRS/4.30.0, paranoia level 1, 456 active, 4 excluded",
		"[2] CRS 930110-2: traversal in the query string",
		"930110  CRITICAL  ARGS:arg ",
		// Six matches of 5 points: 930100 and 930110 twice, 930120 and
		// 932160 once. Coraza gives the same total.
		"Inbound Anomaly Score Exceeded (Total Score: 30)",
		"score 30, threshold 5: ALERT (rule layer only)",
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
	if strings.Contains(out, "NOT MET") || strings.Contains(out, "excluded 901350") {
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
		args := append([]string{"-config", productConfig, "-requests", examples}, format...)
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

	_, out, _ := runTool(t, "-config", productConfig, "-requests", examples, "-show-values")
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
	code, out, _ := runTool(t, "-config", productConfig, "-requests", examples, "-json")
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
	if doc.Startup.Ruleset != "OWASP_CRS/4.30.0" || doc.Startup.ActiveRules != 456 || len(doc.Startup.ExcludedRules) != 4 || doc.Startup.ExcludedRules[3].ID != 901450 {
		t.Errorf("startup = %+v", doc.Startup)
	}
	if len(doc.Requests) != 6 {
		t.Fatalf("%d requests", len(doc.Requests))
	}
	r := doc.Requests[2]
	if r.Index != 3 || r.Method != "POST" || r.Analysis.Body != "inspected" || !r.Analysis.Complete ||
		len(r.Findings) != 5 || r.Findings[0].RuleID != 930100 || r.Findings[0].Location != "ARGS:arg" ||
		r.Findings[2].RuleID != 930120 || r.Findings[3].RuleID != 932160 || r.Findings[4].RuleID != 949110 || r.Findings[4].Action != "deny" ||
		r.Score.Total != 20 || !r.Score.Exceeded || r.Score.Categories["lfi"] != 15 || r.Score.Categories["rce"] != 5 || !r.Expectation.Met {
		t.Errorf("request 3 = %+v", r)
	}
	if n := doc.Requests[4]; len(n.Findings) != 0 || n.Score.Total != 0 || n.Score.Exceeded {
		t.Errorf("request 5 = %+v", n)
	}
}

func TestStartupOnly(t *testing.T) {
	code, out, _ := runTool(t, "-config", productConfig)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"Rules: OWASP_CRS/4.30.0, paranoia level 1, 456 active, 4 excluded",
		"excluded 901350 (REQUEST-901-INITIALIZATION.conf:387): Left out on purpose",
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
	code, out, _ := runTool(t, "-config", productConfig, "-requests", requests)
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

// An expectation can also be a pattern for the log text of a match.
func TestLogExpectations(t *testing.T) {
	requests := write(t, "r.json", `[
		{"name": "finds it", "method": "GET", "uri": "/?q=../../x", "expect_log": "\\[id \"930110\"\\].*found within ARGS:q"},
		{"name": "does not find it", "method": "GET", "uri": "/?q=kitap", "expect_log": "found within ARGS:q"},
		{"name": "finds what it must not", "method": "GET", "uri": "/?q=../../x", "no_expect_log": "Path Traversal"}
	]`)
	code, out, _ := runTool(t, "-config", productConfig, "-requests", requests)
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	for _, want := range []string{
		`expectation: NOT MET, no log line has "found within ARGS:q"`,
		`expectation: NOT MET, a log line has "Path Traversal"`,
		"3 requests, 2 with an expectation that was not met",
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
	code, out, _ := runTool(t, "-config", productConfig, "-requests", requests)
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

// The summary over the converted CRS tests of the finished rule files, with
// the configuration the tests are written for: paranoia level 4 and the CRS
// test setup rule. The numbers of tests per rule file were counted
// independently from the CRS files. Every rule is active and every test
// must pass.
func TestSummaryOfCRSTests(t *testing.T) {
	code, out, _ := runTool(t, "-config", "../../testdata/crs-tests.json", "-requests", "../../testdata/requests/crs", "-summary", "-json")
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
	var doc struct {
		Startup struct {
			ParanoiaLevel int `json:"paranoia_level"`
		} `json:"startup"`
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
	if doc.Startup.ParanoiaLevel != 4 {
		t.Errorf("paranoia level = %d, want 4", doc.Startup.ParanoiaLevel)
	}
	if doc.Requests != nil {
		t.Error("the summary also lists the requests")
	}
	if len(doc.Summary) != 290 {
		t.Fatalf("%d files, want 290", len(doc.Summary))
	}
	tests := map[string]int{}
	for _, g := range doc.Summary {
		tests[g.Source[:3]] += g.Tests
		// File 944000 is named after no rule; its one test is about a
		// body of type text/plain.
		active := g.RuleStatus == "active" || g.Source == "944000"
		if !active || g.Passed != g.Tests || g.Failed != 0 || g.NotInspected != 0 {
			t.Errorf("rule %s: %+v", g.Source, g)
		}
	}
	want := map[string]int{"901": 18, "911": 8, "913": 9, "920": 407, "921": 116, "922": 47, "930": 83, "931": 42, "932": 1089, "933": 442, "934": 287, "941": 263, "942": 1033, "943": 47, "944": 1176, "949": 5}
	if !reflect.DeepEqual(tests, want) {
		t.Errorf("tests per rule file = %v, want %v", tests, want)
	}
	if first := doc.Summary[0]; first.Source != "901360" || first.Tests != 5 {
		t.Errorf("first row = %+v", first)
	}
}

// At the default level 1 the rules of higher levels are switched off, so
// their tests fail and the tool says so with exit code 1. An unsupported
// level stops the tool before any request is read.
func TestParanoiaLevelFlag(t *testing.T) {
	code, out, _ := runTool(t, "-config", productConfig, "-requests", "../../testdata/requests/crs/942200.json", "-summary")
	if code != 1 || !strings.Contains(out, "paranoia level 1") {
		t.Errorf("level 1: exit %d, output:\n%s", code, out)
	}
	code, out, _ = runTool(t, "-config", productConfig, "-requests", "../../testdata/requests/crs/942200.json", "-summary", "-paranoia-level", "2")
	if code != 0 || !strings.Contains(out, "paranoia level 2") {
		t.Errorf("level 2: exit %d, output:\n%s", code, out)
	}
	for _, level := range []string{"5", "-1"} {
		code, _, errOut := runTool(t, "-config", productConfig, "-paranoia-level", level)
		if code != 2 || !strings.Contains(errOut, "paranoia level "+level+" is not supported") {
			t.Errorf("level %s: exit %d, error output: %s", level, code, errOut)
		}
	}
}

func TestSummaryText(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"b-attacks.json": `[{"method": "GET", "uri": "/?q=../../x", "headers": [["Host", "shop.test"]], "expect_ids": [930110]}, {"method": "GET", "uri": "/?q=kitap", "headers": [["Host", "shop.test"]], "expect_ids": [930110]}]`,
		"a-normal.json":  `[{"method": "GET", "uri": "/", "headers": [["Host", "shop.test"]]}]`,
		"901320.json":    `[{"method": "POST", "uri": "/", "headers": [["Host", "shop.test"], ["Content-Type", "text/plain"], ["Content-Length", "1"]], "body": "x", "expect_ids": [901320]}]`,
		"notes.txt":      `not a request file`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := runTool(t, "-config", productConfig, "-requests", dir, "-summary")
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
		// text/plain is not an allowed content type in CRS, so rule
		// 920420 flags this one.
		"901320 excluded 1 1 0 0 1",
		"a-normal - 1 0 1 0 0",
		"b-attacks - 2 1 1 1 0",
		"total 4 2 2 1 1",
	}
	if strings.Join(rows, "|") != strings.Join(want, "|") {
		t.Errorf("rows = %q\nwant   %q\n%s", rows, want, out)
	}

	// Without -summary the same directory gives every request.
	_, out, _ = runTool(t, "-config", productConfig, "-requests", dir)
	if !strings.Contains(out, "4 requests, 2 with an expectation that was not met") {
		t.Errorf("output:\n%s", out)
	}

	if code, _, errOut := runTool(t, "-config", productConfig, "-requests", t.TempDir()); code != 2 || !strings.Contains(errOut, "no .json files") {
		t.Errorf("empty directory: exit %d, stderr %q", code, errOut)
	}
}

func TestLoadFailures(t *testing.T) {
	rules := write(t, "bad.conf", `SecRule ARGS "@rbl zen.example" "id:7,phase:2"`)
	badRules := write(t, "c.json", `{"files": ["`+rules+`"]}`)

	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"missing config", []string{"-config", "no-such-file.json"}, "no-such-file.json"},
		{"unsupported rule", []string{"-config", badRules}, "rule 7: operator @rbl is not supported"},
		{"missing requests", []string{"-config", productConfig, "-requests", "no-such-file.json"}, "no-such-file.json"},
		{"bad requests", []string{"-config", productConfig, "-requests", write(t, "r.json", `[{"uri": "/"}]`)}, "method is missing"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"stray argument", []string{"-config", productConfig, "extra"}, `unexpected argument "extra"`},
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

// R1: with a records directory, the requests with a finding or an
// incomplete analysis are written there, after a start record and before
// the counts. The text and JSON output say how many.
func TestRecordsAreWritten(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := runTool(t, "-records", dir, "-config", productConfig, "-requests", examples)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	var alerts int
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		var rec struct {
			Type      string `json:"type"`
			Alert     bool   `json:"alert"`
			DecidedBy string `json:"decided_by"`
			Engine    struct {
				CRS    string `json:"crs"`
				Config string `json:"config"`
			} `json:"engine"`
			Analysed int `json:"analysed"`
			Recorded int `json:"recorded"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		types = append(types, rec.Type)
		switch rec.Type {
		case "request":
			if rec.Alert {
				alerts++
			}
			if rec.DecidedBy != "rule layer only" || rec.Engine.CRS != "OWASP_CRS/4.30.0" || !strings.HasPrefix(rec.Engine.Config, "sha256:") {
				t.Errorf("record = %s", line)
			}
		case "counts":
			if rec.Analysed != 6 || rec.Recorded != 4 {
				t.Errorf("counts = %s", line)
			}
		}
	}
	// The example file holds four attacks, each with an expected match,
	// and two normal requests, which get no record.
	if want := []string{"start", "request", "request", "request", "request", "counts"}; !reflect.DeepEqual(types, want) {
		t.Errorf("types = %v, want %v", types, want)
	}
	// All four reach the threshold; the text output shows their scores.
	if alerts != 4 {
		t.Errorf("%d alerts, want 4", alerts)
	}
	if !strings.Contains(out, "Records: 4 of 6 requests written to "+dir+" (run ") {
		t.Errorf("output:\n%s", out)
	}

	// Without -requests nothing is written.
	empty := t.TempDir()
	if code, _, _ := runTool(t, "-records", empty, "-config", productConfig); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("startup report wrote %d files", len(entries))
	}
}
