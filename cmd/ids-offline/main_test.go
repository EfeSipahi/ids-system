package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
		"Rules: OWASP_CRS/4.30.0, 65 active, 11 excluded",
		"Variables named by rules but not provided: FILES, XML",
		"[2] CRS 930110-2: traversal in the query string",
		"930110  CRITICAL  ARGS:arg ",
		"Inbound Anomaly Score Exceeded (Total Score: 20)",
		"score 20, threshold 5: THRESHOLD EXCEEDED",
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
	if strings.Contains(out, "NOT MET") || strings.Contains(out, "excluded 930120") {
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
	if doc.Startup.Ruleset != "OWASP_CRS/4.30.0" || doc.Startup.ActiveRules != 65 || len(doc.Startup.ExcludedRules) != 11 || doc.Startup.ExcludedRules[7].ID != 930120 {
		t.Errorf("startup = %+v", doc.Startup)
	}
	if len(doc.Requests) != 6 {
		t.Fatalf("%d requests", len(doc.Requests))
	}
	r := doc.Requests[2]
	if r.Index != 3 || r.Method != "POST" || r.Analysis.Body != "inspected" || !r.Analysis.Complete ||
		len(r.Findings) != 3 || r.Findings[0].RuleID != 930100 || r.Findings[0].Location != "ARGS:arg" ||
		r.Findings[2].RuleID != 949110 || r.Findings[2].Action != "deny" ||
		r.Score.Total != 10 || !r.Score.Exceeded || r.Score.Categories["lfi"] != 10 || !r.Expectation.Met {
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
		"Rules: OWASP_CRS/4.30.0, 65 active, 11 excluded",
		"excluded 930120 (REQUEST-930-APPLICATION-ATTACK-LFI.conf:104): Outside the first engine: needs @pmFromFile",
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
	code, out, _ := runTool(t, "-config", config, "-requests", "../../testdata/requests/crs-930-regression-not-yet-supported.json")
	// These examples expect a match the engine cannot produce yet.
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if strings.Count(out, "ANALYSIS INCOMPLETE") != 4 || !strings.Contains(out, `body not inspected (content type "application/xml" is not parsed)`) {
		t.Errorf("output:\n%s", out)
	}
}

func TestLoadFailures(t *testing.T) {
	rules := write(t, "bad.conf", `SecRule ARGS "@pmFromFile x.data" "id:7,phase:2"`)
	badRules := write(t, "c.json", `{"files": ["`+rules+`"]}`)

	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"missing config", []string{"-config", "no-such-file.json"}, "no-such-file.json"},
		{"unsupported rule", []string{"-config", badRules}, "rule 7: operator @pmFromFile is not supported"},
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
