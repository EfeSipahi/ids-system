package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// ownRulesConfig is appConfig's configuration with the own rules of
// testdata (docs/development-plan-own-rules.md).
func ownRulesConfig(t *testing.T) string {
	t.Helper()
	path := appConfig(t, `[
		{"name": "shop", "hosts": ["shop.test"], "profile": "every-path.json"},
		{"name": "blog", "hosts": ["blog.test"], "profile": "every-path.json"}
	]`, map[string]string{"every-path.json": `{"endpoints": [{"methods": ["GET"], "path": "/*", "other_params": "allow"}]}`})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["own_rules"], err = filepath.Abs("../../testdata/own-rules/own-rules.conf"); err != nil {
		t.Fatal(err)
	}
	if data, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ids-offline runs own rules like CRS's: each for its applications, with
// its severity's score, and the start record of its records marks them.
func TestOwnRules(t *testing.T) {
	requests := write(t, "r.json", `[
		{"name": "shop admin from outside", "method": "GET", "uri": "/admin", "remote_addr": "203.0.113.5",
		 "headers": [["Host", "shop.test"], ["User-Agent", "test"], ["Accept", "*/*"]], "expect_ids": [1000]},
		{"name": "shop admin from the office", "method": "GET", "uri": "/admin", "remote_addr": "10.1.2.3",
		 "headers": [["Host", "shop.test"], ["User-Agent", "test"], ["Accept", "*/*"]], "no_expect_ids": [1000]},
		{"name": "blog admin from outside", "method": "GET", "uri": "/admin", "remote_addr": "203.0.113.5",
		 "headers": [["Host", "blog.test"], ["User-Agent", "test"], ["Accept", "*/*"]], "no_expect_ids": [1000]},
		{"name": "a scanner on the blog", "method": "GET", "uri": "/", "remote_addr": "203.0.113.5",
		 "headers": [["Host", "blog.test"], ["User-Agent", "evil-scanner"], ["Accept", "*/*"]], "expect_ids": [1001]},
		{"name": "no application's debug page", "method": "GET", "uri": "/debug", "remote_addr": "203.0.113.5",
		 "headers": [["Host", "other.test"], ["User-Agent", "test"], ["Accept", "*/*"]], "expect_ids": [1002]},
		{"name": "the shop's debug page", "method": "GET", "uri": "/debug", "remote_addr": "203.0.113.5",
		 "headers": [["Host", "shop.test"], ["User-Agent", "test"], ["Accept", "*/*"]], "no_expect_ids": [1002]}
	]`)
	records := t.TempDir()
	code, out, errOut := runTool(t, "-config", ownRulesConfig(t), "-requests", requests, "-json", "-records", records)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	var got struct {
		Requests []struct {
			Name  string `json:"name"`
			Score struct {
				Total    int  `json:"total"`
				Exceeded bool `json:"exceeded"`
			} `json:"score"`
			Expectation struct {
				Met bool `json:"met"`
			} `json:"expectation"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		score int
		alert bool
	}{{5, true}, {0, false}, {0, false}, {3, false}, {4, false}, {0, false}}
	if len(got.Requests) != len(want) {
		t.Fatalf("%d requests", len(got.Requests))
	}
	for i, r := range got.Requests {
		if !r.Expectation.Met || r.Score.Total != want[i].score || r.Score.Exceeded != want[i].alert {
			t.Errorf("%s: met %v, score %d, alert %v; want score %d, alert %v", r.Name, r.Expectation.Met, r.Score.Total, r.Score.Exceeded, want[i].score, want[i].alert)
		}
	}

	// The start record: own rules with their applications; CRS's
	// rules without either field.
	f, err := os.Open(filepath.Join(records, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20)
	if !sc.Scan() {
		t.Fatal("no start record")
	}
	var start struct {
		Type  string `json:"type"`
		Rules []map[string]any
	}
	if err := json.Unmarshal(sc.Bytes(), &start); err != nil || start.Type != "start" {
		t.Fatalf("start record: %v, %q", err, start.Type)
	}
	rules := map[float64]map[string]any{}
	for _, r := range start.Rules {
		rules[r["id"].(float64)] = r
	}
	for id, apps := range map[float64][]any{1000: {"shop"}, 1001: nil, 1002: {"none"}} {
		r := rules[id]
		gotApps, _ := r["applications"].([]any)
		if r["own"] != true || r["file"] != "own-rules.conf" || !slices.Equal(gotApps, apps) {
			t.Errorf("rule %v: %v", id, r)
		}
	}
	if r := rules[942100]; r == nil || r["own"] != nil || r["applications"] != nil {
		t.Errorf("rule 942100: %v", r)
	}
}
