package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// appConfig writes the product configuration with the given applications
// and their profiles to a temporary directory. profiles maps a file name to
// its text; the applications name their profile by that file name.
func appConfig(t *testing.T, applications string, profiles map[string]string) string {
	t.Helper()
	data, err := os.ReadFile(productConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	base, err := filepath.Abs(filepath.Dir(productConfig))
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range cfg["files"].([]any) {
		cfg["files"].([]any)[i] = filepath.Join(base, f.(string))
	}
	delete(cfg, "records")
	var apps any
	if err := json.Unmarshal([]byte(applications), &apps); err != nil {
		t.Fatal(err)
	}
	cfg["applications"] = apps

	dir := t.TempDir()
	for name, text := range profiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ids.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const testApps = `[
	{"name": "local", "hosts": ["localhost"], "profile": "local.json"},
	{"name": "pl2", "hosts": ["pl2.test"], "profile": "pl2.json"},
	{"name": "pl1", "hosts": ["pl1.test"], "profile": "pl1.json"}
]`

var testProfiles = map[string]string{
	"local.json": `{
		"mode": "alert",
		"endpoints": [
			{"method": "GET", "path": "/get", "params": {"arg": {"in": "query", "max_length": 8}}},
			{"method": "GET", "path": "/arama", "params": {"q": {"repeat": true}}}
		],
		"exceptions": [{"rule": 930120, "off": true, "reason": "a test of rule exceptions"}]
	}`,
	"pl2.json": `{"paranoia_level": 2, "endpoints": []}`,
	"pl1.json": `{"paranoia_level": 1, "endpoints": []}`,
}

// Each request gets the application of its Host header, runs with that
// application's exceptions and is checked against its profile (F3, F5,
// F6). A request of another host gets the rules only.
func TestApplicationsInOutput(t *testing.T) {
	requests := write(t, "r.json", `[
		{"name": "traversal", "method": "GET", "uri": "/get?arg=../../../etc/passwd", "headers": [["Host", "localhost"]]},
		{"name": "normal", "method": "GET", "uri": "/arama?q=kitap&q=kalem", "headers": [["Host", "LOCALHOST"]]},
		{"name": "unknown path", "method": "GET", "uri": "/yok", "headers": [["Host", "localhost"]]},
		{"name": "other host", "method": "GET", "uri": "/get?arg=../../../etc/passwd", "headers": [["Host", "other.test"]]}
	]`)
	cfg := appConfig(t, testApps, testProfiles)

	code, out, errOut := runTool(t, "-config", cfg, "-requests", requests, "-json")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	var got struct {
		Startup struct {
			ParanoiaLevel int `json:"paranoia_level"`
			Applications  []struct {
				Name          string `json:"name"`
				Profile       string `json:"profile"`
				Mode          string `json:"mode"`
				ParanoiaLevel int    `json:"paranoia_level"`
				Exceptions    []struct {
					Rule   int    `json:"rule"`
					Off    bool   `json:"off"`
					Reason string `json:"reason"`
				} `json:"exceptions"`
			} `json:"applications"`
		} `json:"startup"`
		Requests []struct {
			Name     string `json:"name"`
			Findings []struct {
				RuleID int `json:"rule_id"`
			} `json:"findings"`
			Score struct {
				Total int `json:"total"`
			} `json:"score"`
			Application *struct {
				Name          string `json:"name"`
				ParanoiaLevel int    `json:"paranoia_level"`
				Mode          string `json:"mode"`
			} `json:"application"`
			Profile *struct {
				Findings []struct {
					Kind     string `json:"kind"`
					Location string `json:"location"`
					Message  string `json:"message"`
				} `json:"findings"`
				BodyChecked bool `json:"body_checked"`
			} `json:"profile"`
			AlertBy []string `json:"alert_by"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}

	apps := got.Startup.Applications
	if len(apps) != 3 || apps[0].Name != "local" || apps[0].Profile != "local.json" || apps[0].Mode != "alert" || apps[0].ParanoiaLevel != 1 ||
		apps[1].ParanoiaLevel != 2 || apps[1].Mode != "monitor" {
		t.Errorf("startup applications %+v", apps)
	}
	if ex := apps[0].Exceptions; len(ex) != 1 || ex[0].Rule != 930120 || !ex[0].Off || ex[0].Reason == "" {
		t.Errorf("exceptions %+v", ex)
	}

	rs := got.Requests
	if len(rs) != 4 {
		t.Fatalf("%d requests", len(rs))
	}
	// TestTextOutput's request [2] is the same and scores 30, with one
	// match of 930120 (5 points). That rule is off for the application.
	ids := func(i int) []int {
		var out []int
		for _, f := range rs[i].Findings {
			out = append(out, f.RuleID)
		}
		return out
	}
	if rs[0].Score.Total != 25 {
		t.Errorf("traversal: score %d, rules %v", rs[0].Score.Total, ids(0))
	}
	for _, id := range ids(0) {
		if id == 930120 {
			t.Errorf("rule 930120 matched although it is off for the application: %v", ids(0))
		}
	}
	if a := rs[0].Application; a == nil || a.Name != "local" || a.ParanoiaLevel != 1 || a.Mode != "alert" {
		t.Errorf("traversal: application %+v", a)
	}
	if p := rs[0].Profile; p == nil || len(p.Findings) != 1 || p.Findings[0].Kind != "too_long" || p.Findings[0].Location != "ARGS_GET:arg" || !p.BodyChecked {
		t.Errorf("traversal: profile %+v", p)
	}
	if !reflect.DeepEqual(rs[0].AlertBy, []string{"rules", "profile"}) {
		t.Errorf("traversal: alert_by %v", rs[0].AlertBy)
	}

	// The Host header is matched without regard to case.
	if a, p := rs[1].Application, rs[1].Profile; a == nil || a.Name != "local" || p == nil || len(p.Findings) != 0 || rs[1].AlertBy != nil {
		t.Errorf("normal: application %+v, profile %+v, alert_by %v", a, p, rs[1].AlertBy)
	}
	if p := rs[2].Profile; p == nil || len(p.Findings) != 1 || p.Findings[0].Kind != "unknown_endpoint" || !reflect.DeepEqual(rs[2].AlertBy, []string{"profile"}) {
		t.Errorf("unknown path: profile %+v, alert_by %v", p, rs[2].AlertBy)
	}

	// Another host: the rules only, with 930120 as usual.
	if a := rs[3].Application; a == nil || a.Name != "none" || a.ParanoiaLevel != 1 || a.Mode != "" {
		t.Errorf("other host: application %+v", a)
	}
	if rs[3].Profile != nil || rs[3].Score.Total != 30 || !reflect.DeepEqual(rs[3].AlertBy, []string{"rules"}) {
		t.Errorf("other host: profile %+v, score %d, alert_by %v", rs[3].Profile, rs[3].Score.Total, rs[3].AlertBy)
	}

	// No value of a request is printed (M11).
	for _, secret := range []string{"passwd", "kitap", "kalem"} {
		if strings.Contains(out, secret) {
			t.Errorf("the output contains %q", secret)
		}
	}

	// The text gives the same.
	_, text, _ := runTool(t, "-config", cfg, "-requests", requests)
	for _, want := range []string{
		"Rules: OWASP_CRS/4.30.0, paranoia level 1 by default, 456 active, 4 excluded",
		"Applications: 3; requests of other hosts get the rules only",
		"  local: hosts localhost; profile local.json, mode alert, paranoia level 1, 1 exception",
		"  pl2: hosts pl2.test; profile pl2.json, mode monitor, paranoia level 2, 0 exceptions",
		"    application: local, paranoia level 1, profile mode alert",
		"    score 25, threshold 5: ALERT (rules)",
		"    profile: 1 finding: ALERT (profile)",
		"      too_long          ARGS_GET:arg                        longer than 8 bytes",
		"    profile: no findings",
		"      unknown_endpoint  REQUEST_FILENAME                    no endpoint of the profile fits this path",
		"    application: none, paranoia level 1\n",
		"    score 30, threshold 5: ALERT (rules)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text does not contain %q:\n%s", want, text)
		}
	}
}

// F11: an application runs at its own level. -paranoia-level changes the
// level of the configuration, not that of an application with its own.
// The CRS tests of rule 942200, a level 2 rule, fail at level 1 (see
// TestParanoiaLevelFlag) and pass at level 2.
func TestApplicationLevel(t *testing.T) {
	cfg := appConfig(t, testApps, testProfiles)
	tests := "../../testdata/requests/crs/942200.json"
	for _, c := range []struct {
		args []string
		exit int
	}{
		{[]string{"-application", "pl2"}, 0},
		{[]string{"-application", "pl1"}, 1},
		{[]string{"-application", "pl1", "-paranoia-level", "2"}, 1},
		{[]string{"-application", "local", "-paranoia-level", "2"}, 0},
		{[]string{"-application", "local"}, 1},
	} {
		args := append([]string{"-config", cfg, "-requests", tests, "-summary"}, c.args...)
		if code, out, errOut := runTool(t, args...); code != c.exit {
			t.Errorf("%v: exit %d, want %d\n%s%s", c.args, code, c.exit, out, errOut)
		}
	}
}

// -application and broken applications stop the tool with a message that
// says what to change.
func TestApplicationErrors(t *testing.T) {
	cfg := appConfig(t, testApps, testProfiles)
	protected := appConfig(t, `[{"name": "shop", "hosts": ["a"], "profile": "p.json"}]`,
		map[string]string{"p.json": `{"endpoints": [], "exceptions": [{"rule": 949052, "off": true, "reason": "too many alerts"}]}`})
	for _, c := range []struct {
		name string
		args []string
		msg  string
	}{
		{"unknown application", []string{"-config", cfg, "-application", "nope"}, "-application nope: no such application; the configuration has: local, pl2, pl1"},
		{"no applications", []string{"-config", productConfig, "-application", "shop"}, "-application shop: the configuration has no applications"},
		{"protected rule", []string{"-config", protected}, "exceptions[0]: rule 949052 cannot be excepted."},
		{"endpoints without requests", []string{"-endpoints"}, "-endpoints needs -requests"},
		{"endpoints with records", []string{"-endpoints", "-requests", examples, "-records", "x"}, "leave out -records"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := runTool(t, c.args...)
			if code != 2 || !strings.Contains(errOut, c.msg) || out != "" {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", code, out, errOut, c.msg)
			}
		})
	}
}

// F10: the CSIC shop's configuration and profile load, with the level and
// the three exceptions the user accepted on 25 October 2026. The CSIC
// records belong to ids-model, so the measurements themselves are in
// docs/development-plan-profiles.md, notes 17 and 18.
func TestCSICShopConfiguration(t *testing.T) {
	code, out, errOut := runTool(t, "-config", "../../configs/csic-shop.json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"csic-shop: hosts localhost:8080; profile csic-shop.json, mode monitor, paranoia level 2, 3 exceptions",
		`setting crs_validate_utf8_encoding = "0": `,
		`setting restricted_headers_extended = "": `,
		"rule 932350 skips ARGS_NAMES:pwd, ARGS_NAMES:id: ",
		"note: exceptions[2]: rule 932350 belongs to paranoia level 3 and does not run at level 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// F4g: -endpoints lists methods, paths and parameters, never values. The
// expected numbers were counted from the file with Python's urllib.
func TestEndpointsListing(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"-endpoints", "-requests", examples, "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	var got struct {
		Requests  int `json:"requests"`
		Endpoints []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Count  int    `json:"count"`
			Params []struct {
				Name       string `json:"name"`
				In         string `json:"in"`
				Count      int    `json:"count"`
				Repeated   bool   `json:"repeated"`
				MaxLength  int    `json:"max_length"`
				AllInteger bool   `json:"all_integer"`
			} `json:"params"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, ep := range got.Endpoints {
		line := ep.Method + " " + ep.Path + " " + strconv.Itoa(ep.Count)
		for _, p := range ep.Params {
			line += " | " + p.In + " " + p.Name + " " + strconv.Itoa(p.Count) + " " + strconv.Itoa(p.MaxLength)
			if p.Repeated {
				line += " repeated"
			}
			if p.AllInteger {
				line += " integer"
			}
		}
		lines = append(lines, line)
	}
	want := []string{
		"GET /arama 1 | query q 1 5 repeated",
		"GET /get 3 | query arg 1 19 | query foo 1 23",
		"POST /giris 1 | body kullanici 1 3 | body parola 1 12",
		"POST /post 1 | body arg 1 19 | body foo 1 3",
	}
	if got.Requests != 6 || !reflect.DeepEqual(lines, want) {
		t.Errorf("requests %d, endpoints\n%s\nwant\n%s", got.Requests, strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	out.Reset()
	if code := run([]string{"-endpoints", "-requests", examples}, &out, &errOut); code != 0 {
		t.Fatalf("text: exit %d", code)
	}
	for _, secret := range []string{"passwd", "kitap", "efe", "gizli", "win.ini"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("the listing contains %q:\n%s", secret, out.String())
		}
	}
	if !strings.Contains(out.String(), "6 requests, 4 endpoints") {
		t.Errorf("text listing:\n%s", out.String())
	}
}

// F9: with applications, records carry the application and the profile,
// and a request with only a profile finding gets a record too. Of the six
// examples, the login form fits no endpoint of the profile local, whose
// mode is alert; the search is clean in both layers.
func TestRecordsWithApplications(t *testing.T) {
	dir := t.TempDir()
	cfg := appConfig(t, testApps, testProfiles)
	code, out, errOut := runTool(t, "-records", dir, "-config", cfg, "-requests", examples)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	data, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var byProfile, apps int
	var counts map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		switch rec["type"] {
		case "start":
			apps = len(rec["applications"].([]any))
		case "request":
			if a := rec["application"].(map[string]any); a["name"] != "local" || rec["decided_by"] != "rule and profile layers" {
				t.Errorf("record %s", line)
			}
			if reflect.DeepEqual(rec["alert_by"], []any{"profile"}) {
				byProfile++
			}
		case "counts":
			counts = rec
		}
	}
	if apps != 3 || byProfile != 1 || counts["recorded"] != 5.0 || counts["alerts"] != 5.0 || counts["no_profile"] != nil {
		t.Errorf("start applications %d, alerts by the profile only %d, counts %v", apps, byProfile, counts)
	}
	if !strings.Contains(out, "Records: 5 of 6 requests written to ") {
		t.Errorf("output:\n%s", out)
	}
}
