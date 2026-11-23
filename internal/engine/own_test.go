package engine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// The tests of own rules (docs/development-plan-own-rules.md) use two small
// files in CRS's places: a setup file with CRS's scores, and a scoring
// file named like CRS's REQUEST-949, which adds up level 1's points.
const ownSetupConf = `SecDefaultAction "phase:1,log,pass"
SecDefaultAction "phase:2,log,pass"
SecAction "id:900990,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5,setvar:tx.error_anomaly_score=4,setvar:tx.warning_anomaly_score=3,setvar:tx.notice_anomaly_score=2,setvar:tx.inbound_anomaly_score_pl1=0,setvar:tx.blocking_inbound_anomaly_score=0"
`

const ownScoringConf = `SecAction "id:949990,phase:2,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'"
`

// ownConfig writes the setup and scoring files and the own rules, and
// returns the configuration that loads them.
func ownConfig(t *testing.T, own string) Config {
	t.Helper()
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return Config{
		Files:    []string{write("setup.conf", ownSetupConf), write("REQUEST-949-SCORING.conf", ownScoringConf)},
		OwnRules: write("own.conf", own),
	}
}

func fromAddr(target, addr string, headers ...httpmodel.Header) *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{Method: "GET", Target: target, Version: "HTTP/1.1", Headers: headers, RemoteAddr: addr})
}

// The example file of testdata: each rule adds its severity's score, once
// every condition of its chain matches, in phase 1 and in phase 2, and
// the scoring file after the own rules adds it up.
func TestOwnRulesAddTheirScore(t *testing.T) {
	text, err := os.ReadFile("../../testdata/own-rules/own-rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Load(ownConfig(t, string(text)))
	if err != nil {
		t.Fatal(err)
	}
	scanner := httpmodel.Header{Name: "User-Agent", Value: "Evil-Scanner/2.0"}
	for _, c := range []struct {
		name  string
		req   *httpmodel.Request
		rules []int
		score int
	}{
		{"admin from outside", fromAddr("/admin/users", "203.0.113.5"), []int{1000}, 5},
		{"admin from the office", fromAddr("/admin/users", "10.1.2.3"), nil, 0},
		{"another page", fromAddr("/shop", "203.0.113.5"), nil, 0},
		{"a scanner", fromAddr("/", "203.0.113.5", scanner), []int{1001}, 3},
		{"the debug page, phase 2", fromAddr("/debug", "203.0.113.5"), []int{1002}, 4},
		{"all three", fromAddr("/admin", "203.0.113.5", scanner), []int{1000, 1001}, 8},
	} {
		res := rs.Evaluate(c.req)
		if got := res.MatchedIDs(); !slices.Equal(got, c.rules) {
			t.Errorf("%s: rules %v, want %v", c.name, got, c.rules)
		}
		if got := res.Score("blocking_inbound_anomaly_score"); got != c.score {
			t.Errorf("%s: score %d, want %d", c.name, got, c.score)
		}
	}
}

// Every severity adds its own score, as CRS's rules do.
func TestOwnRuleScoreBySeverity(t *testing.T) {
	for severity, score := range map[string]int{"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2} {
		rule := `SecRule REQUEST_FILENAME "@streq /x" "id:1000,phase:1,block,msg:'x',severity:'` + severity + `',setvar:'` + OwnScore(severity) + `'"`
		rs, err := Load(ownConfig(t, rule))
		if err != nil {
			t.Fatalf("%s: %v", severity, err)
		}
		if got := rs.Evaluate(get("/x")).Score("blocking_inbound_anomaly_score"); got != score {
			t.Errorf("%s: score %d, want %d", severity, got, score)
		}
	}
}

// The rule list marks own rules and the applications they are for.
func TestOwnRuleStatuses(t *testing.T) {
	text, err := os.ReadFile("../../testdata/own-rules/own-rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Load(ownConfig(t, string(text)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]RuleStatus{}
	for _, st := range rs.Statuses() {
		got[st.ID] = st
	}
	if st := got[900990]; st.Own || st.Applications != nil {
		t.Errorf("setup rule: %+v", st)
	}
	for id, apps := range map[int][]string{1000: {"shop"}, 1001: nil, 1002: {"none"}} {
		st := got[id]
		if !st.Own || !st.Active || !slices.Equal(st.Applications, apps) || st.ParanoiaLevel != 1 || filepath.Base(st.Pos.File) != "own.conf" {
			t.Errorf("rule %d: %+v", id, st)
		}
	}
	if got[1002].Phase != 2 || got[1000].Msg != "Admin pages reached from outside the office" {
		t.Errorf("phase %d, msg %q", got[1002].Phase, got[1000].Msg)
	}
}

// What an own rule may not do is refused with its reason, the file and the
// line, and nothing of the file is loaded (N3, N4, N6).
func TestOwnRulesCheck(t *testing.T) {
	const score = `setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'`
	rule := func(actions string) string {
		return `SecRule REQUEST_FILENAME "@streq /x" "id:1000,phase:1,block,msg:'x',severity:'CRITICAL',` + actions + `"`
	}
	for _, c := range []struct {
		name, own, want string
	}{
		{"ctl", rule("ctl:ruleRemoveById=942100," + score), "ctl is not allowed in own rules"},
		{"the threshold", rule("setvar:tx.inbound_anomaly_score_threshold=1000"), "an own rule only adds its severity's score"},
		{"skipAfter", rule("skipAfter:END,"+score) + "\nSecMarker END", "skipAfter is not allowed in own rules"},
		{"pmFromFile", `SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners.data" "id:1000,phase:1,block,msg:'x',severity:'CRITICAL',` + score + `"`, "@pmFromFile is not allowed in own rules"},
		{"a low id", strings.Replace(rule(score), "id:1000", "id:999", 1), "own rules use ids 1000 to 99999"},
		{"a high id", strings.Replace(rule(score), "id:1000", "id:100000", 1), "own rules use ids 1000 to 99999"},
		{"no msg", strings.Replace(rule(score), "msg:'x',", "", 1), "has no msg"},
		{"no severity", strings.Replace(rule(score), "severity:'CRITICAL',", "", 1), "has no severity"},
		{"another severity", strings.Replace(rule(score), "CRITICAL", "INFO", 1), "severity INFO"},
		{"the wrong score", strings.Replace(rule(score), "CRITICAL", "WARNING", 1), "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"},
		{"no score", `SecRule REQUEST_FILENAME "@streq /x" "id:1000,phase:1,block,msg:'x',severity:'CRITICAL'"`, "adds no score"},
		{"two scores", rule(score + "," + score), "adds its score 2 times"},
		{"the score not last", rule(score+",chain") + "\nSecRule REMOTE_ADDR \"@ipMatch 192.0.2.1\" \"t:none\"", "setvar belongs on the last rule of the chain"},
		{"SecAction", `SecAction "id:1000,phase:1,pass,nolog"`, "SecAction is not allowed in own rules"},
		{"SecDefaultAction", `SecDefaultAction "phase:1,log,deny"` + "\n" + rule(score), "SecDefaultAction is not allowed in own rules"},
		{"another level", rule("tag:'paranoia-level/2'," + score), "own rules run at every level"},
		{"a later phase", strings.Replace(rule(score), "phase:1", "phase:3", 1), "phase 3"},
		{"nolog", rule("nolog," + score), "action nolog is not allowed in own rules"},
		{"an application's name", rule("tag:'application/my shop'," + score), "tag application/my shop"},
	} {
		_, err := Load(ownConfig(t, c.own))
		if err == nil {
			t.Errorf("%s: loaded", c.name)
			continue
		}
		if msg := err.Error(); !strings.Contains(msg, c.want) || !strings.Contains(msg, "own.conf:") {
			t.Errorf("%s: %v\nwant %q with the file and line", c.name, err, c.want)
		}
	}
}

// A rule that passes the check is still compiled as every rule is: what
// the engine can't run is an error too.
func TestOwnRulesAreCompiled(t *testing.T) {
	own := `SecRule REQUEST_FILENAME "@rx (?<=a)b" "id:1000,phase:1,block,msg:'x',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	if _, err := Load(ownConfig(t, own)); err == nil || !strings.Contains(err.Error(), "rule 1000") {
		t.Errorf("a look-behind: %v", err)
	}
}

// Own rules load before the scoring file, so there must be one; and the
// file is named only as own_rules.
func TestOwnRulesPlace(t *testing.T) {
	cfg := ownConfig(t, "")
	cfg.Files = cfg.Files[:1]
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "REQUEST-949") {
		t.Errorf("without a scoring file: %v", err)
	}
	cfg = ownConfig(t, "")
	cfg.Files = append(cfg.Files, cfg.OwnRules)
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "also in files") {
		t.Errorf("also in files: %v", err)
	}
	cfg = ownConfig(t, "# no rules yet\n")
	if _, err := Load(cfg); err != nil {
		t.Errorf("an empty file: %v", err)
	}
}

// ReadFile gives the own rules when a caller checks them before writing
// them; the file need not be on disk.
func TestOwnRulesReadFile(t *testing.T) {
	cfg := ownConfig(t, "")
	path := filepath.Join(filepath.Dir(cfg.OwnRules), "not-written.conf")
	cfg.OwnRules = path
	cfg.ReadFile = func(name string) ([]byte, error) {
		if name != path {
			t.Errorf("read %s", name)
		}
		return []byte(`SecRule REQUEST_FILENAME "@streq /x" "id:1000,phase:1,block,msg:'x',severity:'NOTICE',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}'"`), nil
	}
	rs, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.Evaluate(get("/x")).Score("blocking_inbound_anomaly_score"); got != 2 {
		t.Errorf("score %d", got)
	}
	cfg.ReadFile = nil
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "own_rules") {
		t.Errorf("from disk: %v", err)
	}
}

// ReadOwnRules gives each rule once, chains included, with what the
// dashboard shows.
func TestReadOwnRules(t *testing.T) {
	got, err := ReadOwnRules(Config{OwnRules: "../../testdata/own-rules/own-rules.conf"})
	if err != nil {
		t.Fatal(err)
	}
	want := []OwnRule{
		{ID: 1000, Line: 9, Msg: "Admin pages reached from outside the office", Severity: "CRITICAL", Applications: []string{"shop"}},
		{ID: 1001, Severity: "WARNING"},
		{ID: 1002, Severity: "ERROR", Applications: []string{"none"}},
	}
	if len(got) != len(want) {
		t.Fatalf("%d rules: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.ID != w.ID || g.Severity != w.Severity || !slices.Equal(g.Applications, w.Applications) || w.Line != 0 && g.Line != w.Line || w.Msg != "" && g.Msg != w.Msg {
			t.Errorf("rule %d: %+v", w.ID, g)
		}
	}
	if rules, err := ReadOwnRules(Config{}); rules != nil || err != nil {
		t.Errorf("without own_rules: %v, %v", rules, err)
	}
}
