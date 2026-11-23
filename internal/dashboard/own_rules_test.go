package dashboard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// The own rules of testdata as the start record lists them: 1000 for the
// shop, 1001 for every request, 1002 for requests of no application.
var ownTestRules = []record.Rule{
	{ID: 1000, File: "own-rules.conf", Line: 9, Phase: 1, ParanoiaLevel: 1, Msg: "Admin pages reached from outside the office", Active: true, Own: true, Applications: []string{"shop"}},
	{ID: 1001, File: "own-rules.conf", Line: 23, Phase: 1, ParanoiaLevel: 1, Msg: "A scanner the office has seen before", Active: true, Own: true},
	{ID: 1002, File: "own-rules.conf", Line: 34, Phase: 2, ParanoiaLevel: 1, Msg: "The debug page, on a host of no application", Active: true, Own: true, Applications: []string{"none"}},
}

// ownFinding is a finding of an own rule, with the severity that weighs
// it in the preview.
func ownFinding(rule int, severity string) record.Finding {
	return record.Finding{RuleID: rule, Severity: severity, Location: "REQUEST_FILENAME", Message: "own", Action: "pass"}
}

// Stage 2 of docs/development-plan-own-rules.md: the Rules page and the
// page per rule show own rules, their group, which requests they are for,
// their severity and their text.
func TestOwnRulesOnTheRulePages(t *testing.T) {
	dir := t.TempDir()
	st := appsStart("run1", t0.Add(-time.Hour))
	st.Rules = append(st.Rules, ownTestRules...)
	s1 := appRecord("s1", t0.Add(-10*time.Minute), "shop", 2, 5, nil)
	s1.Findings = []record.Finding{ownFinding(1000, "CRITICAL")}
	appendLines(t, filepath.Join(dir, record.CurrentFile), st, s1)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)
	conf := t.TempDir()
	own, err := filepath.Abs("../../testdata/own-rules/own-rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(conf, "ids.json"), []byte(`{"files": [], "own_rules": "`+own+`"}`), 0o600)
	d.srv.cfg.IDSConfig = filepath.Join(conf, "ids.json")

	notFor := func(app string) map[int]bool {
		t.Helper()
		var p rulesPage
		decode(t, d.do("GET", "/api/rules?range=1h&app="+app, nil, session), &p)
		got := map[int]bool{}
		for _, r := range p.Rules {
			if r.Own && r.Group != ownGroup || !r.Own && r.Group == ownGroup {
				t.Errorf("rule %d: group %s", r.ID, r.Group)
			}
			if r.NotFor {
				got[r.ID] = true
			}
		}
		return got
	}
	for app, want := range map[string]string{"": "", "shop": "1002", "blog": "1000,1002", "none": "1000"} {
		var ids []string
		for _, r := range ownTestRules {
			if notFor(app)[r.ID] {
				ids = append(ids, fmt.Sprint(r.ID))
			}
		}
		if got := strings.Join(ids, ","); got != want {
			t.Errorf("app %q: not for %s, want %s", app, got, want)
		}
	}

	var p rulePage
	decode(t, d.do("GET", "/api/rules/1000?range=1h", nil, session), &p)
	if p.Group != ownGroup || p.Severity != "CRITICAL" || p.Fired != 1 || !strings.HasPrefix(p.Text, `SecRule REQUEST_FILENAME "@beginsWith /admin"`) || !strings.Contains(p.Text, "!@ipMatch 10.0.0.0/8") {
		t.Errorf("rule 1000: %+v", p)
	}
	want := map[string]string{"shop": "runs", "blog": "not_for", "none": "not_for"}
	for _, st := range p.Statuses {
		if st.Status != want[st.Application] {
			t.Errorf("1000 for %s: %s, want %s", st.Application, st.Status, want[st.Application])
		}
	}
	p = rulePage{}
	decode(t, d.do("GET", "/api/rules/1001?range=1h", nil, session), &p)
	if p.Severity != "WARNING" || !strings.Contains(p.Text, "@contains evil-scanner") {
		t.Errorf("rule 1001: %+v", p)
	}

	// The alerts list knows the group, so it can filter by it.
	r, _ := parseRange("all", t0)
	if l := d.srv.store.list(filter{Range: r, Kind: "all", Group: ownGroup, Sort: "time", Page: 1}); len(l.Rows) != 1 || l.Rows[0].ID != "s1" {
		t.Errorf("group %s: %+v", ownGroup, l.Rows)
	}
}

// The preview knows own rules: while the own-rules file has a rule, its
// findings count for the applications it is for; a change that removes
// it, or gives it to another application, takes them away.
func TestPreviewOfOwnRules(t *testing.T) {
	s, dir := newTestStore(t)
	st := startRecord("run1", t0.Add(-time.Hour), "sha256:own")
	st.Applications = []result.AppStartup{
		{Name: "shop", Hosts: []string{"shop.test"}, Profile: "every.json", Mode: profile.ModeMonitor, ParanoiaLevel: 1, Exceptions: []profile.ExceptionStatus{}},
		{Name: "blog", Hosts: []string{"blog.test"}, Profile: "every.json", Mode: profile.ModeMonitor, ParanoiaLevel: 1, Exceptions: []profile.ExceptionStatus{}},
	}
	st.Rules = append(st.Rules, ownTestRules...)
	s1 := appRecord("s1", t0.Add(-10*time.Minute), "shop", 1, 5, nil)
	s1.Findings = []record.Finding{ownFinding(1000, "CRITICAL"), {RuleID: 949110, Location: "TX:BLOCKING_INBOUND_ANOMALY_SCORE", Message: "score", Action: "pass"}}
	appendLines(t, filepath.Join(dir, record.CurrentFile), st, s1)
	refresh(t, s)

	conf := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(conf, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	text, err := os.ReadFile("../../testdata/own-rules/own-rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	own := write("own-rules.conf", string(text))
	write("every.json", `{"endpoints": [{"methods": ["GET"], "path": "/*", "other_params": "allow"}]}`)
	path := write("ids.json", `{"files": ["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"], "own_rules": "own-rules.conf",
		"applications": [{"name": "shop", "hosts": ["shop.test"], "profile": "every.json"}, {"name": "blog", "hosts": ["blog.test"], "profile": "every.json"}]}`)
	before, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	after := func(ownText string) *config.Product {
		t.Helper()
		raw, _ := os.ReadFile(path)
		p, err := config.Parse(path, raw, func(name string) ([]byte, error) {
			if name == own {
				return []byte(ownText), nil
			}
			return os.ReadFile(name)
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	if p := s.previewChanges(objectGlobal, before, before); p.Error != "" || p.Alerts != 1 || p.AlertsRemoved != 0 || p.RecordsRemoved != 0 {
		t.Errorf("no change: %+v", p)
	}
	change := func(old, new string) string {
		t.Helper()
		if !strings.Contains(string(text), old) {
			t.Fatalf("the example file has no %q", old)
		}
		return strings.Replace(string(text), old, new, 1)
	}
	removed := change("id:1000,", "id:1003,")
	if p := s.previewChanges(objectGlobal, before, after(removed)); p.AlertsRemoved != 1 || p.RecordsRemoved != 1 || len(p.ByRule) != 1 || p.ByRule[0].Key != "1000" {
		t.Errorf("1000 removed: %+v", p)
	}
	toBlog := change("tag:'application/shop'", "tag:'application/blog'")
	if p := s.previewChanges(objectGlobal, before, after(toBlog)); p.AlertsRemoved != 1 {
		t.Errorf("1000 for the blog: %+v", p)
	}
	noScope := change("    tag:'application/shop',\\\n", "")
	if p := s.previewChanges(objectGlobal, before, after(noScope)); p.AlertsRemoved != 0 || p.Alerts != 1 {
		t.Errorf("1000 for every request: %+v", p)
	}
	if p := s.previewChanges(objectGlobal, before, after(`SecRule ARGS "@rx (" "id:1`)); p.Error == "" {
		t.Errorf("unreadable own rules: %+v", p)
	}
}

// app.js knows the ids of own rules the engine allows.
func TestScriptKnowsOwnRuleIDs(t *testing.T) {
	data, err := webFiles.ReadFile("web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("const ownIDs = [%d, %d];", engine.OwnFirstID, engine.OwnLastID); !strings.Contains(string(data), want) {
		t.Errorf("app.js lacks %s", want)
	}
	if want := fmt.Sprintf("const ownGroup = %q;", ownGroup); !strings.Contains(string(data), want) {
		t.Errorf("app.js lacks %s", want)
	}
}
