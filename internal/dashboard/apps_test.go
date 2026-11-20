package dashboard

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// W1: the overview of one application leaves out what is not kept per
// application.
func TestOverviewOfOneApplication(t *testing.T) {
	dir := t.TempDir()
	profiledRecords(t, dir)
	s := newStore(dir)
	refresh(t, s)
	r := timeRange{Name: "1h", From: t0.Add(-time.Hour), To: t0}
	all := s.overviewFor(r, "")
	if all.Recorded != 4 || all.Analysed != 50 || all.Application != "" {
		t.Errorf("every application: %+v", all)
	}
	shop := s.overviewFor(r, "shop")
	if shop.Recorded != 2 || shop.Alerts != 1 || shop.Analysed != 0 || shop.Application != "shop" {
		t.Errorf("shop: %d records, %d alerts, %d analysed", shop.Recorded, shop.Alerts, shop.Analysed)
	}
	for _, b := range shop.Series {
		if b.Analysed != 0 {
			t.Errorf("a bar of shop counts %d analysed", b.Analysed)
		}
	}
	none := s.overviewFor(r, profile.NoApplication)
	if none.Recorded != 1 || none.Alerts != 1 {
		t.Errorf("no application: %+v", none)
	}
}

// W1–W3: the Applications list, with the requests of no application and
// an application that only old records have.
func TestApplicationsList(t *testing.T) {
	dir := t.TempDir()
	profiledRecords(t, dir)
	old := appRecord("o1", t0.Add(-5*time.Minute), "gone", 1, 5, nil, at{942100, "ARGS:q"})
	appendLines(t, filepath.Join(dir, "records.jsonl"), old)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)
	d.srv.marks.add([]markLine{{Record: "b1", Verdict: verdictFalsePositive, User: "admin", Time: t0, Alert: markAlert{Time: t0.Add(-20 * time.Minute), Application: "blog", Rules: []int{942100}}}})

	var p appsPage
	decode(t, d.do("GET", "/api/applications?range=1h", nil, session), &p)
	names := []string{}
	for _, a := range p.Applications {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "shop,blog,gone" || !p.RequireProfile || p.DefaultLevel != 1 {
		t.Fatalf("applications %v, %+v", names, p)
	}
	shop, blog, gone := p.Applications[0], p.Applications[1], p.Applications[2]
	if !shop.Running || shop.Records != 2 || shop.Alerts != 1 || shop.NotReviewed != 1 || shop.ParanoiaLevel != 2 || len(shop.Exceptions) != 3 {
		t.Errorf("shop: %+v", shop)
	}
	if blog.Alerts != 1 || blog.NotReviewed != 0 || blog.FalsePositives != 1 {
		t.Errorf("blog: %+v", blog)
	}
	if gone.Running || gone.Alerts != 1 || gone.Exceptions == nil {
		t.Errorf("gone: %+v", gone)
	}
	if p.None.Records != 1 || p.None.Alerts != 1 || p.None.ParanoiaLevel != 1 {
		t.Errorf("no application: %+v", p.None)
	}

	var a appPage
	decode(t, d.do("GET", "/api/applications/shop?range=1h", nil, session), &a)
	if a.Application.Name != "shop" || len(a.Paths) != 2 || a.Paths[0].Count != 1 || a.DefaultLevel != 1 {
		t.Errorf("shop's page: %+v", a)
	}
	if w := d.do("GET", "/api/applications/nothing", nil, session); w.Code != http.StatusNotFound {
		t.Errorf("unknown application: %d", w.Code)
	}
	for _, path := range []string{"/applications", "/applications/shop", "/applications/shop/rules"} {
		w := d.do("GET", path, nil, session)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	tab := d.do("GET", "/applications/shop/rules", nil, session).Body.String()
	if !strings.Contains(tab, `data-app="shop"`) || !strings.Contains(tab, `data-tab="rules"`) || strings.Contains(tab, `id="app-field"`) || !strings.Contains(tab, "Off for shop") {
		t.Errorf("the Rules tab of shop: %s", tab)
	}
	// A name no application could have is a page that does not exist.
	for _, path := range []string{"/applications/a%20b", "/applications/" + strings.Repeat("x", 65)} {
		if w := d.do("GET", path, nil, session); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}

// W6: a rule's page has its status for every application, what it found,
// and its text from the rule file.
func TestRulePage(t *testing.T) {
	dir := t.TempDir()
	profiledRecords(t, dir)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)

	// A configuration whose rule file holds 942100 at line 20, as the
	// start record says, chained to a second rule.
	conf := t.TempDir()
	lines := make([]string, 19)
	for i := range lines {
		lines[i] = "# comment"
	}
	lines = append(lines,
		`SecRule ARGS "@detectSQLi" \`,
		`    "id:942100,\`,
		`    phase:2,\`,
		`    chain"`,
		`    SecRule ARGS "@rx x" "t:none"`,
		``, ``, ``, ``, ``,
		`SecRule ARGS "@rx y" "id:942101"`)
	os.WriteFile(filepath.Join(conf, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	os.WriteFile(filepath.Join(conf, "ids.json"), []byte(`{"files": ["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]}`), 0o600)
	d.srv.cfg.IDSConfig = filepath.Join(conf, "ids.json")

	var p rulePage
	decode(t, d.do("GET", "/api/rules/942100?range=1h", nil, session), &p)
	if p.Rule.ID != 942100 || p.Group != "SQL injection" || p.Fired != 2 || p.Alerts != 2 {
		t.Fatalf("rule: %+v", p)
	}
	want := map[string]string{"shop": "off", "blog": "runs", "none": "runs"}
	for _, st := range p.Statuses {
		if want[st.Application] != st.Status {
			t.Errorf("%s: %s, want %s", st.Application, st.Status, want[st.Application])
		}
		if st.Application == "shop" && (st.Level != 2 || st.Reason != "the search takes SQL words") {
			t.Errorf("shop: %+v", st)
		}
		if st.Application == "blog" && st.Fired != 1 {
			t.Errorf("blog: %+v", st)
		}
	}
	if len(p.Statuses) != 3 {
		t.Errorf("statuses: %+v", p.Statuses)
	}
	if len(p.Locations) != 1 || p.Locations[0].Key != "ARGS:id" || p.Locations[0].Count != 2 {
		t.Errorf("locations: %+v", p.Locations)
	}
	wantText := strings.Join(lines[19:24], "\n")
	if p.Text != wantText {
		t.Errorf("text:\n%s\nwant:\n%s (%s)", p.Text, wantText, p.TextError)
	}

	// 930100 skips a place for shop; 942101 is above the level of blog.
	p = rulePage{}
	decode(t, d.do("GET", "/api/rules/930100?range=1h", nil, session), &p)
	if st := p.Statuses[0]; st.Status != "runs" || len(st.Skips) != 1 || st.NoEffect == "" {
		t.Errorf("930100 for shop: %+v", st)
	}
	p = rulePage{}
	decode(t, d.do("GET", "/api/rules/942101?range=1h", nil, session), &p)
	if p.Statuses[0].Status != "runs" || p.Statuses[1].Status != "above" {
		t.Errorf("942101: %+v", p.Statuses)
	}
	if p.Text != `SecRule ARGS "@rx y" "id:942101"` {
		t.Errorf("942101's text: %q", p.Text)
	}
	p = rulePage{}
	decode(t, d.do("GET", "/api/rules/901320?range=1h", nil, session), &p)
	if p.Statuses[0].Status != "excluded" || p.TextError == "" {
		t.Errorf("901320: %+v", p)
	}

	if w := d.do("GET", "/api/rules/123", nil, session); w.Code != http.StatusNotFound {
		t.Errorf("unknown rule: %d", w.Code)
	}
	for path, code := range map[string]int{"/rules/942100": 200, "/rules/0": 404, "/rules/x": 404, "/rules/0942100": 404} {
		if w := d.do("GET", path, nil, session); w.Code != code {
			t.Errorf("%s: %d, want %d", path, w.Code, code)
		}
	}
}

func TestReadRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	os.WriteFile(path, []byte("SecRule A \"@rx a\" \"id:1,pass\"\nSecRule B \"@rx b\" \"id:2,chain\"\n\n# between\n    SecRule C \"@rx c\" \"t:none\"\nSecRule D \"@rx d\" \"id:3\"\n"), 0o600)
	for line, want := range map[int]string{
		1: `SecRule A "@rx a" "id:1,pass"`,
		2: "SecRule B \"@rx b\" \"id:2,chain\"\n    SecRule C \"@rx c\" \"t:none\"",
		6: `SecRule D "@rx d" "id:3"`,
	} {
		got, err := readRule(path, line)
		if err != nil || got != want {
			t.Errorf("line %d: %q, %v", line, got, err)
		}
	}
	if _, err := readRule(path, 99); err == nil {
		t.Error("a line after the end gave no error")
	}
}

// W17: the Engine page says whether ids-live writes.
func TestEnginePageLive(t *testing.T) {
	dir := t.TempDir()
	liveRecords(t, dir, t0.Add(-time.Minute), 1)
	s := newStore(dir)
	refresh(t, s)
	p := s.enginePageAt(t0)
	if p.Live == nil || p.Live.Stale || *p.Live.Copiers != 1 {
		t.Errorf("live: %+v", p.Live)
	}
	// In the last hour: 1,228 not connected, 15 with a full queue.
	if p.NotAnalysed != 1243 || len(p.NotAnalysedBy) != 2 || p.NotAnalysedBy[0].Missed != 1228 {
		t.Errorf("not analysed: %d %+v", p.NotAnalysed, p.NotAnalysedBy)
	}
	if p := s.enginePageAt(t0.Add(time.Hour)); p.Live == nil || !p.Live.Stale {
		t.Errorf("an hour later: %+v", p.Live)
	}
}

// A replay's start record carries its first request's time; it is the
// newest run when it was replayed last.
func TestReplayIsNewestWhenReplayedLast(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	st := appsStart("replay1", t0.Add(-48*time.Hour))
	st.Input = &record.Input{Kind: record.InputReplay, Replayed: t0.Add(-time.Minute)}
	appendLines(t, filepath.Join(dir, record.CurrentFile), st)
	s := newStore(dir)
	refresh(t, s)
	if got, _ := s.latestRun(); got.Run != "replay1" {
		t.Errorf("newest run %s, want replay1", got.Run)
	}
	if p := s.enginePageAt(t0); p.Runs[0].Run != "replay1" {
		t.Errorf("runs: %+v", p.Runs)
	}
}
