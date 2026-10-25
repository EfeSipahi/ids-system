package dashboard

import (
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

func ptr[T any](v T) *T { return &v }

// appsStart is a start record with two applications: shop at level 2, with
// three exceptions, and blog at the run's level 1.
func appsStart(run string, at time.Time) record.Start {
	st := startRecord(run, at, "sha256:apps")
	st.RequireProfile = true
	st.Applications = []result.AppStartup{
		{Name: "shop", Hosts: []string{"shop.example.com"}, Profile: "shop.json", Mode: profile.ModeAlert, ParanoiaLevel: 2,
			Exceptions: []profile.ExceptionStatus{
				{Exception: profile.Exception{Setting: "arg_length", Value: ptr("400"), Reason: "long notes"}},
				{Exception: profile.Exception{Rule: 942100, Off: true, Reason: "the search takes SQL words"}},
				{Exception: profile.Exception{Rule: 930100, Skip: []string{"ARGS:file"}, Reason: "file names"},
					NoEffect: "an example of a note"},
			}},
		{Name: "blog", Hosts: []string{"blog.example.com"}, Profile: "blog.json", Mode: profile.ModeMonitor, ParanoiaLevel: 1,
			Exceptions: []profile.ExceptionStatus{}},
	}
	return st
}

// appRecord is requestRecord for an application, with profile findings of
// the given kinds.
func appRecord(id string, when time.Time, app string, level, score int, kinds []string, findings ...at) record.Request {
	rec := requestRecord(id, "run1", when, "203.0.113.9", score, findings...)
	rec.Application = &result.Application{Name: app, ParanoiaLevel: level}
	if app != profile.NoApplication {
		rec.Application.Mode = profile.ModeMonitor
		rec.Profile = &record.Profile{Findings: []profile.Finding{}, BodyChecked: true}
		for _, k := range kinds {
			rec.Profile.Findings = append(rec.Profile.Findings, profile.Finding{Kind: k, Location: "ARGS_GET:x", Message: "test"})
		}
	}
	if rec.Alert {
		rec.AlertBy = []string{result.AlertByRules}
	}
	return rec
}

// profiledRecords are one run with applications:
//
//	s1: shop, a profile alert (unknown_param), no rule
//	s2: shop, 930100 below the threshold, with a too_long finding
//	b1: blog, 942100 alert
//	n1: no application, 942100 alert
//
// and counts of 50 requests, 20 of them of no application.
func profiledRecords(t *testing.T, dir string) {
	t.Helper()
	s1 := appRecord("s1", t0.Add(-30*time.Minute), "shop", 2, 0, []string{profile.KindUnknownParam})
	s1.Alert, s1.AlertBy, s1.DecidedBy = true, []string{result.AlertByProfile}, record.DecidedByProfile
	counts := countsRecord("run1", t0.Add(-3*time.Minute), 50, 4, 3)
	counts.NoProfile = 20
	appendLines(t, filepath.Join(dir, record.CurrentFile),
		appsStart("run1", t0.Add(-time.Hour)),
		s1,
		appRecord("s2", t0.Add(-25*time.Minute), "shop", 2, 3, []string{profile.KindTooLong, profile.KindTooLong}, at{930100, "ARGS:file"}),
		appRecord("b1", t0.Add(-20*time.Minute), "blog", 1, 5, nil, at{942100, "ARGS:id"}),
		appRecord("n1", t0.Add(-10*time.Minute), profile.NoApplication, 1, 5, nil, at{942100, "ARGS:id"}),
		counts)
}

// F9: the alerts list filters by application, and its rows say which
// application and profile findings a record has.
func TestApplicationFilter(t *testing.T) {
	s, dir := newTestStore(t)
	profiledRecords(t, dir)
	refresh(t, s)
	r, _ := parseRange("all", t0)
	list := func(app string) []string {
		l := s.list(filter{Range: r, Kind: "all", App: app, Sort: "time", Page: 1})
		var got []string
		for _, row := range l.Rows {
			got = append(got, row.ID)
		}
		return got
	}
	for app, want := range map[string][]string{"": {"n1", "b1", "s2", "s1"}, "shop": {"s2", "s1"}, "blog": {"b1"}, "none": {"n1"}, "nope": nil} {
		if got := list(app); !reflect.DeepEqual(got, want) {
			t.Errorf("app %q: %v, want %v", app, got, want)
		}
	}
	l := s.list(filter{Range: r, Kind: "alerts", Sort: "time", Page: 1})
	if want := []string{"blog", "shop", "none"}; !reflect.DeepEqual(l.Applications, want) {
		t.Errorf("applications %v, want %v", l.Applications, want)
	}
	byID := map[string]row{}
	for _, row := range s.list(filter{Range: r, Kind: "all", Sort: "time", Page: 1}).Rows {
		byID[row.ID] = row
	}
	if row := byID["s1"]; row.Application != "shop" || !reflect.DeepEqual(row.ProfileKinds, []string{"unknown_param"}) || !reflect.DeepEqual(row.AlertBy, []string{"profile"}) || !row.Alert {
		t.Errorf("s1 %+v", row)
	}
	if row := byID["s2"]; !reflect.DeepEqual(row.ProfileKinds, []string{"too_long"}) || row.Alert {
		t.Errorf("s2 %+v", row)
	}

	// Records of a run without applications belong to none.
	plain, plainDir := newTestStore(t)
	sampleRecords(t, plainDir)
	refresh(t, plain)
	if l := plain.list(filter{Range: r, Kind: "all", App: "none", Sort: "time", Page: 1}); l.Total != 4 || len(l.Applications) != 0 {
		t.Errorf("without applications: %d records, applications %v", l.Total, l.Applications)
	}

	if _, err := parseFilter(map[string][]string{"app": {strings.Repeat("a", 65)}}, t0); err == nil {
		t.Error("no error for a long application name")
	}
}

func TestOverviewWithoutProfile(t *testing.T) {
	s, dir := newTestStore(t)
	profiledRecords(t, dir)
	refresh(t, s)
	r, _ := parseRange("all", t0)
	if o := s.overview(r); !o.Profiled || o.NoProfile != 20 || o.Analysed != 50 || o.Alerts != 3 {
		t.Errorf("profiled %v, no profile %d, analysed %d, alerts %d", o.Profiled, o.NoProfile, o.Analysed, o.Alerts)
	}
	plain, plainDir := newTestStore(t)
	sampleRecords(t, plainDir)
	refresh(t, plain)
	if o := plain.overview(r); o.Profiled || o.NoProfile != 0 {
		t.Errorf("without applications: profiled %v, no profile %d", o.Profiled, o.NoProfile)
	}
}

// F9, F11: the rules page gives the statuses of one application: its level
// and its exceptions, and counts only its records.
func TestRulesPerApplication(t *testing.T) {
	s, dir := newTestStore(t)
	profiledRecords(t, dir)
	refresh(t, s)
	r, _ := parseRange("all", t0)

	p, err := s.rulesPage(r, "shop")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[int]ruleRow{}
	for _, row := range p.Rules {
		rows[row.ID] = row
	}
	if p.Level != 2 || p.App != "shop" || len(p.Applications) != 2 {
		t.Errorf("level %d, app %q, applications %d", p.Level, p.App, len(p.Applications))
	}
	if r := rows[942100]; !r.Off || r.ExceptionReason != "the search takes SQL words" || r.Fired != 0 {
		t.Errorf("942100 for shop: %+v", r)
	}
	if r := rows[930100]; r.Off || !reflect.DeepEqual(r.Skips, []string{"ARGS:file"}) || r.NoEffect == "" || r.Fired != 1 {
		t.Errorf("930100 for shop: %+v", r)
	}

	p, _ = s.rulesPage(r, "blog")
	for _, row := range p.Rules {
		if row.Off || row.Skips != nil {
			t.Errorf("blog has an exception of rule %d: %+v", row.ID, row)
		}
		if row.ID == 942100 && row.Fired != 1 {
			t.Errorf("942100 fired %d times for blog, want 1", row.Fired)
		}
	}
	if p.Level != 1 {
		t.Errorf("blog's level %d", p.Level)
	}

	p, err = s.rulesPage(r, "none")
	if err != nil || p.Level != 1 {
		t.Errorf("none: level %d, error %v", p.Level, err)
	}
	if _, err := s.rulesPage(r, "nope"); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("unknown application: %v", err)
	}

	e := s.enginePage()
	if len(e.Applications) != 2 || e.Applications[0].Name != "shop" || !e.RequireProfile {
		t.Errorf("engine applications %+v, require profile %v", e.Applications, e.RequireProfile)
	}
}

func TestApplicationAPI(t *testing.T) {
	dir := t.TempDir()
	profiledRecords(t, dir)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)
	var p rulesPage
	decode(t, d.do("GET", "/api/rules?range=all&app=shop", nil, session), &p)
	if p.Level != 2 || p.App != "shop" {
		t.Errorf("rules for shop: level %d, app %q", p.Level, p.App)
	}
	if w := d.do("GET", "/api/rules?app=nope", nil, session); w.Code != http.StatusBadRequest {
		t.Errorf("unknown application: %d %s", w.Code, w.Body)
	}
	var l list
	decode(t, d.do("GET", "/api/alerts?kind=all&range=all&app=shop", nil, session), &l)
	if l.Total != 2 {
		t.Errorf("alerts of shop: %d", l.Total)
	}
}
