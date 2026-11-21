package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// shopRecords are records of the shop's configuration, with the severities
// the score is made of:
//
//	r1: csic-shop, 942100 at ARGS:id: score 5, an alert, marked real attack
//	r2: csic-shop, 942100 at ARGS:id and 930100 at ARGS:file: score 10
//	r3: no application, 942100 at ARGS:q: score 5
//	r4: csic-shop, a profile finding only: not an alert in monitor mode
func shopRecords(t *testing.T, dir string) {
	t.Helper()
	st := startRecord("run1", t0.Add(-time.Hour), "sha256:shop")
	st.Applications = []result.AppStartup{{Name: "csic-shop", Hosts: []string{"localhost:8080"}, Profile: "csic-shop.json", Mode: profile.ModeMonitor, ParanoiaLevel: 2, Exceptions: []profile.ExceptionStatus{}}}
	rec := func(id, app string, score int, profiled bool, findings ...record.Finding) record.Request {
		r := requestRecord(id, "run1", t0.Add(-10*time.Minute), "203.0.113.5", score)
		r.Findings = findings
		if r.Alert {
			r.Findings = append(r.Findings, record.Finding{RuleID: 949110, Location: "TX:BLOCKING_INBOUND_ANOMALY_SCORE", Message: "score", Action: "pass"})
		}
		r.Application = &result.Application{Name: app, ParanoiaLevel: 2}
		if app != profile.NoApplication {
			r.Profile = &record.Profile{Findings: []profile.Finding{}, BodyChecked: true}
			if profiled {
				r.Profile.Findings = append(r.Profile.Findings, profile.Finding{Kind: profile.KindUnknownParam, Location: "ARGS_GET:x", Message: "test"})
			}
		}
		return r
	}
	sqli := func(at string) record.Finding {
		return record.Finding{RuleID: 942100, Severity: "CRITICAL", Location: at, Message: "sqli", Action: "pass"}
	}
	lfi := record.Finding{RuleID: 930100, Severity: "CRITICAL", Location: "ARGS:file", Message: "lfi", Action: "pass"}
	appendLines(t, filepath.Join(dir, record.CurrentFile), st,
		rec("r1", "csic-shop", 5, false, sqli("ARGS:id")),
		rec("r2", "csic-shop", 10, false, sqli("ARGS:id"), lfi),
		rec("r3", profile.NoApplication, 5, false, sqli("ARGS:q")),
		rec("r4", "csic-shop", 0, true))
}

// controlDashboard is a dashboard of the shop's records and a copy of its
// configuration, with an analyst.
func controlDashboard(t *testing.T) (*testDashboard, map[string]*http.Cookie, string) {
	t.Helper()
	dir := t.TempDir()
	shopRecords(t, dir)
	d := newDashboard(t, dir)
	path := idsCopy(t)
	d.srv.cfg.IDSConfig = path
	d.srv.control = newControl(path, d.cfg.StateDir, d.clock.now)
	d.srv.marks.add([]markLine{{Record: "r1", Verdict: verdictRealAttack, User: "admin", Time: t0, Alert: markAlert{Time: t0.Add(-10 * time.Minute), Application: "csic-shop", Rules: []int{942100}}}})
	sessions := map[string]*http.Cookie{RoleAdmin: d.login(t, "admin", d.password)}
	password, err := AddUser(d.cfg.StateDir, "ana", RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	sessions[RoleAnalyst] = d.login(t, "ana", password)
	return d, sessions, path
}

// W9, W10: an analyst proposes rule exceptions for an application; an
// admin applies, and gives the password again for every application.
func TestChangesByRole(t *testing.T) {
	d, sessions, path := controlDashboard(t)
	analyst, admin := sessions[RoleAnalyst], sessions[RoleAdmin]
	add := func(session *http.Cookie, object string, ch pendingChange) *httptest.ResponseRecorder {
		return d.postJSON("/api/changes", changeRequest{Action: "add", Object: object, Change: &ch}, session)
	}

	w := add(analyst, "app:csic-shop", pendingChange{Kind: kindRuleOff, Rule: 942100, Reason: "the search"})
	var proposed pendingChange
	decode(t, w, &proposed)
	if w.Code != 200 || !proposed.Proposal || proposed.User != "ana" {
		t.Fatalf("analyst's proposal: %d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		object string
		ch     pendingChange
	}{
		{"app:csic-shop", pendingChange{Kind: kindMode, Mode: "alert"}},
		{"global", pendingChange{Kind: kindExclude, Rule: 942100, Reason: "x"}},
	} {
		if w := add(analyst, tc.object, tc.ch); w.Code != http.StatusForbidden {
			t.Errorf("analyst %s %s: %d %s", tc.object, tc.ch.Kind, w.Code, w.Body)
		}
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "app:csic-shop", Reason: "x"}, analyst); w.Code != http.StatusForbidden {
		t.Errorf("analyst applies: %d", w.Code)
	}
	// The admin's own change is not a proposal; the analyst can't drop it.
	var own pendingChange
	decode(t, add(admin, "app:csic-shop", pendingChange{Kind: kindMode, Mode: "alert"}), &own)
	if own.Proposal {
		t.Errorf("admin's change is a proposal: %+v", own)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "drop", Object: "app:csic-shop", ID: own.ID}, analyst); w.Code != http.StatusForbidden {
		t.Errorf("analyst drops the admin's change: %d", w.Code)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "turn_down", Object: "app:csic-shop", ID: proposed.ID}, admin); w.Code != http.StatusBadRequest {
		t.Errorf("turned down without a reason: %d", w.Code)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "app:csic-shop"}, admin); w.Code != http.StatusBadRequest {
		t.Errorf("applied without a reason: %d", w.Code)
	}
	w = d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "app:csic-shop", Reason: "the shop's search"}, admin)
	var a applied
	decode(t, w, &a)
	if w.Code != 200 || a.Version.ID == "" || len(a.Version.Items) != 2 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	profileText := read(t, filepath.Join(filepath.Dir(path), "..", "profiles", "csic-shop.json"))
	if !strings.Contains(profileText, `"mode": "alert"`) || !strings.Contains(profileText, `"rule": 942100`) {
		t.Errorf("profile:\n%s", profileText)
	}

	// Every application: the password again (W10).
	if w := add(admin, "global", pendingChange{Kind: kindDefaultLevel, Level: level(2)}); w.Code != 200 {
		t.Fatalf("global change: %d %s", w.Code, w.Body)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "global", Reason: "stricter", Password: "wrong"}, admin); w.Code != http.StatusForbidden {
		t.Errorf("global apply with a wrong password: %d", w.Code)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "global", Reason: "stricter", Password: d.password}, admin); w.Code != 200 {
		t.Errorf("global apply: %d %s", w.Code, w.Body)
	}

	// Undo the shop's version: it waits as a pending change.
	if w := d.postJSON("/api/changes", changeRequest{Action: "undo", Version: a.Version.ID}, admin); w.Code != 200 {
		t.Fatalf("undo: %d %s", w.Code, w.Body)
	}
	var c changesAnswer
	decode(t, d.do("GET", "/api/changes?object=app:csic-shop", nil, admin), &c)
	if len(c.Items) != 1 || c.Items[0].Kind != kindRestore || !c.Apply || c.Password {
		t.Errorf("pending after undo: %+v", c)
	}
	var vs struct {
		Versions []versionRow `json:"versions"`
	}
	decode(t, d.do("GET", "/api/versions?object=app:csic-shop", nil, analyst), &vs)
	if len(vs.Versions) != 1 || !vs.Versions[0].Current {
		t.Errorf("versions: %+v", vs)
	}

	// The change log has each step.
	log := changes(t, d.cfg.StateDir)
	got := []string{}
	for _, c := range log {
		got = append(got, c.Action)
	}
	if want := "change_proposed,change_added,changes_applied,change_added,changes_applied,change_added"; strings.Join(got, ",") != want {
		t.Errorf("change log: %s", strings.Join(got, ","))
	}
}

// W8: the preview works out from the records what a change takes away.
func TestPreview(t *testing.T) {
	d, sessions, _ := controlDashboard(t)
	admin := sessions[RoleAdmin]
	add := func(object string, ch pendingChange) {
		t.Helper()
		if w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: object, Change: &ch}, admin); w.Code != 200 {
			t.Fatalf("%s: %d %s", ch.Kind, w.Code, w.Body)
		}
	}
	get := func(object string) preview {
		t.Helper()
		var p preview
		decode(t, d.do("GET", "/api/changes/preview?object="+object, nil, admin), &p)
		if p.Error != "" {
			t.Fatalf("preview of %s: %s", object, p.Error)
		}
		return p
	}

	// 942100 off for the shop: r1 is no longer an alert (and is marked a
	// real attack), r2 keeps 930100's 5, r3 is not the shop's.
	add("app:csic-shop", pendingChange{Kind: kindRuleOff, Rule: 942100, Reason: "x"})
	// Every list of the answer is a list, never null: the page reads
	// their length.
	if body := d.do("GET", "/api/changes/preview?object=app:csic-shop", nil, admin).Body.String(); strings.Contains(body, "null") {
		t.Errorf("a list is null: %s", body)
	}
	p := get("app:csic-shop")
	if p.Records != 3 || p.Alerts != 2 || p.AlertsRemoved != 1 || p.RealAttacks != 1 || p.RecordsRemoved != 1 || len(p.Examples) != 1 || p.Examples[0].ID != "r1" {
		t.Errorf("rule off: %+v", p)
	}
	if len(p.ByRule) != 1 || p.ByRule[0].Key != "942100" || p.ByRule[0].Count != 1 {
		t.Errorf("by rule: %+v", p.ByRule)
	}
	// And the mode to alert: r4's profile finding makes it an alert.
	add("app:csic-shop", pendingChange{Kind: kindMode, Mode: "alert"})
	if p := get("app:csic-shop"); p.AlertsAdded != 1 || p.AlertsRemoved != 1 {
		t.Errorf("with alert mode: %+v", p)
	}

	// Every application: 942100 off for all takes r1 and r3.
	add("global", pendingChange{Kind: kindExclude, Rule: 942100, Reason: "x"})
	if p := get("global"); p.Records != 4 || p.AlertsRemoved != 2 {
		t.Errorf("excluded for every application: %+v", p)
	}

	// A skip of the place it matched is the same as off for these
	// records; a skip elsewhere changes nothing.
	d2, s2, _ := controlDashboard(t)
	for target, want := range map[string]int{"ARGS:id": 1, "ARGS:other": 0, "ARGS": 1, "ARGS:/^i/": 1} {
		ch := pendingChange{Kind: kindRuleSkip, Rule: 942100, Targets: []string{target}, Reason: "x"}
		if w := d2.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &ch}, s2[RoleAdmin]); w.Code != 200 {
			t.Fatalf("%s: %d %s", target, w.Code, w.Body)
		}
		var p preview
		decode(t, d2.do("GET", "/api/changes/preview?object=app:csic-shop", nil, s2[RoleAdmin]), &p)
		if p.AlertsRemoved != want {
			t.Errorf("skip %s: %d removed, want %d", target, p.AlertsRemoved, want)
		}
		var c changesAnswer
		decode(t, d2.do("GET", "/api/changes?object=app:csic-shop", nil, s2[RoleAdmin]), &c)
		d2.postJSON("/api/changes", changeRequest{Action: "drop", Object: "app:csic-shop", ID: c.Items[0].ID}, s2[RoleAdmin])
	}

	// Switched back on, the rule's findings of the records count again:
	// the undo of the shop's change brings r1's alert back.
	d4, s4, _ := controlDashboard(t)
	off := pendingChange{Kind: kindRuleOff, Rule: 942100, Reason: "x"}
	d4.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &off}, s4[RoleAdmin])
	var a applied
	decode(t, d4.postJSON("/api/changes", changeRequest{Action: "apply", Object: "app:csic-shop", Reason: "x"}, s4[RoleAdmin]), &a)
	d4.postJSON("/api/changes", changeRequest{Action: "undo", Version: a.Version.ID}, s4[RoleAdmin])
	var back preview
	decode(t, d4.do("GET", "/api/changes/preview?object=app:csic-shop", nil, s4[RoleAdmin]), &back)
	if back.AlertsAdded != 1 || back.AlertsRemoved != 0 || back.Alerts != 1 {
		t.Errorf("undo of rule off: %+v", back)
	}

	// A higher level adds rules: the preview says it can't tell.
	d3, s3, _ := controlDashboard(t)
	ch := pendingChange{Kind: kindLevel, Level: level(3)}
	d3.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &ch}, s3[RoleAdmin])
	var up preview
	decode(t, d3.do("GET", "/api/changes/preview?object=app:csic-shop", nil, s3[RoleAdmin]), &up)
	if len(up.Untested) == 0 || !strings.Contains(up.Untested[0], "for csic-shop") || up.AlertsRemoved != 0 {
		t.Errorf("level 3: %+v", up)
	}
}

// Without ids_config the dashboard changes nothing, and says why.
func TestChangesNeedTheConfiguration(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)
	ch := pendingChange{Kind: kindMode, Mode: "alert"}
	w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:shop", Change: &ch}, session)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "ids_config") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	var c changesAnswer
	decode(t, d.do("GET", "/api/changes?object=global", nil, session), &c)
	if c.Configured || len(c.Items) != 0 {
		t.Errorf("%+v", c)
	}
	if _, err := os.Stat(filepath.Join(d.cfg.StateDir, PendingFile)); err == nil {
		t.Error("a pending file was written")
	}
}

// W3, W4: the settings pages show the settings as written, with the
// files beside the loaded rule files.
func TestSettingsAPI(t *testing.T) {
	d, sessions, _ := controlDashboard(t)
	admin := sessions[RoleAdmin]
	var p settingsPage
	decode(t, d.do("GET", "/api/settings", nil, admin), &p)
	if !p.Configured || p.Error != "" || p.File != "csic-shop.json" || p.DefaultLevel != 1 || len(p.Excluded) != 4 || p.Records == nil || p.Records.KeepFiles != 10 {
		t.Fatalf("settings: %+v", p)
	}
	on, off := 0, 0
	for _, f := range p.RuleFiles {
		if f.On {
			on++
		} else {
			off++
		}
		if f.Name == "REQUEST-949-BLOCKING-EVALUATION.conf" && !f.Needed {
			t.Error("949 is not needed")
		}
	}
	// The shop loads every request rule file of CRS 4.30.0.
	if on != 19 || off != 0 || p.RuleFiles[0].Name != "crs-setup.conf.example" {
		t.Errorf("rule files: %d on, %d off, first %s", on, off, p.RuleFiles[0].Name)
	}
	if p.OwnLevels["csic-shop"] != 2 || p.LiveDefaults.Workers != 2 {
		t.Errorf("levels %v, live defaults %+v", p.OwnLevels, p.LiveDefaults)
	}
	var a appSettings
	decode(t, d.do("GET", "/api/applications/csic-shop/settings", nil, sessions[RoleAnalyst]), &a)
	if a.Error != "" || a.Mode != "monitor" || a.Level != 2 || len(a.Hosts) != 1 || a.Profile != "../profiles/csic-shop.json" || len(a.Exceptions) != 3 || len(a.Settings) < 10 {
		t.Errorf("app settings: %+v", a)
	}
	if w := d.do("GET", "/api/applications/nothing/settings", nil, admin); w.Code != http.StatusNotFound {
		t.Errorf("unknown application: %d", w.Code)
	}
	// A rule file switched off: the others load, as written.
	var files []string
	for _, f := range p.RuleFiles {
		if f.On && f.Name != "REQUEST-944-APPLICATION-ATTACK-JAVA.conf" {
			files = append(files, f.Path)
		}
	}
	ch := pendingChange{Kind: kindFiles, Files: files}
	if w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: "global", Change: &ch}, admin); w.Code != 200 {
		t.Errorf("files: %d %s", w.Code, w.Body)
	}
}

// W15, W16: the Profile tab's suggestions from the records, the check as
// one types, and the profile written as a whole.
func TestProfileTab(t *testing.T) {
	d, sessions, path := controlDashboard(t)
	admin := sessions[RoleAdmin]
	var p profilePage
	decode(t, d.do("GET", "/api/applications/csic-shop/profile", nil, sessions[RoleAnalyst]), &p)
	profilePath := filepath.Join(filepath.Dir(path), "..", "profiles", "csic-shop.json")
	if p.Error != "" || p.Text != read(t, profilePath) || p.Endpoints != 8 || p.File != "../profiles/csic-shop.json" {
		t.Fatalf("profile: %+v", p)
	}
	// r4 (GET /r4, an unknown parameter x) is not only an alert, so it
	// comes first; r1 and r2 are alerts only.
	if len(p.Suggestions) != 3 || p.Suggestions[0].Path != "/r4" || p.Suggestions[0].Only || len(p.Suggestions[0].Params) != 1 ||
		p.Suggestions[0].Params[0] != (suggestedParam{Name: "x", In: "query", Seen: 1}) || !p.Suggestions[1].Only {
		t.Errorf("suggestions: %+v", p.Suggestions)
	}
	check := func(text string) map[string]any {
		var r map[string]any
		decode(t, d.postJSON("/api/applications/csic-shop/profile/check", map[string]string{"text": text}, admin), &r)
		return r
	}
	if r := check(p.Text); r["ok"] != true || r["endpoints"].(float64) != 8 {
		t.Errorf("check of the file: %v", r)
	}
	if r := check(`{"mode": "loud"}`); r["ok"] != false || !strings.HasPrefix(r["error"].(string), "mode") {
		t.Errorf("check of a bad mode: %v", r)
	}
	// The profile with /r4 added, as a whole.
	text := strings.Replace(p.Text, `"endpoints": [`, `"endpoints": [
    {"method": "GET", "path": "/r4", "params": {"x": {"in": "query"}}},`, 1)
	ch := pendingChange{Kind: kindProfile, Text: text}
	if w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &ch}, admin); w.Code != 200 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: "app:csic-shop", Reason: "r4 is the shop's"}, admin); w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	if read(t, profilePath) != text {
		t.Error("the profile is not the text as given")
	}
	p = profilePage{}
	decode(t, d.do("GET", "/api/applications/csic-shop/profile", nil, admin), &p)
	for _, sg := range p.Suggestions {
		if sg.Path == "/r4" {
			t.Errorf("/r4 is still suggested: %+v", sg)
		}
	}
	// An analyst can't write the profile.
	ch = pendingChange{Kind: kindProfile, Text: text}
	if w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &ch}, sessions[RoleAnalyst]); w.Code != http.StatusForbidden {
		t.Errorf("analyst: %d", w.Code)
	}
}
