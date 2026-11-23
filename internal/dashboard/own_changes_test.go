package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
)

// adminForm is the rule of section 3 of docs/development-plan-own-rules.md
// as the form gives it.
func adminForm(apps ...string) ownForm {
	return ownForm{
		Msg: "Admin pages reached from outside the office", Severity: "critical", Applications: apps,
		Conditions: []ownCondition{
			{Place: "REQUEST_FILENAME", Test: "beginsWith", Value: " /admin "},
			{Place: "REMOTE_ADDR", Test: "ipMatch", Not: true, Value: "10.0.0.0/8"},
		},
	}
}

const adminText = `SecRule REQUEST_FILENAME "@beginsWith /admin" \
    "id:1000,\
    phase:1,\
    block,\
    msg:'Admin pages reached from outside the office',\
    severity:'CRITICAL',\
    tag:'paranoia-level/1',\
    tag:'application/csic-shop',\
    t:none,\
    chain"
    SecRule REMOTE_ADDR "!@ipMatch 10.0.0.0/8" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`

// loadOwn loads text as own rules with a setup and a scoring file like
// CRS's, so that the engine's check of own rules reads it.
func loadOwn(t *testing.T, text string) error {
	t.Helper()
	dir := t.TempDir()
	write := func(name, s string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	setup := write("setup.conf", `SecDefaultAction "phase:1,log,pass"
SecDefaultAction "phase:2,log,pass"
SecAction "id:900990,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5,setvar:tx.error_anomaly_score=4,setvar:tx.warning_anomaly_score=3,setvar:tx.notice_anomaly_score=2,setvar:tx.inbound_anomaly_score_pl1=0"
`)
	scoring := write("REQUEST-949-SCORING.conf", `SecAction "id:949990,phase:2,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}'"`+"\n")
	_, err := engine.Load(engine.Config{Files: []string{setup, scoring}, OwnRules: write("own.conf", text)})
	return err
}

// N1: the form writes the rule of the plan in CRS's layout, which the
// engine's check of own rules takes, and reads it back.
func TestOwnText(t *testing.T) {
	text, err := ownText(1000, adminForm("csic-shop"))
	if err != nil {
		t.Fatal(err)
	}
	if text != adminText {
		t.Errorf("text:\n%s\nwant:\n%s", text, adminText)
	}
	if err := loadOwn(t, text); err != nil {
		t.Errorf("the engine refuses it: %v", err)
	}
	f, ok := formOf(1000, text)
	want := adminForm("csic-shop")
	want.Severity, want.Conditions[0].Value = "CRITICAL", "/admin"
	if !ok || !reflect.DeepEqual(*f, want) {
		t.Errorf("read back: %v %+v", ok, f)
	}

	// The body's places run in phase 2; ignoring case writes the value in
	// lower case with t:lowercase, or (?i) for a regular expression; quotes
	// are written so that they read back.
	f2 := ownForm{Msg: `The "debug" page's form`, Severity: "WARNING", Applications: []string{"none"}, Conditions: []ownCondition{
		{Place: "ARGS", Key: "cmd", Test: "contains", Value: `Run "Me"`, IgnoreCase: true},
		{Place: "REQUEST_HEADERS", Key: "User-Agent", Test: "rx", Value: `^curl/\d`, IgnoreCase: true},
	}}
	text, err = ownText(1001, f2)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"phase:2", `"@contains run \"me\"" \`, "t:none,\\\n    t:lowercase", `"@rx (?i)^curl/\d" \`, `msg:'The \"debug\" page\'s form'`, "tag:'application/none'", "warning_anomaly_score"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q not in:\n%s", want, text)
		}
	}
	if err := loadOwn(t, text); err != nil {
		t.Errorf("the engine refuses it: %v\n%s", err, text)
	}
	if back, ok := formOf(1001, text); !ok || back.Conditions[0].Value != `run "me"` || back.Conditions[1].Value != `^curl/\d` || !back.Conditions[1].IgnoreCase || back.Msg != f2.Msg {
		t.Errorf("read back: %v %+v", ok, back)
	}

	// A rule the form would not write so is edited as text.
	if _, ok := formOf(1000, strings.Replace(adminText, "    block,\\\n", "    block,\\\n    logdata:'%{MATCHED_VAR}',\\\n", 1)); ok {
		t.Error("a rule with logdata reads into the form")
	}

	for name, c := range map[string]struct {
		f    func(*ownForm)
		want string
	}{
		"no message":       {func(f *ownForm) { f.Msg = " " }, "give a message"},
		"a severity":       {func(f *ownForm) { f.Severity = "INFO" }, "give a severity"},
		"no condition":     {func(f *ownForm) { f.Conditions = nil }, "give 1 to 10 conditions"},
		"a place":          {func(f *ownForm) { f.Conditions[0].Place = "TX" }, "choose the place"},
		"a header's name":  {func(f *ownForm) { f.Conditions[0].Place = "REQUEST_HEADERS" }, "name the header"},
		"a name too many":  {func(f *ownForm) { f.Conditions[0].Key = "x" }, "takes no name"},
		"a name's letters": {func(f *ownForm) { f.Conditions[0].Place, f.Conditions[0].Key = "ARGS", "a|b" }, "use letters"},
		"a test":           {func(f *ownForm) { f.Conditions[0].Test = "detectSQLi" }, "choose its test"},
		"ipMatch":          {func(f *ownForm) { f.Conditions[0].Test = "ipMatch" }, "only the client IP address"},
		"a variable":       {func(f *ownForm) { f.Conditions[0].Value = "%{tx.x}" }, "starts a variable"},
		"a line break":     {func(f *ownForm) { f.Conditions[0].Value = "a\nb" }, "on one line"},
		"no value":         {func(f *ownForm) { f.Conditions[0].Value = "" }, "give the value"},
		"a backslash":      {func(f *ownForm) { f.Conditions[0].Value = `/admin\` }, "leave out a backslash"},
		"an application":   {func(f *ownForm) { f.Applications = []string{"my shop"} }, "not an application's name"},
	} {
		f := adminForm()
		c.f(&f)
		if _, err := ownText(1000, f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The own-rules file is edited rule by rule: added at the end, replaced
// in place, removed with its blank line.
func TestEditOwn(t *testing.T) {
	raw := []byte(ownHeader)
	edit := func(ch pendingChange) {
		t.Helper()
		var err error
		if raw, err = editOwn("own.conf", raw, ch); err != nil {
			t.Fatal(err)
		}
	}
	one, _ := ownText(1000, adminForm())
	notice := adminForm()
	notice.Severity = "NOTICE"
	two, _ := ownText(1001, notice)
	edit(pendingChange{Kind: kindOwnRuleAdd, Rule: 1000, Text: one})
	edit(pendingChange{Kind: kindOwnRuleAdd, Rule: 1001, Text: two})
	if got, want := string(raw), ownHeader+"\n"+one+"\n"+two; got != want {
		t.Errorf("added:\n%s", got)
	}
	edited := strings.Replace(one, "/admin", "/manage", 1)
	edit(pendingChange{Kind: kindOwnRuleEdit, Rule: 1000, Text: edited})
	if got, want := string(raw), ownHeader+"\n"+edited+"\n"+two; got != want {
		t.Errorf("edited:\n%s", got)
	}
	edit(pendingChange{Kind: kindOwnRuleRemove, Rule: 1000})
	if got, want := string(raw), ownHeader+"\n"+two; got != want {
		t.Errorf("1000 removed:\n%s", got)
	}
	edit(pendingChange{Kind: kindOwnRuleRemove, Rule: 1001})
	if got := string(raw); got != ownHeader {
		t.Errorf("both removed:\n%q", got)
	}
	for _, ch := range []pendingChange{{Kind: kindOwnRuleRemove, Rule: 1000}, {Kind: kindOwnRuleEdit, Rule: 1000, Text: one}} {
		if _, err := editOwn("own.conf", raw, ch); err == nil || !strings.Contains(err.Error(), "no rule 1000") {
			t.Errorf("%s of a rule not there: %v", ch.Kind, err)
		}
	}
	if _, err := editOwn("own.conf", []byte(ownHeader+"\n"+one), pendingChange{Kind: kindOwnRuleAdd, Rule: 1000, Text: one}); err == nil {
		t.Error("1000 added twice")
	}
}

// Stage 3: own rules are added, changed and removed as pending changes for
// every application; the first sets own_rules and makes the file; a
// number is never given twice; an undo takes them back.
func TestOwnRuleChanges(t *testing.T) {
	path := idsCopy(t)
	origConfig := read(t, path)
	c := newControl(path, t.TempDir(), newClock().now)
	ownFile := filepath.Join(filepath.Dir(path), "..", "own-rules", "csic-shop.conf")

	first, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleAdd, Own: ptr(adminForm("csic-shop")), User: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Rule != 1000 || first.Text != adminText || first.What != "Own rule 1000, CRITICAL, for csic-shop: Admin pages reached from outside the office" {
		t.Errorf("first: %+v", first)
	}
	scanner := ownForm{Msg: "A scanner", Severity: "WARNING", Conditions: []ownCondition{{Place: "REQUEST_HEADERS", Key: "User-Agent", Test: "contains", Value: "evil-scanner"}}}
	second, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleAdd, Own: &scanner, User: "admin"})
	if err != nil || second.Rule != 1001 {
		t.Fatalf("second: %v %+v", err, second)
	}
	// try gives the next rule as add would, and adds nothing.
	if tried, err := c.try(objectGlobal, pendingChange{Kind: kindOwnRuleAdd, Own: &scanner, User: "admin"}); err != nil || tried.Rule != 1002 {
		t.Errorf("try: %v %+v", err, tried)
	}
	if list, _ := c.pending(objectGlobal); len(list) != 2 {
		t.Errorf("%d pending", len(list))
	}

	a, err := c.apply(objectGlobal, "admin", "own rules")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, path), `"own_rules": "../own-rules/csic-shop.conf"`) {
		t.Errorf("configuration:\n%s", read(t, path))
	}
	if got, want := read(t, ownFile), ownHeader+"\n"+adminText+"\n"+second.Text; got != want {
		t.Errorf("own rules:\n%s", got)
	}
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Load(p.Config); err != nil {
		t.Fatalf("the rules don't load: %v", err)
	}

	// The scanner as a notice; the admin rule removed; a new rule gets
	// 1002, not 1001 or 1000 again.
	scanner.Severity = "NOTICE"
	if _, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleEdit, Rule: 1001, Own: &scanner, User: "admin"}); err != nil {
		t.Fatal(err)
	}
	removed, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleRemove, Rule: 1000, User: "admin"})
	if err != nil || removed.What != "Own rule 1000 removed: Admin pages reached from outside the office" {
		t.Fatalf("remove: %v %+v", err, removed)
	}
	if _, err := c.apply(objectGlobal, "admin", "x"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ownFile); strings.Contains(got, "id:1000") || !strings.Contains(got, "severity:'NOTICE'") {
		t.Errorf("after the edit and the removal:\n%s", got)
	}
	third, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleAdd, Own: ptr(adminForm()), User: "admin"})
	if err != nil || third.Rule != 1002 {
		t.Errorf("third: %v %+v", err, third)
	}
	c.drop(objectGlobal, third.ID)

	// Refused: an application the configuration doesn't have, a rule not
	// there, text with a number used before, text that turns rules off.
	for name, ch := range map[string]pendingChange{
		"an unknown application": {Kind: kindOwnRuleAdd, Own: ptr(adminForm("blog"))},
		"an edit of 1000":        {Kind: kindOwnRuleEdit, Rule: 1000, Own: ptr(adminForm())},
		"a removal of 1005":      {Kind: kindOwnRuleRemove, Rule: 1005},
		"a used number":          {Kind: kindOwnRuleAdd, Text: adminText},
		"ctl":                    {Kind: kindOwnRuleAdd, Text: strings.Replace(strings.Replace(adminText, "1000", "1003", 1), "    block,", "    block,ctl:ruleRemoveById=942100,", 1)},
		"two rules":              {Kind: kindOwnRuleAdd, Text: adminText + strings.Replace(adminText, "1000", "1004", 1)},
		"form and text":          {Kind: kindOwnRuleAdd, Own: ptr(adminForm()), Text: adminText},
	} {
		ch.User = "admin"
		if _, err := c.add(objectGlobal, ch); err == nil {
			t.Errorf("%s: added", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}

	// The undo of the first version takes own_rules out of the
	// configuration; the file it made stays, and nothing reads it.
	c.add(objectGlobal, pendingChange{Kind: kindRestore, Version: a.Version.ID, User: "admin"})
	if _, err := c.apply(objectGlobal, "admin", "undo"); err != nil {
		t.Fatal(err)
	}
	if read(t, path) != origConfig {
		t.Errorf("the undo left the configuration:\n%s", read(t, path))
	}
	// A rule added now starts the file again, after the numbers used.
	again, err := c.add(objectGlobal, pendingChange{Kind: kindOwnRuleAdd, Own: &scanner, User: "admin"})
	if err != nil || again.Rule != 1002 {
		t.Fatalf("again: %v %+v", err, again)
	}
	if _, err := c.apply(objectGlobal, "admin", "x"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ownFile); got != ownHeader+"\n"+again.Text {
		t.Errorf("the file started again:\n%s", got)
	}
}

// N7: an analyst proposes own rules with the form; their text, and
// applying, are an admin's. The draft gives the rule's number and text.
func TestOwnRulesByRole(t *testing.T) {
	d, sessions, _ := controlDashboard(t)
	analyst, admin := sessions[RoleAnalyst], sessions[RoleAdmin]
	add := func(session *http.Cookie, ch pendingChange) (int, pendingChange) {
		t.Helper()
		w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: objectGlobal, Change: &ch}, session)
		var got pendingChange
		if w.Code == 200 {
			decode(t, w, &got)
		}
		return w.Code, got
	}

	var draft map[string]any
	decode(t, d.postJSON("/api/own-rules/draft", ownDraft{Own: ptr(adminForm("csic-shop"))}, analyst), &draft)
	if draft["rule"] != float64(1000) || draft["text"] != adminText || draft["error"] != nil {
		t.Errorf("draft: %v", draft)
	}
	decode(t, d.postJSON("/api/own-rules/draft", ownDraft{Own: ptr(adminForm("blog"))}, analyst), &draft)
	if e, _ := draft["error"].(string); !strings.Contains(e, "blog") {
		t.Errorf("draft for an unknown application: %v", draft)
	}
	if w := d.postJSON("/api/own-rules/draft", ownDraft{Text: adminText}, analyst); w.Code != http.StatusForbidden {
		t.Errorf("an analyst's text: %d", w.Code)
	}

	code, proposed := add(analyst, pendingChange{Kind: kindOwnRuleAdd, Own: ptr(adminForm("csic-shop"))})
	if code != 200 || !proposed.Proposal || proposed.Rule != 1000 {
		t.Fatalf("proposal: %d %+v", code, proposed)
	}
	if code, _ := add(analyst, pendingChange{Kind: kindOwnRuleAdd, Text: strings.Replace(adminText, "1000", "1001", 1)}); code != http.StatusForbidden {
		t.Errorf("an analyst's text: %d", code)
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "apply", Object: objectGlobal, Reason: "x", Password: d.password}, admin); w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}

	// The rules on disk, with the form for a rule it writes, and none for
	// one written by hand.
	text := strings.Replace(strings.Replace(adminText, "1000", "1001", 1), "    block,", "    block,\\\n    logdata:'%{MATCHED_VAR}',", 1)
	if code, got := add(admin, pendingChange{Kind: kindOwnRuleAdd, Text: text}); code != 200 || got.Rule != 1001 {
		t.Fatalf("admin's text: %d %+v", code, got)
	}
	d.postJSON("/api/changes", changeRequest{Action: "apply", Object: objectGlobal, Reason: "x", Password: d.password}, admin)
	var own ownRulesAnswer
	decode(t, d.do("GET", "/api/own-rules", nil, analyst), &own)
	if len(own.Rules) != 2 || own.File != "csic-shop.conf" || !reflect.DeepEqual(own.Applications, []string{"csic-shop"}) || own.Error != "" {
		t.Fatalf("own rules: %+v", own)
	}
	if own.Rules[0].Form == nil || own.Rules[1].Form != nil || own.Rules[1].Text != strings.TrimRight(text, "\n") {
		t.Errorf("forms: %+v, %+v", own.Rules[0].Form, own.Rules[1])
	}
	if code, got := add(analyst, pendingChange{Kind: kindOwnRuleRemove, Rule: 1001}); code != 200 || !got.Proposal {
		t.Errorf("an analyst's removal: %d %+v", code, got)
	}

	// The preview of a new rule says the records can't tell what it finds.
	if code, _ := add(admin, pendingChange{Kind: kindOwnRuleAdd, Own: ptr(adminForm())}); code != 200 {
		t.Fatal(code)
	}
	var pv preview
	decode(t, d.do("GET", "/api/changes/preview?object=global", nil, admin), &pv)
	if pv.Error != "" || len(pv.Untested) != 1 || !strings.HasPrefix(pv.Untested[0], "Own rule 1002 is new") {
		t.Errorf("preview: %+v", pv)
	}
}

// N8: the Test tab runs a request with an object's pending changes, built
// as they would be applied, so a proposed own rule finds what it is
// written for before anyone applies it. Nothing is written.
func TestTestTabWithPendingChanges(t *testing.T) {
	d, sessions, path := controlDashboard(t)
	analyst := sessions[RoleAnalyst]
	var err error
	if d.srv.test, err = newTester(path, []string{path, crsFirst}, "", d.clock.now); err != nil {
		t.Fatal(err)
	}
	before := read(t, path)
	page := func() testPage {
		t.Helper()
		var p testPage
		decode(t, d.do("GET", "/api/test", nil, analyst), &p)
		return p
	}
	p := page()
	if len(p.Configs) != 2 || !p.Configs[0].IDS || p.Configs[0].Name != "csic-shop.json" || p.Configs[1].IDS || len(p.Pending) != 0 {
		t.Fatalf("the IDS's configuration comes first, once: %+v", p)
	}

	w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: objectGlobal, Change: &pendingChange{Kind: kindOwnRuleAdd, Own: ptr(adminForm("csic-shop"))}}, analyst)
	var proposed pendingChange
	decode(t, w, &proposed)
	if w.Code != 200 || proposed.Rule != 1000 {
		t.Fatalf("proposal: %d %s", w.Code, w.Body)
	}
	if p := page(); !reflect.DeepEqual(p.Pending, []testPending{{Object: objectGlobal, Reach: "every application", Count: 1}}) {
		t.Errorf("pending on the page: %+v", p.Pending)
	}

	test := func(query, client string) (int, testAnswer, string) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://127.0.0.1/api/test?"+query+"&client="+client, strings.NewReader("GET /admin HTTP/1.1\nHost: localhost:8080\n"))
		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
		r.AddCookie(analyst)
		rw := httptest.NewRecorder()
		d.h.ServeHTTP(rw, r)
		var a testAnswer
		if rw.Code == 200 {
			decode(t, rw, &a)
		}
		return rw.Code, a, rw.Body.String()
	}
	found := func(a testAnswer) bool {
		for _, f := range a.Result.Findings {
			if f.RuleID == 1000 {
				return true
			}
		}
		return false
	}
	code, onDisk, body := test("config=0", "203.0.113.5")
	if code != 200 || found(onDisk) || onDisk.Pending != nil || onDisk.Read.Application != "csic-shop" {
		t.Fatalf("as on disk: %d %s", code, body)
	}
	code, with, body := test("config=0&pending=global", "203.0.113.5")
	if code != 200 || !found(with) || with.Result.Score.Total < 5 || !with.Result.Score.Exceeded {
		t.Fatalf("with the pending rule: %d %s", code, body)
	}
	if with.Pending == nil || with.Pending.Object != objectGlobal || len(with.Pending.Changes) != 1 || with.Pending.Changes[0] != proposed.What {
		t.Errorf("the answer's pending changes: %+v", with.Pending)
	}
	// Its fingerprint is the one ids-live will have once they are applied.
	if with.Config.Fingerprint == onDisk.Config.Fingerprint || with.Config.Newest {
		t.Errorf("fingerprints: %s, %s", with.Config.Fingerprint, onDisk.Config.Fingerprint)
	}
	if code, office, body := test("config=0&pending=global", "10.1.2.3"); code != 200 || found(office) {
		t.Errorf("from the office: %d %s", code, body)
	}

	for query, want := range map[string]int{
		"config=1&pending=global":        http.StatusBadRequest, // not the IDS's configuration
		"config=0&pending=app:csic-shop": http.StatusConflict,   // nothing pending
		"config=0&pending=app:none":      http.StatusBadRequest,
		"config=0&pending=everything":    http.StatusBadRequest,
	} {
		if code, _, body := test(query, ""); code != want {
			t.Errorf("%s: %d, want %d: %s", query, code, want, body)
		}
	}

	if read(t, path) != before {
		t.Errorf("a test changed the configuration")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "..", "own-rules")); !os.IsNotExist(err) {
		t.Errorf("a test made the own-rules folder: %v", err)
	}
	if list, _ := d.srv.control.pending(objectGlobal); len(list) != 1 {
		t.Errorf("%d pending after the tests", len(list))
	}
}
