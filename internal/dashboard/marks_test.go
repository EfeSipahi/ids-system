package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
)

type markAnswer struct {
	Marked int    `json:"marked"`
	Change string `json:"change"`
}

type historyAnswer struct {
	Verdict string     `json:"verdict"`
	History []markLine `json:"history"`
}

// TestMarks (G1, G2, G5, verification 5): marking one record, the chosen
// ones and all that match a filter; what the list, overview, Rules and
// Engine answers show; one log entry per action; who may mark.
func TestMarks(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	before := folderState(t, dir)
	d := newDashboard(t, dir)
	admin := d.login(t, "admin", d.password)
	sessions := map[string]*http.Cookie{RoleAdmin: admin}
	for _, role := range []string{RoleViewer, RoleAnalyst} {
		p, err := AddUser(d.cfg.StateDir, role+"1", role)
		if err != nil {
			t.Fatal(err)
		}
		sessions[role] = d.login(t, role+"1", p)
	}
	analyst := sessions[RoleAnalyst]

	// A viewer reads marks but can't make them; another site can't post.
	if w := d.postJSON("/api/marks", markRequest{Verdict: verdictFalsePositive, IDs: []string{"a"}}, sessions[RoleViewer]); w.Code != http.StatusForbidden {
		t.Errorf("a viewer marked: %d", w.Code)
	}
	if w := d.postJSON("/api/marks", markRequest{Verdict: verdictFalsePositive, IDs: []string{"a"}}, analyst, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site: %d", w.Code)
	}

	// One record, with a note.
	var ma markAnswer
	w := d.postJSON("/api/marks", markRequest{Verdict: verdictFalsePositive, Note: "our own health check", IDs: []string{"a"}}, analyst)
	decode(t, w, &ma)
	if w.Code != 200 || ma.Marked != 1 {
		t.Fatalf("mark a: %d %s", w.Code, w.Body)
	}
	var h historyAnswer
	decode(t, d.do("GET", "/api/marks/a", nil, sessions[RoleViewer]), &h)
	if h.Verdict != verdictFalsePositive || len(h.History) != 1 || h.History[0].User != "analyst1" || h.History[0].Note != "our own health check" ||
		h.History[0].Change != ma.Change || h.History[0].Alert.Client != "203.0.113.1" || len(h.History[0].Alert.Rules) == 0 {
		t.Errorf("history of a: %+v", h)
	}
	decode(t, d.do("GET", "/api/marks/c", nil, admin), &h)
	if h.Verdict != verdictNotReviewed || len(h.History) != 0 {
		t.Errorf("an unmarked record: %+v", h)
	}

	// All records of rule 942100 (b and c), by the list's filter.
	w = d.postJSON("/api/marks", markRequest{Verdict: verdictExpected, Filter: ptr("kind=all&range=all&rule=942100&page=3&sort=score")}, analyst)
	decode(t, w, &ma)
	if w.Code != 200 || ma.Marked != 2 {
		t.Fatalf("mark by filter: %d %s", w.Code, w.Body)
	}
	// Then a again: its history has both, in order.
	if w := d.postJSON("/api/marks", markRequest{Verdict: verdictRealAttack, IDs: []string{"a", "b"}}, admin); w.Code != 200 {
		t.Fatalf("mark a and b: %d %s", w.Code, w.Body)
	}
	decode(t, d.do("GET", "/api/marks/a", nil, admin), &h)
	if h.Verdict != verdictRealAttack || len(h.History) != 2 || h.History[0].Verdict != verdictFalsePositive || h.History[1].User != "admin" {
		t.Errorf("history of a after two marks: %+v", h)
	}

	// One log entry per action, with the filter or the records and what
	// they were before.
	cs := changes(t, d.cfg.StateDir)
	if len(cs) != 3 {
		t.Fatalf("%d log entries, want 3", len(cs))
	}
	if c := cs[1]; c.Action != actionMark || c.Records != 2 || c.Filter != "kind=all&range=all&rule=942100" || c.IDs != nil || c.Before[verdictNotReviewed] != 2 {
		t.Errorf("filter entry: %+v", c)
	}
	if c := cs[2]; c.Records != 2 || strings.Join(c.IDs, ",") != "a,b" || c.Before[verdictFalsePositive] != 1 || c.Before[verdictExpected] != 1 {
		t.Errorf("records entry: %+v", c)
	}

	// The list shows verdicts and filters by them.
	var l list
	decode(t, d.do("GET", "/api/alerts?kind=all&range=all", nil, admin), &l)
	got := map[string]string{}
	for _, r := range l.Rows {
		got[r.ID] = r.Verdict
	}
	if got["a"] != verdictRealAttack || got["b"] != verdictRealAttack || got["c"] != verdictExpected || got["d"] != verdictNotReviewed {
		t.Errorf("verdicts in the list: %v", got)
	}
	decode(t, d.do("GET", "/api/alerts?kind=all&range=all&review=not_reviewed", nil, admin), &l)
	if l.Total != 1 || l.Rows[0].ID != "d" {
		t.Errorf("review=not_reviewed: %+v", l.Rows)
	}
	if w := d.do("GET", "/api/alerts?review=maybe", nil, admin); w.Code != http.StatusBadRequest {
		t.Errorf("review=maybe: %d", w.Code)
	}

	// The overview counts alerts nobody marked; the Rules page the
	// records marked false positive.
	d.postJSON("/api/marks", markRequest{Verdict: verdictNotReviewed, IDs: []string{"b"}}, admin)
	d.postJSON("/api/marks", markRequest{Verdict: verdictFalsePositive, IDs: []string{"a"}}, admin)
	var o overview
	decode(t, d.do("GET", "/api/overview?range=all", nil, admin), &o)
	if o.Alerts != 2 || o.NotReviewed != 1 {
		t.Errorf("overview: %d alerts, %d not reviewed", o.Alerts, o.NotReviewed)
	}
	var rp rulesPage
	decode(t, d.do("GET", "/api/rules?range=all", nil, admin), &rp)
	for _, r := range rp.Rules {
		if want := map[int]int{930100: 1, 949110: 1}[r.ID]; r.FalsePositives != want {
			t.Errorf("rule %d: %d false positives, want %d", r.ID, r.FalsePositives, want)
		}
	}
	var ep enginePage
	decode(t, d.do("GET", "/api/engine", nil, admin), &ep)
	if ep.Marks != 3 {
		t.Errorf("engine: %d marked records, want 3", ep.Marks)
	}

	// Bad requests.
	for _, bad := range []markRequest{
		{Verdict: "maybe", IDs: []string{"a"}},
		{Verdict: verdictExpected},
		{Verdict: verdictExpected, IDs: []string{"a"}, Filter: ptr("kind=all")},
		{Verdict: verdictExpected, IDs: []string{"nothing"}},
		{Verdict: verdictExpected, Note: strings.Repeat("n", maxNote+1), IDs: []string{"a"}},
		{Verdict: verdictExpected, Filter: ptr("kind=nothing")},
		{Verdict: verdictExpected, Filter: ptr("kind=all&range=all&ip=198.51.100.99")},
	} {
		if w := d.postJSON("/api/marks", bad, analyst); w.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d %s", bad, w.Code, w.Body)
		}
	}

	// The marks stay after a restart.
	d.srv.Close()
	srv, err := newServer(d.cfg, io.Discard, d.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if v := srv.marks.verdict("a"); v != verdictFalsePositive {
		t.Errorf("after a restart: %q", v)
	}
	if after := folderState(t, dir); after != before {
		t.Error("the records folder changed")
	}
}

// TestMarksOutliveRecords (G6): a record that rotated away still counts on
// the Rules page with its mark; a mark line that can't be read is skipped
// and counted.
func TestMarksOutliveRecords(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, record.RotatedPrefix+"20261023T110000.000000000Z.jsonl")
	appendLines(t, old, startRecord("run1", t0.Add(-time.Hour), "sha256:one"),
		requestRecord("gone", "run1", t0.Add(-50*time.Minute), "203.0.113.9", 10, at{930100, "ARGS:file"}))
	appendLines(t, filepath.Join(dir, record.CurrentFile), startRecord("run1", t0.Add(-time.Hour), "sha256:one"),
		requestRecord("kept", "run1", t0.Add(-10*time.Minute), "203.0.113.1", 10, at{930100, "ARGS:file"}))
	d := newDashboard(t, dir)
	admin := d.login(t, "admin", d.password)
	if w := d.postJSON("/api/marks", markRequest{Verdict: verdictFalsePositive, IDs: []string{"gone", "kept"}}, admin); w.Code != 200 {
		t.Fatalf("mark: %d %s", w.Code, w.Body)
	}
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	if err := d.srv.store.refresh(); err != nil {
		t.Fatal(err)
	}
	if w := d.do("GET", "/api/records/gone", nil, admin); w.Code != http.StatusNotFound {
		t.Fatalf("the rotated record is still there: %d", w.Code)
	}
	var rp rulesPage
	decode(t, d.do("GET", "/api/rules?range=all", nil, admin), &rp)
	for _, r := range rp.Rules {
		if r.ID == 930100 && r.FalsePositives != 2 {
			t.Errorf("930100: %d false positives, want 2 (one record rotated away)", r.FalsePositives)
		}
	}
	var h historyAnswer
	decode(t, d.do("GET", "/api/marks/gone", nil, admin), &h)
	if h.Verdict != verdictFalsePositive {
		t.Errorf("the mark of a rotated record: %+v", h)
	}

	// A broken line in the marks file is skipped and counted.
	d.srv.Close()
	f, _ := os.OpenFile(filepath.Join(d.cfg.StateDir, MarksFile), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{broken\n" + `{"record":"x","verdict":"maybe"}` + "\n")
	f.Close()
	m, err := openMarks(filepath.Join(d.cfg.StateDir, MarksFile))
	if err != nil {
		t.Fatal(err)
	}
	if n, broken := m.count(); n != 2 || broken != 2 {
		t.Errorf("%d marked records, %d broken lines; want 2 and 2", n, broken)
	}
}

// TestMarkLimit (C7): at most 10,000 records in one action.
func TestMarkLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 10,001 records")
	}
	dir := t.TempDir()
	lines := []any{startRecord("run1", t0.Add(-time.Hour), "sha256:one")}
	for i := range maxMarkRecords {
		lines = append(lines, requestRecord(fmt.Sprintf("r%05d", i), "run1", t0.Add(-30*time.Minute), "203.0.113.1", 10))
	}
	lines = append(lines, requestRecord("other", "run1", t0.Add(-30*time.Minute), "203.0.113.2", 10))
	appendLines(t, filepath.Join(dir, record.CurrentFile), lines...)
	d := newDashboard(t, dir)
	admin := d.login(t, "admin", d.password)
	if w := d.postJSON("/api/marks", markRequest{Verdict: verdictExpected, Filter: ptr("kind=all&range=all")}, admin); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "10001 records match") {
		t.Errorf("10,001 records: %d %s", w.Code, w.Body)
	}
	start := time.Now()
	w := d.postJSON("/api/marks", markRequest{Verdict: verdictExpected, Filter: ptr("kind=all&range=all&ip=203.0.113.1")}, admin)
	var ma markAnswer
	decode(t, w, &ma)
	if w.Code != 200 || ma.Marked != maxMarkRecords {
		t.Fatalf("10,000 records: %d %.200s", w.Code, w.Body)
	}
	info, _ := os.Stat(filepath.Join(d.cfg.StateDir, MarksFile))
	t.Logf("marking 10,000 records took %v and wrote %d bytes", time.Since(start).Round(time.Millisecond), info.Size())
	cs := changes(t, d.cfg.StateDir)
	if len(cs) != 1 || cs[0].Records != maxMarkRecords {
		t.Errorf("log: %d entries", len(cs))
	}
	data, _ := json.Marshal(cs[0])
	if len(data) > 2000 {
		t.Errorf("a bulk mark's log entry has %d bytes; it should name the filter, not the records", len(data))
	}
}
