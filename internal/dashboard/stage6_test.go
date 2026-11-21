package dashboard

import (
	"encoding/csv"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
)

// W19: the records exported as CSV and JSON Lines, a run deleted with the
// password, and the marks' maximum age.
func TestRecordsPage(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	d := newDashboard(t, dir)
	admin := d.login(t, "admin", d.password)

	w := d.do("GET", "/api/export?format=csv&kind=all&range=all", nil, admin)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || w.Code != 200 || len(rows) != 5 || rows[0][0] != "id" || rows[1][0] != "d" || !strings.Contains(w.Header().Get("Content-Disposition"), ".csv") {
		t.Errorf("csv: %d %v %v", w.Code, rows, err)
	}
	w = d.do("GET", "/api/export?format=jsonl&rule=942100&kind=all&range=all", nil, admin)
	if lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n"); len(lines) != 2 || !strings.Contains(lines[0], `"id":"c"`) {
		t.Errorf("jsonl: %s", w.Body)
	}
	if w := d.do("GET", "/api/export?format=xml", nil, admin); w.Code != http.StatusBadRequest {
		t.Errorf("xml: %d", w.Code)
	}

	var p recordsPage
	decode(t, d.do("GET", "/api/records-page", nil, admin), &p)
	if len(p.Runs) != 1 || p.Runs[0].Records != 4 || p.Busy || len(p.Files) != 1 {
		t.Errorf("records page: %+v", p)
	}
	// A deletion needs the password, and no writer in the folder.
	if w := d.postJSON("/api/records/delete", deleteRequest{Run: "run1", Reason: "test", Password: "wrong"}, admin); w.Code != http.StatusForbidden {
		t.Errorf("wrong password: %d", w.Code)
	}
	writer, err := record.Open(record.Config{Dir: dir}, record.Engine{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := d.postJSON("/api/records/delete", deleteRequest{Run: "run1", Reason: "test", Password: d.password}, admin); w.Code != http.StatusConflict {
		t.Errorf("while a writer has the folder: %d %s", w.Code, w.Body)
	}
	writer.Close()
	before := time.Date(2026, 10, 23, 11, 45, 0, 0, time.UTC)
	if w := d.postJSON("/api/records/delete", deleteRequest{Before: before, Reason: "old ones", Password: d.password}, admin); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if got := ids(d.srv.store); strings.Join(got, ",") != "c,d" {
		t.Errorf("after deleting before 11:45: %v", got)
	}
	log := changes(t, d.cfg.StateDir)
	if last := log[len(log)-1]; last.Action != actionRecordsDeleted || last.Reason != "old ones" {
		t.Errorf("change log: %+v", last)
	}

	// Marks older than their age go once a day.
	d.srv.marks.add([]markLine{
		{Record: "old", Verdict: verdictFalsePositive, User: "admin", Time: t0, Alert: markAlert{Time: t0.Add(-40 * 24 * time.Hour)}},
		{Record: "b", Verdict: verdictRealAttack, User: "admin", Time: t0, Alert: markAlert{Time: t0.Add(-time.Hour)}}})
	d.srv.cfg.MarksMaxAgeDays = 30
	d.srv.pruneMarks()
	if n, _ := d.srv.marks.count(); n != 1 || d.srv.marks.verdict("b") != verdictRealAttack {
		t.Errorf("%d marks left", n)
	}
	reopened, _ := openMarks(filepath.Join(d.cfg.StateDir, MarksFile))
	if n, _ := reopened.count(); n != 1 {
		t.Errorf("the file keeps %d marks", n)
	}
}

// W23: Clients and Endpoints, with the application filter.
func TestClientsAndEndpoints(t *testing.T) {
	dir := t.TempDir()
	profiledRecords(t, dir)
	s := newStore(dir)
	refresh(t, s)
	r := timeRange{Name: "1h", From: t0.Add(-time.Hour), To: t0}
	c := s.clients(r, "")
	if c.Total != 1 || c.Rows[0].IP != "203.0.113.9" || c.Rows[0].Records != 4 || c.Rows[0].Alerts != 3 || len(c.Rows[0].Applications) != 3 {
		t.Errorf("clients: %+v", c)
	}
	if c := s.clients(r, "blog"); c.Rows[0].Records != 1 {
		t.Errorf("clients of blog: %+v", c)
	}
	one := s.client("203.0.113.9", r)
	if one.Records != 4 || one.Alerts != 3 || len(one.Paths) != 4 {
		t.Errorf("client: %+v", one)
	}
	e := s.endpoints(r, "shop")
	if e.Total != 2 || e.Rows[0].Application != "shop" || e.Rows[0].Clients != 1 {
		t.Errorf("endpoints: %+v", e)
	}
}

// W20: the dashboard's settings written to its file, checked first, and
// taken at once.
func TestDashboardSettings(t *testing.T) {
	d := newDashboard(t, "")
	admin := d.login(t, "admin", d.password)
	path := filepath.Join(t.TempDir(), "dashboard.json")
	os.WriteFile(path, []byte("{\n  \"listen\": \"127.0.0.1:0\",\n  \"records_dir\": \"r\",\n  \"state_dir\": \"s\"\n}\n"), 0o600)
	d.srv.cfg.path, d.srv.cfg.Listen = path, "127.0.0.1:8443"
	post := func(v any) *httpResponse {
		w := d.postJSON("/api/dashboard-settings", v, admin)
		return &httpResponse{w.Code, w.Body.String()}
	}
	good := map[string]any{"session_idle_minutes": 30, "marks_max_age_days": 90, "test_configs": []string{"../../../configs/crs-first-engine.json"}, "cert_names": []string{"ids.lan", "10.0.0.5"}, "reason": "VPN", "password": d.password}
	if r := post(map[string]any{"session_idle_minutes": 0, "reason": "x", "password": d.password}); r.code != http.StatusBadRequest {
		t.Errorf("idle 0: %+v", r)
	}
	bad := map[string]any{}
	for k, v := range good {
		bad[k] = v
	}
	bad["cert_names"] = []string{"not a name"}
	if r := post(bad); r.code != http.StatusBadRequest {
		t.Errorf("bad name: %+v", r)
	}
	good["test_configs"] = []string{}
	if r := post(good); r.code != 200 {
		t.Fatalf("save: %+v", r)
	}
	text := read(t, path)
	for _, want := range []string{`"session_idle_minutes": 30`, `"marks_max_age_days": 90`, `"10.0.0.5"`, `"listen": "127.0.0.1:0"`} {
		if !strings.Contains(text, want) {
			t.Errorf("the file lacks %s:\n%s", want, text)
		}
	}
	if d.srv.cfg.SessionIdleMinutes != 30 || d.srv.auth.idle != 30*time.Minute || d.srv.cfg.MarksMaxAgeDays != 90 {
		t.Errorf("not taken: %+v", d.srv.cfg)
	}
	if c := d.srv.cert.Load(); c == nil || c.Leaf == nil || !strings.Contains(strings.Join(c.Leaf.DNSNames, ","), "ids.lan") {
		t.Error("no certificate with the new name")
	}
}

type httpResponse struct {
	code int
	body string
}
