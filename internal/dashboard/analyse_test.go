package dashboard

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
)

// analyseForm posts the form of an analysis.
func (d *testDashboard) analyseForm(t *testing.T, session *http.Cookie, fields map[string][]string, files map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, vs := range fields {
		for _, v := range vs {
			mw.WriteField(k, v)
		}
	}
	for name, content := range files {
		fw, _ := mw.CreateFormFile("files", name)
		fw.Write([]byte(content))
	}
	mw.Close()
	r := httptest.NewRequest("POST", "https://127.0.0.1/api/analyse", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(session)
	w := httptest.NewRecorder()
	d.h.ServeHTTP(w, r)
	return w
}

// waitJob waits for the analysis to end and returns it.
func (d *testDashboard) waitJob(t *testing.T, session *http.Cookie) *job {
	t.Helper()
	for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		var p analysePage
		decode(t, d.do("GET", "/api/analyse", nil, session), &p)
		if p.Job != nil && !p.Job.Running {
			return p.Job
		}
	}
	t.Fatal("the analysis does not end")
	return nil
}

// W14: every CRS test, analysed from the dashboard with the first
// configuration at level 1, gives ids-offline's numbers: 2,916 of 5,072
// flagged (main plan, verification).
func TestAnalyseGivesIDSOfflinesNumbers(t *testing.T) {
	d := newDashboard(t, "")
	d.srv.test = newTestTester(t, crsFirst)
	d.srv.cfg.TestConfigs = []string{crsFirst}
	session := d.login(t, "admin", d.password)
	w := d.analyseForm(t, session, map[string][]string{"config": {"0"}, "level": {"1"}, "folder": {"*"}}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// One analysis at a time.
	if w := d.analyseForm(t, session, map[string][]string{"config": {"0"}, "folder": {"920100"}}, nil); w.Code != http.StatusConflict && w.Code != http.StatusAccepted {
		t.Errorf("a second analysis: %d", w.Code)
	}
	j := d.waitJob(t, session)
	if j.Error != "" || j.Requests != 5072 {
		t.Fatalf("job: %s, %d requests", j.Error, j.Requests)
	}
	flagged := 0
	for _, g := range j.Summary {
		flagged += g.Flagged
	}
	if flagged != 2916 || len(j.Summary) != 290 || len(j.Rows) != maxAnalyseRows {
		t.Errorf("%d flagged of %d, %d files, %d rows", flagged, j.Requests, len(j.Summary), len(j.Rows))
	}
	if entries, _ := os.ReadDir(d.cfg.RecordsDir); len(entries) != 0 {
		t.Errorf("records were written without asking: %v", entries)
	}
}

// Uploaded files, an analyst, and records written by an admin only, and
// only while no other program writes the records folder.
func TestAnalyseUploadsAndRecords(t *testing.T) {
	d, sessions, _ := controlDashboard(t)
	d.srv.test = newTestTester(t, crsFirst)
	d.srv.cfg.TestConfigs = []string{crsFirst}
	file := `[{"name": "sqli", "method": "GET", "uri": "/?id=1%27%20union%20select%201,2--", "headers": [["Host", "localhost:8080"]]},
		{"name": "plain", "method": "GET", "uri": "/tienda1/index.jsp", "headers": [["Host", "localhost:8080"]], "time": "2026-11-20T10:00:00Z"}]`
	analyst := sessions[RoleAnalyst]
	if w := d.analyseForm(t, analyst, map[string][]string{"config": {"0"}, "write": {"records"}}, map[string]string{"mine.json": file}); w.Code != http.StatusForbidden {
		t.Errorf("analyst writes records: %d %s", w.Code, w.Body)
	}
	if w := d.analyseForm(t, analyst, map[string][]string{"config": {"0"}}, map[string]string{"mine.json": file}); w.Code != http.StatusAccepted {
		t.Fatalf("analyst: %d %s", w.Code, w.Body)
	}
	j := d.waitJob(t, analyst)
	if j.Error != "" || j.Requests != 2 || j.Alerts != 1 || j.Files[0] != "mine" || j.Rows[0].Application != "csic-shop" || !j.Profiled {
		t.Fatalf("job: %+v", j)
	}
	if w := d.analyseForm(t, analyst, map[string][]string{"config": {"0"}, "write": {"replay"}}, map[string]string{"mine.json": file}); w.Code != http.StatusForbidden {
		t.Errorf("analyst replays: %d", w.Code)
	}
	admin := sessions[RoleAdmin]
	if w := d.analyseForm(t, admin, map[string][]string{"config": {"0"}, "write": {"replay"}}, map[string]string{"mine.json": file}); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "has no time") {
		t.Errorf("replay without times: %d %s", w.Code, w.Body)
	}
	// While another program writes the records folder, nothing is
	// written and the error says why.
	lock, err := record.Open(record.Config{Dir: d.cfg.RecordsDir}, record.Engine{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.analyseForm(t, admin, map[string][]string{"config": {"0"}, "write": {"records"}}, map[string]string{"mine.json": file})
	if j := d.waitJob(t, admin); !strings.Contains(j.Error, "ids-live writes the records folder") {
		t.Errorf("locked: %+v", j.Error)
	}
	lock.Close()
	before, _ := os.ReadFile(filepath.Join(d.cfg.RecordsDir, record.CurrentFile))
	d.analyseForm(t, admin, map[string][]string{"config": {"0"}, "write": {"records"}}, map[string]string{"mine.json": file})
	j = d.waitJob(t, admin)
	after, _ := os.ReadFile(filepath.Join(d.cfg.RecordsDir, record.CurrentFile))
	if j.Error != "" || j.RecordRun == "" || j.Written != 2 || !bytes.Contains(after[len(before):], []byte(j.RecordRun)) {
		t.Errorf("records: %+v", j)
	}

	// The pending changes tried on these requests (W8): the rule that
	// found the injection, off for the shop, takes its alert away.
	ch := pendingChange{Kind: kindRuleOff, Rule: 942100, Reason: "x"}
	for _, id := range j.Rows[0].Rules {
		if id >= 942000 && id < 943000 && id != 942100 {
			ch.Rule = id
		}
	}
	if w := d.postJSON("/api/changes", changeRequest{Action: "add", Object: "app:csic-shop", Change: &ch}, admin); w.Code != 200 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	var tr tryResult
	w := d.postJSON("/api/analyse/try", map[string]string{"object": "app:csic-shop"}, admin)
	decode(t, w, &tr)
	if w.Code != 200 || tr.Requests != 2 || tr.AlertsBefore != 1 {
		t.Errorf("try: %d %s", w.Code, w.Body)
	}
	// The Profile tab counts the requests of the analysis.
	var p profilePage
	decode(t, d.do("GET", "/api/applications/csic-shop/profile", nil, admin), &p)
	if len(p.Files) != 1 || p.Files[0] != "mine" {
		t.Errorf("profile tab files: %+v", p.Files)
	}
}
