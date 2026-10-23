package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

func TestMain(m *testing.M) {
	// Real passwords use 600,000 PBKDF2 rounds; the tests need not be
	// that slow. The stored count is per user, so check still uses the
	// count a user was made with.
	newIterations = 1000
	os.Exit(m.Run())
}

// t0 is the fake "now" of the tests.
var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: t0} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// appendLines writes records to a file, one JSON line each.
func appendLines(t *testing.T, path string, lines ...any) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		data, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func startRecord(run string, at time.Time, config string) record.Start {
	return record.Start{
		Type: record.TypeStart, Schema: record.Schema, Run: run, Time: at,
		Engine: record.Engine{Version: "test", CRS: "OWASP_CRS/4.30.0", ParanoiaLevel: 1, Config: config},
		Rules: []record.Rule{
			{ID: 930100, File: "REQUEST-930-APPLICATION-ATTACK-LFI.conf", Line: 10, Phase: 2, Active: true},
			{ID: 942100, File: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Line: 20, Phase: 2, Active: true},
			{ID: 942101, File: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", Line: 30, Phase: 2, ParanoiaLevel: 2, Reason: "paranoia level 2 is above 1"},
			{ID: 949110, File: "REQUEST-949-BLOCKING-EVALUATION.conf", Line: 40, Phase: 2, Active: true},
		},
	}
}

// at is one finding of a test record: a rule and where it matched.
type at struct {
	rule     int
	location string
}

// requestRecord is a record with a threshold of 5. Like CRS, an alert also
// carries a finding of the score rule 949110.
func requestRecord(id, run string, when time.Time, ip string, score int, findings ...at) record.Request {
	rec := record.Request{
		Type: record.TypeRequest, Schema: record.Schema, ID: id, Run: run, Time: when,
		Alert: score >= 5, DecidedBy: record.DecidedBy,
		Client:   record.Client{IP: ip, Port: 40000},
		Server:   record.Server{Host: "shop.example.com"},
		HTTP:     record.HTTP{Method: "GET", Path: "/" + id, UserAgent: "test-agent", HeaderNames: []string{"Host"}},
		Analysis: result.Analysis{Complete: true, Body: "empty"},
		Score:    result.Score{Total: score, Threshold: 5},
		Engine:   record.Engine{Version: "test", CRS: "OWASP_CRS/4.30.0", ParanoiaLevel: 1, Config: "sha256:one"},
	}
	for _, f := range findings {
		rec.Findings = append(rec.Findings, record.Finding{RuleID: f.rule, Location: f.location, Message: "test", Action: "pass"})
	}
	if rec.Alert {
		rec.Findings = append(rec.Findings, record.Finding{RuleID: 949110, Location: "TX:BLOCKING_INBOUND_ANOMALY_SCORE", Message: "score", Action: "pass"})
	}
	return rec
}

func countsRecord(run string, to time.Time, analysed, recorded, alerts int) record.Counts {
	return record.Counts{Type: record.TypeCounts, Schema: record.Schema, Run: run, From: to.Add(-time.Minute), To: to, Analysed: analysed, Recorded: recorded, Alerts: alerts}
}

// sampleRecords are one run with four records and their counts:
//
//	a: alert, 930100 twice (two places), from 203.0.113.1
//	b: alert, 942100, from 203.0.113.2
//	c: 942100 below the threshold, from 203.0.113.1
//	d: no finding, but the body could not be inspected
func sampleRecords(t *testing.T, dir string) {
	t.Helper()
	d := requestRecord("d", "run1", t0.Add(-4*time.Minute), "203.0.113.3", 0)
	d.Analysis = result.Analysis{Complete: false, Body: "partial", BodyReason: "larger than the limit"}
	appendLines(t, filepath.Join(dir, record.CurrentFile),
		startRecord("run1", t0.Add(-time.Hour), "sha256:one"),
		requestRecord("a", "run1", t0.Add(-30*time.Minute), "203.0.113.1", 10, at{930100, "ARGS:file"}, at{930100, "REQUEST_URI_RAW"}),
		requestRecord("b", "run1", t0.Add(-20*time.Minute), "203.0.113.2", 5, at{942100, "ARGS:id"}),
		requestRecord("c", "run1", t0.Add(-10*time.Minute), "203.0.113.1", 3, at{942100, "ARGS:id"}),
		d,
		countsRecord("run1", t0.Add(-3*time.Minute), 100, 4, 2),
	)
}

func newTestStore(t *testing.T) (*store, string) {
	t.Helper()
	dir := t.TempDir()
	return newStore(dir), dir
}

func refresh(t *testing.T, s *store) {
	t.Helper()
	if err := s.refresh(); err != nil {
		t.Fatal(err)
	}
}

func ids(s *store) []string {
	var out []string
	for _, e := range s.entries {
		out = append(out, e.id)
	}
	return out
}

func TestStoreIndexesRecords(t *testing.T) {
	s, dir := newTestStore(t)
	sampleRecords(t, dir)
	refresh(t, s)

	if got := ids(s); !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
		t.Fatalf("entries = %v", got)
	}
	a := s.byID["a"]
	// Each rule and location once; the score rule's TX location is not a
	// part of the request, and its group does not count.
	if !reflect.DeepEqual(a.rules, []int{930100, 949110}) {
		t.Errorf("rules = %v", a.rules)
	}
	if !reflect.DeepEqual(a.locations, []string{"ARGS:file", "REQUEST_URI_RAW"}) {
		t.Errorf("locations = %v", a.locations)
	}
	if !reflect.DeepEqual(a.groups, []string{"Path traversal and file access"}) {
		t.Errorf("groups = %v", a.groups)
	}
	if !s.byID["d"].incomplete || s.byID["a"].incomplete {
		t.Error("incomplete is not taken from the analysis")
	}
	if len(s.rules["run1"]) != 4 || s.starts["run1"].Rules != nil {
		t.Error("the rule list belongs in s.rules only")
	}
	if s.broken != 0 {
		t.Errorf("broken = %d", s.broken)
	}

	// Reading again finds nothing new and doubles nothing.
	refresh(t, s)
	if len(s.entries) != 4 || len(s.counts) != 1 {
		t.Errorf("after a second refresh: %d entries, %d counts", len(s.entries), len(s.counts))
	}
}

func TestStoreWaitsForUnfinishedLine(t *testing.T) {
	s, dir := newTestStore(t)
	path := filepath.Join(dir, record.CurrentFile)
	appendLines(t, path, requestRecord("a", "run1", t0, "", 10, at{930100, "ARGS:x"}))
	line, _ := json.Marshal(requestRecord("b", "run1", t0, "", 10, at{930100, "ARGS:x"}))

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(line[:20])
	refresh(t, s)
	if got := ids(s); !reflect.DeepEqual(got, []string{"a"}) || s.broken != 0 {
		t.Fatalf("with half a line: entries %v, broken %d", got, s.broken)
	}
	f.Write(append(line[20:], '\n'))
	refresh(t, s)
	if got := ids(s); !reflect.DeepEqual(got, []string{"a", "b"}) || s.broken != 0 {
		t.Fatalf("after the line was finished: entries %v, broken %d", got, s.broken)
	}
}

func TestStoreFollowsRotation(t *testing.T) {
	s, dir := newTestStore(t)
	current := filepath.Join(dir, record.CurrentFile)
	appendLines(t, current, startRecord("run1", t0, "sha256:one"), requestRecord("a", "run1", t0, "", 10, at{930100, "ARGS:x"}))
	refresh(t, s)

	// The writer renames the full file and starts a new one with the
	// start record again. More lines were added before the rename.
	appendLines(t, current, requestRecord("b", "run1", t0, "", 10, at{930100, "ARGS:x"}))
	rotated := filepath.Join(dir, record.RotatedPrefix+"20261023T120000.000000000Z.jsonl")
	if err := os.Rename(current, rotated); err != nil {
		t.Fatal(err)
	}
	appendLines(t, current, startRecord("run1", t0, "sha256:one"), requestRecord("c", "run1", t0, "", 10, at{930100, "ARGS:x"}))
	refresh(t, s)

	if got := ids(s); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("entries = %v", got)
	}
	if len(s.runs) != 1 {
		t.Errorf("the repeated start record made runs %v", s.runs)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.load(id); err != nil {
			t.Errorf("load(%s): %v", id, err)
		}
	}
	if names := []string{s.files[0].name, s.files[1].name}; names[0] != filepath.Base(rotated) || names[1] != record.CurrentFile {
		t.Errorf("files = %v", names)
	}

	// The oldest file is deleted when too many are kept: its records go.
	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}
	refresh(t, s)
	if got := ids(s); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("after the rotated file was deleted: entries %v", got)
	}
	if _, err := s.load("a"); err != errNotFound {
		t.Errorf("load of a deleted record: %v", err)
	}
}

func TestStoreRereadsReplacedFile(t *testing.T) {
	s, dir := newTestStore(t)
	current := filepath.Join(dir, record.CurrentFile)
	appendLines(t, current, requestRecord("a", "run1", t0, "", 10), requestRecord("b", "run1", t0, "", 10))
	refresh(t, s)
	// Something shorter is written in place of the file (same inode).
	if err := os.WriteFile(current, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	appendLines(t, current, requestRecord("c", "run1", t0, "", 10))
	refresh(t, s)
	if got := ids(s); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("entries = %v", got)
	}
}

func TestStoreCountsBrokenLines(t *testing.T) {
	s, dir := newTestStore(t)
	current := filepath.Join(dir, record.CurrentFile)
	appendLines(t, current, requestRecord("a", "run1", t0, "", 10))
	f, _ := os.OpenFile(current, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("not json\n{\"type\":\"other\"}\n{\"type\":\"request\"}\n")
	f.Close()
	appendLines(t, current, requestRecord("b", "run1", t0, "", 10))
	refresh(t, s)
	// The bad JSON, the unknown type and the request without an ID.
	if got := ids(s); !reflect.DeepEqual(got, []string{"a", "b"}) || s.broken != 3 {
		t.Fatalf("entries %v, broken %d", got, s.broken)
	}
}

func TestStoreLoadChecksTheLine(t *testing.T) {
	s, dir := newTestStore(t)
	current := filepath.Join(dir, record.CurrentFile)
	appendLines(t, current, requestRecord("a", "run1", t0, "", 10))
	refresh(t, s)
	line, err := s.load("a")
	if err != nil || !strings.Contains(string(line), `"id":"a"`) || strings.HasSuffix(string(line), "\n") {
		t.Fatalf("load = %q, %v", line, err)
	}
	// The same length at the same place, but another record.
	data, _ := os.ReadFile(current)
	os.WriteFile(current, []byte(strings.Replace(string(data), `"id":"a"`, `"id":"z"`, 1)), 0o600)
	if _, err := s.load("a"); err == nil {
		t.Fatal("load returned a line of another record")
	}
}

func TestOverview(t *testing.T) {
	s, dir := newTestStore(t)
	sampleRecords(t, dir)
	refresh(t, s)
	r, err := parseRange("1h", t0)
	if err != nil {
		t.Fatal(err)
	}
	o := s.overview(r)
	if o.Analysed != 100 || o.Recorded != 4 || o.Alerts != 2 || o.Incomplete != 1 {
		t.Errorf("analysed %d, recorded %d, alerts %d, incomplete %d", o.Analysed, o.Recorded, o.Alerts, o.Incomplete)
	}
	// 942100 fired in b and c, 930100 in a (twice, counted once); the
	// score rule is not listed.
	wantRules := []item{{"942100", "SQL injection", 2}, {"930100", "Path traversal and file access", 1}}
	if !reflect.DeepEqual(o.Rules, wantRules) {
		t.Errorf("top rules = %v", o.Rules)
	}
	wantLocations := []item{{Key: "ARGS:id", Count: 2}, {Key: "ARGS:file", Count: 1}, {Key: "REQUEST_URI_RAW", Count: 1}}
	if !reflect.DeepEqual(o.Locations, wantLocations) {
		t.Errorf("top locations = %v", o.Locations)
	}
	wantIPs := []item{{Key: "203.0.113.1", Count: 2}, {Key: "203.0.113.2", Count: 1}, {Key: "203.0.113.3", Count: 1}}
	if !reflect.DeepEqual(o.IPs, wantIPs) {
		t.Errorf("top IPs = %v", o.IPs)
	}
	if !o.LastRecord.Equal(t0.Add(-4 * time.Minute)) {
		t.Errorf("last record %v", o.LastRecord)
	}

	// One hour in bars of 2 minutes, starting on a round time.
	if o.BucketSecs != 120 || !o.Series[0].Start.Equal(t0.Add(-time.Hour)) || len(o.Series) != 31 {
		t.Fatalf("bucket %ds from %v, %d bars", o.BucketSecs, o.Series[0].Start, len(o.Series))
	}
	var records, alerts, analysed int
	for _, b := range o.Series {
		records += b.Records
		alerts += b.Alerts
		analysed += b.Analysed
	}
	if records != 4 || alerts != 2 || analysed != 100 {
		t.Errorf("the bars add up to %d records, %d alerts, %d analysed", records, alerts, analysed)
	}
	// a is 30 minutes before t0: bar 15 of the hour.
	if o.Series[15].Records != 1 || o.Series[15].Alerts != 1 {
		t.Errorf("bar 15 = %+v", o.Series[15])
	}

	// A range before everything shows nothing.
	o = s.overview(timeRange{Name: "test", From: t0.Add(-48 * time.Hour), To: t0.Add(-47 * time.Hour)})
	if o.Recorded != 0 || o.Analysed != 0 || len(o.Rules) != 0 {
		t.Errorf("an empty range has %d records, %d analysed", o.Recorded, o.Analysed)
	}
}

func TestBucketWidth(t *testing.T) {
	for _, tc := range []struct {
		span, want time.Duration
	}{
		{0, time.Minute},
		{30 * time.Minute, time.Minute},
		{time.Hour, 2 * time.Minute},        // 60 one-minute bars would be more than 48
		{24 * time.Hour, 30 * time.Minute},  // exactly 48
		{7 * 24 * time.Hour, 6 * time.Hour}, // 3 h would make 56
		{365 * 24 * time.Hour, 30 * 24 * time.Hour},
	} {
		if got := bucketWidth(tc.span); got != tc.want {
			t.Errorf("bucketWidth(%v) = %v, want %v", tc.span, got, tc.want)
		}
	}
}

func listIDs(t *testing.T, s *store, query string) []string {
	t.Helper()
	q, _ := url.ParseQuery(query)
	f, err := parseFilter(q, t0)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	var out []string
	for _, r := range s.list(f).Rows {
		out = append(out, r.ID)
	}
	return out
}

func TestFilters(t *testing.T) {
	s, dir := newTestStore(t)
	sampleRecords(t, dir)
	refresh(t, s)
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"", []string{"b", "a"}}, // alerts of the last 24 hours, newest first
		{"kind=all", []string{"d", "c", "b", "a"}},
		{"kind=incomplete", []string{"d"}},
		{"kind=all&rule=942100", []string{"c", "b"}},
		{"kind=all&group=Path+traversal+and+file+access", []string{"a"}},
		{"kind=all&ip=203.0.113.1", []string{"c", "a"}},
		{"kind=all&location=ARGS:id", []string{"c", "b"}},
		{"kind=all&min_score=5", []string{"b", "a"}},
		{"kind=all&range=1h&ip=+203.0.113.2+", []string{"b"}},
		{"kind=all&page=2", nil},
	} {
		if got := listIDs(t, s, tc.query); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: %v, want %v", tc.query, got, tc.want)
		}
	}
	for _, bad := range []string{"kind=some", "rule=x", "min_score=-1", "page=0", "range=2d"} {
		q, _ := url.ParseQuery(bad)
		if _, err := parseFilter(q, t0); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestListPages(t *testing.T) {
	s, dir := newTestStore(t)
	var lines []any
	for i := range 120 {
		lines = append(lines, requestRecord(strings.Repeat("x", i+1), "run1", t0.Add(-time.Duration(i)*time.Second), "", 10))
	}
	appendLines(t, filepath.Join(dir, record.CurrentFile), lines...)
	refresh(t, s)
	f := filter{Range: timeRange{To: t0}, Kind: "alerts", Page: 3}
	l := s.list(f)
	if l.Total != 120 || l.Pages != 3 || len(l.Rows) != 20 || l.Rows[0].ID != strings.Repeat("x", 101) {
		t.Fatalf("total %d, pages %d, rows %d", l.Total, l.Pages, len(l.Rows))
	}
}

func TestRulesAndEnginePages(t *testing.T) {
	s, dir := newTestStore(t)
	sampleRecords(t, dir)
	// A second run with another configuration.
	appendLines(t, filepath.Join(dir, record.CurrentFile), startRecord("run2", t0.Add(-time.Minute), "sha256:two"))
	refresh(t, s)

	r, _ := parseRange("all", t0)
	p := s.rulesPage(r)
	if p.Run != "run2" || len(p.Rules) != 4 {
		t.Fatalf("run %q with %d rules", p.Run, len(p.Rules))
	}
	fired := map[int]int{}
	for _, rule := range p.Rules {
		fired[rule.ID] = rule.Fired
	}
	if want := map[int]int{930100: 1, 942100: 2, 942101: 0, 949110: 2}; !reflect.DeepEqual(fired, want) {
		t.Errorf("fired = %v", fired)
	}
	if p.Rules[1].Group != "SQL injection" {
		t.Errorf("group = %q", p.Rules[1].Group)
	}

	e := s.enginePage()
	if e.Latest == nil || e.Latest.Run != "run2" || e.Active != 3 || e.Excluded != 1 {
		t.Fatalf("latest %+v, active %d, excluded %d", e.Latest, e.Active, e.Excluded)
	}
	if len(e.Runs) != 2 || e.Runs[0].Run != "run2" || e.Runs[1].Engine.Config != "sha256:one" {
		t.Errorf("runs = %+v", e.Runs)
	}
	if e.Records != 4 || len(e.Files) != 1 || e.Files[0].Name != record.CurrentFile || e.Files[0].Size == 0 {
		t.Errorf("records %d, files %+v", e.Records, e.Files)
	}
	if !e.Oldest.Equal(t0.Add(-30*time.Minute)) || !e.Newest.Equal(t0.Add(-4*time.Minute)) {
		t.Errorf("oldest %v, newest %v", e.Oldest, e.Newest)
	}
}

func TestFileGroup(t *testing.T) {
	for file, want := range map[string]string{
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "SQL injection",
		"REQUEST-901-INITIALIZATION.conf":          "Setup",
		"REQUEST-999-SOMETHING.conf":               "Other",
		"local.conf":                               "Other",
	} {
		if got := fileGroup(file); got != want {
			t.Errorf("fileGroup(%q) = %q, want %q", file, got, want)
		}
	}
}

// ---- The server ----

type testDashboard struct {
	srv      *Server
	h        http.Handler
	clock    *clock
	cfg      Config
	password string
}

// newDashboard is a dashboard over dir (a new one when ""), with the user
// "admin".
func newDashboard(t *testing.T, dir string) *testDashboard {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	cfg := Config{Listen: "127.0.0.1:0", RecordsDir: dir, StateDir: t.TempDir(), SessionIdleMinutes: 60}
	password, err := AddUser(cfg.StateDir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	c := newClock()
	srv, err := newServer(cfg, io.Discard, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return &testDashboard{srv: srv, h: srv.Handler(), clock: c, cfg: cfg, password: password}
}

// do sends one request to the handler, with the session cookie when given.
func (d *testDashboard) do(method, target string, form url.Values, session *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://127.0.0.1"+target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	if session != nil {
		r.AddCookie(session)
	}
	w := httptest.NewRecorder()
	d.h.ServeHTTP(w, r)
	return w
}

// login logs in and returns the session cookie.
func (d *testDashboard) login(t *testing.T, user, password string) *http.Cookie {
	t.Helper()
	w := d.do("POST", "/login", url.Values{"user": {user}, "password": {password}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("%s: %v", w.Body, err)
	}
}

func TestAPIAnswers(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)

	var o overview
	decode(t, d.do("GET", "/api/overview?range=1h", nil, session), &o)
	if o.Recorded != 4 || o.Alerts != 2 {
		t.Errorf("overview: %d records, %d alerts", o.Recorded, o.Alerts)
	}
	var l list
	decode(t, d.do("GET", "/api/alerts?kind=all&rule=942100", nil, session), &l)
	if l.Total != 2 || l.Rows[0].ID != "c" || l.Rows[0].IP != "203.0.113.1" {
		t.Errorf("alerts: %+v", l)
	}
	var rec record.Request
	w := d.do("GET", "/api/records/a", nil, session)
	decode(t, w, &rec)
	if w.Code != 200 || rec.ID != "a" || len(rec.Findings) != 3 || rec.Client.IP != "203.0.113.1" {
		t.Errorf("record: %d %+v", w.Code, rec)
	}
	if w := d.do("GET", "/api/records/nothing", nil, session); w.Code != http.StatusNotFound {
		t.Errorf("unknown record: %d", w.Code)
	}
	if w := d.do("GET", "/api/alerts?kind=some", nil, session); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "kind") {
		t.Errorf("bad filter: %d %s", w.Code, w.Body)
	}
	if w := d.do("GET", "/api/rules?range=5y", nil, session); w.Code != http.StatusBadRequest {
		t.Errorf("bad range: %d", w.Code)
	}
	var e enginePage
	decode(t, d.do("GET", "/api/engine", nil, session), &e)
	if e.Latest == nil || e.Latest.Run != "run1" {
		t.Errorf("engine: %+v", e)
	}
	for _, page := range []string{"/", "/alerts", "/alerts/a", "/rules", "/engine"} {
		w := d.do("GET", page, nil, session)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `data-page=`) || !strings.Contains(w.Body.String(), "admin") {
			t.Errorf("%s: %d", page, w.Code)
		}
	}
	if w := d.do("GET", "/nothing", nil, session); w.Code != http.StatusNotFound {
		t.Errorf("unknown page with a login: %d", w.Code)
	}
}

func TestDashboardSeesNewRecords(t *testing.T) {
	dir := t.TempDir()
	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)
	appendLines(t, filepath.Join(dir, record.CurrentFile), requestRecord("late", "run1", t0, "", 10))
	if err := d.srv.store.refresh(); err != nil {
		t.Fatal(err)
	}
	var l list
	decode(t, d.do("GET", "/api/alerts", nil, session), &l)
	if l.Total != 1 || l.Rows[0].ID != "late" {
		t.Errorf("alerts: %+v", l)
	}
}

func TestNewServerNeedsRecordsAndUser(t *testing.T) {
	cfg := Config{Listen: "127.0.0.1:0", RecordsDir: filepath.Join(t.TempDir(), "missing"), StateDir: t.TempDir(), SessionIdleMinutes: 60}
	if _, err := New(cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing records directory: %v", err)
	}
	cfg.RecordsDir = t.TempDir()
	if _, err := New(cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "-add-user") {
		t.Errorf("no user: %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(text string) string {
		path := filepath.Join(dir, "dashboard.json")
		os.WriteFile(path, []byte(text), 0o600)
		return path
	}
	cfg, err := LoadConfig(write(`{"records_dir": "../records", "state_dir": "/var/lib/ids"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Listen: DefaultListen, RecordsDir: filepath.Join(filepath.Dir(dir), "records"), StateDir: "/var/lib/ids", SessionIdleMinutes: DefaultIdleMinutes}
	if cfg != want {
		t.Errorf("config = %+v, want %+v", cfg, want)
	}
	for _, bad := range []string{
		`{"records_dir": "r", "state_dir": "s", "listen": "dashboard.example.com:8443"}`,
		`{"records_dir": "r", "state_dir": "s", "listen": "127.0.0.1"}`,
		`{"records_dir": "r", "state_dir": "s", "listen": "127.0.0.1:0"}`,
		`{"records_dir": "r", "state_dir": "s", "listen": "127.0.0.1:70000"}`,
		`{"state_dir": "s"}`,
		`{"records_dir": "r"}`,
		`{"records_dir": "r", "state_dir": "s", "tls_cert": "c.pem"}`,
		`{"records_dir": "r", "state_dir": "s", "session_idle_minutes": 2000}`,
		`{"records_dir": "r", "state_dir": "s", "session_idle_minutes": -1}`,
		`{"records_dir": "r", "state_dir": "s", "colour": "blue"}`,
		`{"records_dir": "r", "state_dir": "s"} {}`,
	} {
		if _, err := LoadConfig(write(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
	for _, good := range []string{
		`{"records_dir": "r", "state_dir": "s", "listen": "localhost:8443"}`,
		`{"records_dir": "r", "state_dir": "s", "listen": "[::1]:8443"}`,
		`{"records_dir": "r", "state_dir": "s", "listen": "0.0.0.0:8443"}`,
		`{"records_dir": "r", "state_dir": "s", "tls_cert": "c.pem", "tls_key": "k.pem"}`,
	} {
		if _, err := LoadConfig(write(good)); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
}
