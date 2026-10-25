package record

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// testRules match the same attack in every place a secret can be: a
// parameter, a cookie, the Authorization header, and the whole query string
// and body, which hold the secret parameters too.
const testRules = `
SecComponentSignature "TEST/1"
SecAction "id:1,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_inbound_anomaly_score=0,setvar:tx.sql_injection_score=0"
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS:Authorization "@rx (?i)union\s+select" "id:2,phase:2,log,pass,capture,severity:'CRITICAL',tag:'attack-sqli',msg:'SQL in %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',setvar:tx.sql_injection_score=+5,setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule QUERY_STRING|REQUEST_BODY "@rx union" "id:3,phase:2,log,pass,t:lowercase,msg:'Union in the whole text',logdata:'%{MATCHED_VAR}'"
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap" "id:4,phase:1,log,pass,msg:'Scanner'"
`

func loadRules(t testing.TB) *engine.RuleSet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(path, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := engine.Load(engine.Config{Files: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

var testEngine = Engine{Version: "test", CRS: "TEST/1", ParanoiaLevel: 1, Config: "sha256:test"}

func testBuilder(full bool) builder {
	return builder{masker: newMasker([]string{"pin_code"}, []byte("key")), full: full, engine: testEngine}
}

// Every secret below contains "S3CR3T", which must not appear anywhere in a
// record. Each one also carries the attack, so that rules match right at
// the secret.
func secretRequest() *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{
		Method:     "POST",
		Target:     "/login?q=1+union+select+2&password=S3CR3T-1+union+select&api_key=S3CR3T-2+union+select",
		Version:    "HTTP/1.1",
		RemoteAddr: "203.0.113.7",
		RemotePort: 51234,
		LocalAddr:  "10.0.0.5",
		LocalPort:  443,
		Headers: []httpmodel.Header{
			{Name: "Host", Value: "shop.example.com"},
			{Name: "User-Agent", Value: "sqlmap/1.8"},
			{Name: "Referer", Value: "https://shop.example.com/reset?token=S3CR3T-3&page=2"},
			{Name: "Cookie", Value: "sid=S3CR3T-4 union select 1; lang=en"},
			{Name: "Authorization", Value: "Bearer S3CR3T-5 union select"},
			{Name: "X-Forwarded-For", Value: "198.51.100.1"},
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
		},
		Body: []byte("user=ali&pwd=S3CR3T-6+union+select&pin_code=S3CR3T-7+union+select&note=hello"),
	})
}

func build(t *testing.T, req *httpmodel.Request, full bool) (Request, []byte) {
	t.Helper()
	res := loadRules(t).Evaluate(req)
	rec := testBuilder(full).build(res.Request, res, nil, "id1", "run1", time.Date(2026, 10, 23, 10, 15, 2, 0, time.UTC))
	line, err := marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, line
}

// R4: who sent the request and where it went are kept; secrets are not.
func TestRecordKeepsDetailsAndMasksSecrets(t *testing.T) {
	rec, line := build(t, secretRequest(), true)
	if strings.Contains(string(line), "S3CR3T") {
		t.Fatalf("a secret is in the record:\n%s", line)
	}

	if rec.Client != (Client{IP: "203.0.113.7", Port: 51234}) {
		t.Errorf("client = %+v", rec.Client)
	}
	if rec.Server != (Server{Host: "shop.example.com", IP: "10.0.0.5", Port: 443}) {
		t.Errorf("server = %+v", rec.Server)
	}
	wantHTTP := HTTP{
		Method:      "POST",
		Path:        "/login",
		Query:       "q=1+union+select+2&password=[masked]&api_key=[masked]",
		Version:     "HTTP/1.1",
		UserAgent:   "sqlmap/1.8",
		Referer:     "https://shop.example.com/reset?token=[masked]&page=2",
		ContentType: "application/x-www-form-urlencoded",
		BodyLength:  len(secretRequest().Received.Body),
		HeaderNames: []string{"Host", "User-Agent", "Referer", "Cookie", "Authorization", "X-Forwarded-For", "Content-Type"},
		Cookies: []Cookie{
			{Name: "sid", Hash: testBuilder(false).cookieHash("S3CR3T-4 union select 1")},
			{Name: "lang", Hash: testBuilder(false).cookieHash("en")},
		},
	}
	if !reflect.DeepEqual(rec.HTTP, wantHTTP) {
		t.Errorf("request = %+v\nwant      %+v", rec.HTTP, wantHTTP)
	}
	if !rec.Alert || rec.DecidedBy != DecidedBy || rec.Engine != testEngine || rec.ID != "id1" || rec.Run != "run1" {
		t.Errorf("alert %v by %q, engine %+v, id %q, run %q", rec.Alert, rec.DecidedBy, rec.Engine, rec.ID, rec.Run)
	}

	byLocation := map[string]Finding{}
	for _, f := range rec.Findings {
		byLocation[f.Location] = f
	}
	// A normal parameter: the matched part is kept.
	if f := byLocation["ARGS:q"]; f.Matched != "1 union select 2" || f.Data != "Matched Data: union select found within ARGS:q: 1 union select 2" || f.Message != "SQL in ARGS:q: 1 union select 2" {
		t.Errorf("ARGS:q finding = %+v", f)
	}
	// Secret places: the rule and the place are kept, the value is not.
	for _, loc := range []string{"ARGS:password", "ARGS:api_key", "ARGS:pwd", "ARGS:pin_code", "REQUEST_COOKIES:sid", "REQUEST_HEADERS:Authorization"} {
		f, ok := byLocation[loc]
		if !ok {
			t.Errorf("no finding at %s; findings: %+v", loc, rec.Findings)
			continue
		}
		if f.RuleID != 2 || f.Matched != Masked || f.Data != Masked || f.Message != result.Hidden {
			t.Errorf("%s finding = %+v", loc, f)
		}
	}
	// The whole query string holds the secrets; they are cut out of it.
	if f := byLocation["QUERY_STRING"]; f.Matched != "q=1+union+select+2&password=[masked]&api_key=[masked]" {
		t.Errorf("QUERY_STRING finding = %+v", f)
	}
	if f := byLocation["REQUEST_BODY"]; f.Matched != "user=ali&pwd=[masked]&pin_code=[masked]&note=hello" {
		t.Errorf("REQUEST_BODY finding = %+v", f)
	}

	// full_requests: all headers and the body, still without secrets.
	if rec.Full == nil {
		t.Fatal("no full request for an alert with full_requests")
	}
	if got := rec.Full.Headers[3]; got != [2]string{"Cookie", Masked} {
		t.Errorf("cookie header = %v", got)
	}
	if got := rec.Full.Headers[5]; got != [2]string{"X-Forwarded-For", "198.51.100.1"} {
		t.Errorf("X-Forwarded-For header = %v", got)
	}
	if rec.Full.Body != "user=ali&pwd=[masked]&pin_code=[masked]&note=hello" {
		t.Errorf("full body = %q", rec.Full.Body)
	}
}

// The client address is the connection's, never X-Forwarded-For: anyone
// can write that header, and a block based on it would hit whoever the
// attacker names.
func TestClientIsNotTakenFromHeaders(t *testing.T) {
	req := httpmodel.New(httpmodel.Received{
		Method:  "GET",
		Target:  "/?q=1+union+select+2",
		Headers: []httpmodel.Header{{Name: "X-Forwarded-For", Value: "198.51.100.1"}, {Name: "X-Real-IP", Value: "198.51.100.2"}},
	})
	rec, _ := build(t, req, false)
	if rec.Client != (Client{}) {
		t.Errorf("client = %+v", rec.Client)
	}
}

// Without full_requests, and for a request that is not an alert, there is
// no full request.
func TestNoFullRequestByDefault(t *testing.T) {
	if rec, _ := build(t, secretRequest(), false); rec.Full != nil {
		t.Error("full request without full_requests")
	}
	req := httpmodel.New(httpmodel.Received{Method: "GET", Target: "/", Headers: []httpmodel.Header{{Name: "User-Agent", Value: "sqlmap"}}})
	rec, _ := build(t, req, true)
	if rec.Alert || rec.Full != nil || len(rec.Findings) != 1 {
		t.Errorf("alert %v, full %v, findings %+v", rec.Alert, rec.Full, rec.Findings)
	}
}

// R1: a record for a finding or an incomplete analysis, not for a clean
// request.
func TestWanted(t *testing.T) {
	rs := loadRules(t)
	for _, tt := range []struct {
		name string
		rec  httpmodel.Received
		want bool
	}{
		{"clean", httpmodel.Received{Method: "GET", Target: "/?q=books"}, false},
		{"finding below the threshold", httpmodel.Received{Method: "GET", Target: "/", Headers: []httpmodel.Header{{Name: "User-Agent", Value: "sqlmap"}}}, true},
		{"incomplete", httpmodel.Received{Method: "POST", Target: "/", Headers: []httpmodel.Header{{Name: "Content-Type", Value: "application/json"}}, Body: []byte("{bad")}, true},
	} {
		req := httpmodel.New(tt.rec)
		res := rs.Evaluate(req)
		if got := Wanted(res.Request, res, nil); got != tt.want {
			t.Errorf("%s: Wanted = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSecretName(t *testing.T) {
	m := newMasker([]string{"Pin_Code"}, nil)
	for name, want := range map[string]bool{
		"password": true, "user_Password": true, "pwd": true, "PHPSESSID": true, "jsessionid": true,
		"access_token": true, "X-CSRF": true, "apiKey": true, "card_number": true, "cvv2": true,
		"json.user.password": true, "pin_code": true,
		"q": false, "name": false, "id": false, "page": false, "email": false,
	} {
		if got := m.secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v", name, got, want)
		}
	}
	for loc, want := range map[string]bool{
		"ARGS:password": true, "ARGS_GET:token": true, "ARGS_POST:pwd": true, "REQUEST_COOKIES:lang": true,
		"REQUEST_HEADERS:authorization": true, "REQUEST_HEADERS:Cookie": true,
		"ARGS:q": false, "ARGS_NAMES:password": false, "REQUEST_HEADERS:User-Agent": false, "REQUEST_COOKIES_NAMES:sid": false,
	} {
		if got := m.secretLocation(loc); got != want {
			t.Errorf("secretLocation(%q) = %v, want %v", loc, got, want)
		}
	}
}

func TestMaskQuery(t *testing.T) {
	m := newMasker(nil, nil)
	for in, want := range map[string]string{
		"":                         "",
		"a=1&b=2":                  "a=1&b=2",
		"user=ali&password=x":      "user=ali&password=[masked]",
		"pass%77ord=x&a=":          "pass%77ord=[masked]&a=",
		"token&x=1":                "token&x=1", // a name without a value
		"a=1&&Session=abc=def&b=2": "a=1&&Session=[masked]&b=2",
		"%zz=1&pwd=2":              "%zz=1&pwd=[masked]",
	} {
		if got := m.maskQuery(in); got != want {
			t.Errorf("maskQuery(%q) = %q, want %q", in, got, want)
		}
	}
	if got := m.maskURL("https://a.example/x?token=1&b=2#f"); got != "https://a.example/x?token=[masked]&b=2#f" {
		t.Errorf("maskURL = %q", got)
	}
}

func TestCut(t *testing.T) {
	for _, tt := range []struct {
		in   string
		max  int
		want string
	}{
		{"abc", 3, "abc"},
		{"abcd", 3, "abc…"},
		{"aşb", 2, "a…"}, // "ş" is two bytes and is not split
		{"aşb", 3, "aş…"},
		{"", 0, ""},
	} {
		if got := cut(tt.in, tt.max); got != tt.want {
			t.Errorf("cut(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}

// A long payload is cut, and the cut does not let a secret through.
func TestLongValuesAreCut(t *testing.T) {
	long := strings.Repeat("A", 5000) + " union select 1"
	req := httpmodel.New(httpmodel.Received{Method: "GET", Target: "/" + strings.Repeat("p", 3000) + "?q=" + long + "&password=" + strings.Repeat("S3CR3T", 100)})
	rec, line := build(t, req, false)
	if strings.Contains(string(line), "S3CR3T") {
		t.Fatal("a secret is in the record")
	}
	if len(rec.HTTP.Path) > maxPath+len("…") || !strings.HasSuffix(rec.HTTP.Path, "…") {
		t.Errorf("path of %d bytes", len(rec.HTTP.Path))
	}
	for _, f := range rec.Findings {
		if len(f.Matched) > maxMatched+len("…") || len(f.Data) > maxMatched+len("…") {
			t.Errorf("finding %d at %s: matched %d bytes, data %d bytes", f.RuleID, f.Location, len(f.Matched), len(f.Data))
		}
	}
}

func TestCookieHash(t *testing.T) {
	a, b := newMasker(nil, []byte("one")), newMasker(nil, []byte("two"))
	if a.cookieHash("x") != a.cookieHash("x") {
		t.Error("the same value gives different hashes")
	}
	if a.cookieHash("x") == a.cookieHash("y") || a.cookieHash("x") == b.cookieHash("x") {
		t.Error("different values or keys give the same hash")
	}
	if h := a.cookieHash("x"); len(h) != 12 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Errorf("hash = %q", h)
	}
}

// readLines returns the lines of a record file, each decoded into a map.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: line %d: %v", path, len(lines)+1, err)
		}
		lines = append(lines, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// clock is a time that tests move forward by hand.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A run writes a start record, the records of R1, and counts once a minute
// and at the end.
func TestRecorder(t *testing.T) {
	rs := loadRules(t)
	dir := filepath.Join(t.TempDir(), "records")
	c := &clock{t: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)}
	r, err := open(Config{Dir: dir}, testEngine, rs.Statuses(), nil, c.now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(rec httpmodel.Received) {
		res := rs.Evaluate(httpmodel.New(rec))
		if err := r.Add(res.Request, res, nil); err != nil {
			t.Fatal(err)
		}
	}
	add(httpmodel.Received{Method: "GET", Target: "/?q=1+union+select+2"}) // alert
	add(httpmodel.Received{Method: "GET", Target: "/?q=books"})            // clean: counted only
	c.add(61 * time.Second)
	add(httpmodel.Received{Method: "POST", Target: "/", Headers: []httpmodel.Header{{Name: "Content-Type", Value: "application/json"}}, Body: []byte("{bad")})
	c.add(time.Second)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, filepath.Join(dir, CurrentFile))
	var types []string
	for _, l := range lines {
		types = append(types, l["type"].(string))
		if l["schema"] != float64(Schema) {
			t.Errorf("line %v has schema %v", l["type"], l["schema"])
		}
		if l["run"] != r.Run() {
			t.Errorf("line %v has run %v, want %v", l["type"], l["run"], r.Run())
		}
	}
	if want := []string{"start", "request", "request", "counts", "counts"}; !reflect.DeepEqual(types, want) {
		t.Fatalf("types = %v, want %v", types, want)
	}
	rules := lines[0]["rules"].([]any)
	if len(rules) != len(rs.Statuses()) {
		t.Fatalf("start lists %d rules, want %d", len(rules), len(rs.Statuses()))
	}
	// A rule's msg as written in testRules, macros unexpanded; rule 1 has none.
	if _, ok := rules[0].(map[string]any)["msg"]; ok {
		t.Errorf("rule 1 has a msg: %v", rules[0])
	}
	if msg := rules[1].(map[string]any)["msg"]; msg != "SQL in %{MATCHED_VAR_NAME}: %{MATCHED_VAR}" {
		t.Errorf("msg of rule 2 = %v", msg)
	}
	first, last := lines[3], lines[4]
	if first["analysed"] != 3.0 || first["recorded"] != 2.0 || first["alerts"] != 1.0 || first["incomplete"] != 1.0 {
		t.Errorf("first counts = %v", first)
	}
	if first["from"] != "2026-10-23T10:00:00Z" || first["to"] != "2026-10-23T10:01:01Z" {
		t.Errorf("first counts window = %v to %v", first["from"], first["to"])
	}
	if last["analysed"] != 0.0 || last["from"] != "2026-10-23T10:01:01Z" || last["to"] != "2026-10-23T10:01:02Z" {
		t.Errorf("last counts = %v", last)
	}
	if lines[1]["alert"] != true || lines[2]["alert"] != false {
		t.Errorf("alerts = %v, %v", lines[1]["alert"], lines[2]["alert"])
	}
}

// Records hold IP addresses and parts of requests: only the user running
// the IDS may read them. The hash key is made once and kept.
func TestFilesArePrivateAndKeyIsKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	r, err := Open(Config{Dir: dir}, testEngine, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := r.b.key
	r.Close()
	for _, tt := range []struct {
		name string
		mode os.FileMode
	}{{"", 0o700}, {CurrentFile, 0o600}, {KeyFile, 0o600}} {
		info, err := os.Stat(filepath.Join(dir, tt.name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != tt.mode {
			t.Errorf("%q has mode %v, want %v", tt.name, got, tt.mode)
		}
	}
	r, err = Open(Config{Dir: dir}, testEngine, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !reflect.DeepEqual(r.b.key, key) || len(key) != 32 {
		t.Error("the key changed between runs")
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, KeyFile), []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Dir: bad}, testEngine, nil, nil); err == nil || !strings.Contains(err.Error(), KeyFile) {
		t.Errorf("a broken key file gives %v", err)
	}
}

// R5: a full file is renamed and a new one started with the start record;
// only keep files remain.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)}
	w, err := openWriter(dir, 300, 3, c.now)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]string{"type": "start"}
	if err := w.setHeader(header); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		c.add(time.Second)
		if err := w.write(map[string]any{"type": "request", "n": i, "pad": strings.Repeat("x", 50)}); err != nil {
			t.Fatal(err)
		}
	}
	w.close()

	rotated, err := RotatedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 2 {
		t.Fatalf("rotated files = %v, want 2 (3 with the current one)", rotated)
	}
	last := -1
	for _, name := range append(rotated, CurrentFile) {
		path := filepath.Join(dir, name)
		info, _ := os.Stat(path)
		if info.Size() > 300 {
			t.Errorf("%s has %d bytes", name, info.Size())
		}
		lines := readLines(t, path)
		if lines[0]["type"] != "start" {
			t.Errorf("%s starts with %v", name, lines[0])
		}
		for _, l := range lines[1:] {
			n := int(l["n"].(float64))
			if n != last+1 && last != -1 {
				t.Errorf("%s: record %d follows %d", name, n, last)
			}
			last = n
		}
	}
	if last != 39 {
		t.Errorf("the newest record is %d, want 39", last)
	}
}

// Many goroutines can write at once; every line stays whole (run with
// -race).
func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	w, err := openWriter(dir, 1<<20, 2, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				if err := w.write(map[string]int{"g": g, "i": i}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	w.close()
	if n := len(readLines(t, filepath.Join(dir, CurrentFile))); n != 1600 {
		t.Errorf("%d lines, want 1600", n)
	}
}

func TestConfigValidate(t *testing.T) {
	for _, tt := range []struct {
		cfg  Config
		want string
	}{
		{Config{Dir: "r"}, ""},
		{Config{}, "dir is missing"},
		{Config{Dir: "r", MaxFileMB: 2000}, "max_file_mb"},
		{Config{Dir: "r", KeepFiles: -1}, "keep_files"},
		{Config{Dir: "r", SecretNames: []string{" "}}, "empty name"},
	} {
		err := tt.cfg.Validate()
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%+v: error %v, want %q", tt.cfg, err, tt.want)
		}
	}
	if got := (Config{Dir: "r"}).WithDefaults(); got.MaxFileMB != DefaultMaxFileMB || got.KeepFiles != DefaultKeepFiles {
		t.Errorf("defaults = %+v", got)
	}
}

// TestShortSecretsInWholeTexts: a secret shorter than minSecretLength,
// such as a three-digit card code, is not removed from text in general,
// but a text that holds the whole query or body holds every parameter, so
// it is removed there.
func TestShortSecretsInWholeTexts(t *testing.T) {
	for _, tc := range []struct {
		name, target, contentType, body string
		// wholeFinding: a rule matches the whole query or body. A JSON
		// body is read as fields only, so there the full body is the
		// whole text.
		wholeFinding bool
	}{
		{"query", "/pay?cvv=731&q=1+union+select+2", "", "", true},
		{"form", "/pay", "application/x-www-form-urlencoded", "cvv=731&q=1+union+select+2", true},
		{"json", "/pay", "application/json", `{"cvv": "731", "q": "1 union select 2"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := []httpmodel.Header{{Name: "Host", Value: "shop.example.com"}}
			if tc.contentType != "" {
				headers = append(headers, httpmodel.Header{Name: "Content-Type", Value: tc.contentType})
			}
			req := httpmodel.New(httpmodel.Received{Method: "POST", Target: tc.target, Version: "HTTP/1.1", Headers: headers, Body: []byte(tc.body)})
			rec, line := build(t, req, true)
			whole := 0
			for _, f := range rec.Findings {
				if f.Location == "QUERY_STRING" || f.Location == "REQUEST_BODY" {
					whole++
				}
			}
			if tc.wholeFinding && whole == 0 {
				t.Fatalf("no finding in the whole query or body: %s", line)
			}
			if rec.Full == nil || !strings.Contains(rec.Full.Body+fmt.Sprint(rec.Findings), "cvv") {
				t.Fatalf("the test request lost its card code field: %s", line)
			}
			if strings.Contains(string(line), "731") {
				t.Errorf("the card code is in the record:\n%s", line)
			}
		})
	}
}
