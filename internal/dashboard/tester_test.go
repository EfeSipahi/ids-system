package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// The configurations of the repository, as configs/dashboard.json lists
// them.
var (
	crsFirst  = "../../configs/crs-first-engine.json"
	csicShop  = "../../configs/csic-shop.json"
	crsTests  = "../../testdata/crs-tests.json"
	crsFolder = "../../testdata/requests/crs"
)

func newTestTester(t *testing.T, configs ...string) *tester {
	t.Helper()
	tt, err := newTester("", configs, crsFolder, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return tt
}

func ruleIDs(a result.Analysed) []int {
	var ids []int
	for _, f := range a.Findings {
		if !slices.Contains(ids, f.RuleID) {
			ids = append(ids, f.RuleID)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestBuiltInExamples: each built-in example finds what its name says,
// with the product configuration at level 1. The rules are those
// ids-offline found for internal/dashboard/web/examples.json.
func TestBuiltInExamples(t *testing.T) {
	tt := newTestTester(t, crsFirst)
	want := map[string][]int{
		"A normal request: no rule should match":    nil,
		"SQL injection in the query":                {942100, 942190, 942270, 942360, 949110},
		"Cross-site scripting (XSS) in a form body": {941100, 941110, 941160, 941180, 941390, 949110},
		"Path traversal to a system file":           {930100, 930110, 930120, 932160, 949110},
		"Command injection after a host name":       {930120, 932160, 949110},
		"SQL injection inside a JSON body":          {942100, 949110},
		"A PHP file uploaded in a multipart form":   {933110, 949110},
		"A scanner's User-Agent":                    {913100, 949110},
		"An HTTP version that is not allowed":       {920430, 949110},
		"A GET request with a body":                 {920170, 949110},
	}
	if len(tt.examples) != len(want) {
		t.Fatalf("%d built-in examples, want %d", len(tt.examples), len(want))
	}
	for _, ex := range tt.examples {
		ids, ok := want[ex.Name]
		if !ok || !ex.Writable {
			t.Errorf("%q: unknown or not writable", ex.Name)
			continue
		}
		a, err := tt.run(context.Background(), testRequest{Text: ex.Text, BodyCRLF: ex.BodyCRLF}, "")
		if err != nil {
			t.Errorf("%s: %v", ex.Name, err)
			continue
		}
		if got := ruleIDs(a.Result); !slices.Equal(got, ids) {
			t.Errorf("%s: rules %v, want %v", ex.Name, got, ids)
		}
		if a.Result.Score.Exceeded != (ids != nil) {
			t.Errorf("%s: alert %v", ex.Name, a.Result.Score.Exceeded)
		}
		if a.ContentLength != nil {
			t.Errorf("%s: Content-Length note %+v", ex.Name, a.ContentLength)
		}
	}
}

// TestTabMatchesOffline (plan verification 3): every example request of the
// repository, written as raw text and tested in the tab, gives what the
// analysis of ids-offline gives for it from its file: the CRS tests with
// the configuration they are written for, where every expectation must be
// met, and the other example files with the CSIC shop's configuration, so
// that the applications and profiles take part. The requests raw text
// can't hold (offline.Raw) are left out.
func TestTabMatchesOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("analyses every example request twice")
	}
	tt := newTestTester(t, crsTests, csicShop)
	other, err := filepath.Glob("../../testdata/requests/*.json")
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob("../../testdata/requests/generated/*.json")
	if err != nil {
		t.Fatal(err)
	}
	crs, err := filepath.Glob(crsFolder + "/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []struct {
		config int
		path   string
		files  []string
		expect bool
	}{
		{0, crsTests, crs, true},
		{1, csicShop, append(other, more...), false},
	} {
		cfg, err := config.Load(set.path)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := engine.Load(cfg.Config)
		if err != nil {
			t.Fatal(err)
		}
		apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
		if err != nil {
			t.Fatal(err)
		}
		compared, skipped, unmet := 0, 0, 0
		for _, file := range set.files {
			examples, err := offline.LoadFileWith(file, cfg.Parsing())
			if err != nil {
				t.Fatal(err)
			}
			for _, ex := range examples {
				text, crlf, ok := offline.Raw(ex.Request.Received)
				if !ok {
					skipped++
					continue
				}
				app := apps.Match(ex.Request)
				res, prof := analysis.Run(rules, apps, ex.Request, app)
				want := result.NewAnalysed(res, prof, app, rules.ParanoiaLevel(), result.Options{ShowValues: true})
				a, err := tt.run(context.Background(), testRequest{Config: set.config, Text: text, BodyCRLF: crlf, Client: ex.Request.Received.RemoteAddr}, "")
				if err != nil {
					t.Errorf("%s: %v", ex.Name, err)
					continue
				}
				compared++
				if !reflect.DeepEqual(a.Result, want) {
					g, _ := json.Marshal(a.Result)
					w, _ := json.Marshal(want)
					t.Errorf("%s: the tab gives\n%s\nids-offline gives\n%s", ex.Name, g, w)
				}
				if set.expect {
					matched := ruleIDs(a.Result)
					for _, id := range ex.ExpectIDs {
						if !slices.Contains(matched, id) {
							unmet++
							t.Errorf("%s: rule %d was expected and did not match", ex.Name, id)
						}
					}
					for _, id := range ex.NoExpectIDs {
						if slices.Contains(matched, id) {
							unmet++
							t.Errorf("%s: rule %d matched and must not", ex.Name, id)
						}
					}
				}
			}
		}
		t.Logf("%s: %d requests compared, %d not writable as text, %d expectations not met", filepath.Base(set.path), compared, skipped, unmet)
	}
}

// writeConfig writes a product configuration with the rule files of the
// repository's, by absolute paths, at the given paranoia level.
func writeConfig(t *testing.T, path string, level int) {
	t.Helper()
	data, err := os.ReadFile(crsFirst)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	dir, _ := filepath.Abs(filepath.Dir(crsFirst))
	files := cfg["files"].([]any)
	for i, f := range files {
		files[i] = filepath.Join(dir, f.(string))
	}
	delete(cfg, "records")
	cfg["paranoia_level"] = level
	out, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRuleSetsAreKeptAndReloaded (C2): a rule set is prepared once, kept
// at most maxRuleSets at a time, and prepared again when its files change.
func TestRuleSetsAreKeptAndReloaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.json")
	writeConfig(t, path, 1)
	c := newClock()
	tt, err := newTester("", []string{path}, "", c.now)
	if err != nil {
		t.Fatal(err)
	}
	text := "GET /?q=1 HTTP/1.1\nHost: a\n"
	first, err := tt.run(context.Background(), testRequest{Text: text}, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Level != 1 || first.Config.Level != 1 {
		t.Errorf("level %d, configuration's %d", first.Level, first.Config.Level)
	}
	kept := tt.sets[setKey{0, 0, ""}]
	if _, err := tt.run(context.Background(), testRequest{Text: text}, first.Config.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if tt.sets[setKey{0, 0, ""}] != kept {
		t.Error("the rule set was prepared again although nothing changed")
	}

	// A changed file is seen after recheckAfter.
	writeConfig(t, path, 2)
	same, _ := tt.run(context.Background(), testRequest{Text: text}, "")
	if same.Level != 1 {
		t.Errorf("level %d before recheckAfter, want the kept 1", same.Level)
	}
	c.advance(recheckAfter)
	changed, err := tt.run(context.Background(), testRequest{Text: text}, first.Config.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Level != 2 || changed.Config.Fingerprint == first.Config.Fingerprint || changed.Config.Newest {
		t.Errorf("after the change: level %d, fingerprint %s, newest %v", changed.Level, changed.Config.Fingerprint, changed.Config.Newest)
	}

	// Levels 1 to 4 and the configuration's own: five sets, four kept.
	for level := 1; level <= 4; level++ {
		a, err := tt.run(context.Background(), testRequest{Level: level, Text: text}, "")
		if err != nil {
			t.Fatal(err)
		}
		if a.Level != level {
			t.Errorf("level %d asked, %d used", level, a.Level)
		}
	}
	if len(tt.sets) != maxRuleSets {
		t.Errorf("%d rule sets kept, want %d", len(tt.sets), maxRuleSets)
	}
	if _, ok := tt.sets[setKey{0, 0, ""}]; ok {
		t.Error("the least recently used rule set was kept")
	}

	// A configuration that breaks is an error, and its set is dropped.
	os.WriteFile(path, []byte("{"), 0o600)
	c.advance(recheckAfter)
	_, err = tt.run(context.Background(), testRequest{Level: 4, Text: text}, "")
	var te *testError
	if !errors.As(err, &te) || te.status != 500 || !strings.Contains(te.msg, "product.json can't be loaded") {
		t.Errorf("broken configuration: %v", err)
	}
}

func TestTestErrors(t *testing.T) {
	tt := newTestTester(t, csicShop)
	ok := "GET / HTTP/1.1\nHost: localhost:8080\n"
	for _, tc := range []struct {
		tr   testRequest
		want string
	}{
		{testRequest{Config: 1, Text: ok}, "there is no configuration 1"},
		{testRequest{Config: -1, Text: ok}, "there is no configuration -1"},
		{testRequest{Level: 5, Text: ok}, "paranoia level 5"},
		{testRequest{Application: "shop2", Text: ok}, `has no application "shop2"`},
		{testRequest{Client: "localhost", Text: ok}, "is not an IP address"},
		{testRequest{Client: "fe80::1%eth0", Text: ok}, "is not an IP address"},
		{testRequest{Text: "GET / HTTP/1.1\nHost localhost"}, "line 2: a header is"},
		{testRequest{Text: ""}, "the request is empty"},
	} {
		_, err := tt.run(context.Background(), tc.tr, "")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.tr, err, tc.want)
		}
	}
	off := newTestTester(t)
	if _, err := off.run(context.Background(), testRequest{Text: ok}, ""); err == nil || !strings.Contains(err.Error(), "the test tab is off") {
		t.Errorf("no configurations: %v", err)
	}
}

// TestTestOptions: the level, the application and the client address
// reach the analysis; a wrong Content-Length is noted, not corrected.
func TestTestOptions(t *testing.T) {
	tt := newTestTester(t, csicShop)
	// A request of no application at level 1 (the configuration's), then
	// the same request checked against the shop, whose level is 2.
	text := "POST /other HTTP/1.1\nHost: elsewhere.example\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 99\n\na=1"
	none, err := tt.run(context.Background(), testRequest{Text: text, Client: "198.51.100.7"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if none.Result.Application == nil || none.Result.Application.Name != profile.NoApplication || none.Read.Application != "" {
		t.Errorf("by host: application %+v, read %q", none.Result.Application, none.Read.Application)
	}
	if none.Read.Client != "198.51.100.7" || none.Read.BodyLength != 3 || len(none.Read.Params) != 1 || none.Read.Params[0] != (testParam{Origin: "body", Name: "a", Value: "1"}) {
		t.Errorf("read: %+v", none.Read)
	}
	if none.ContentLength == nil || none.ContentLength.Declared != "99" || none.ContentLength.Body != 3 {
		t.Errorf("Content-Length note: %+v", none.ContentLength)
	}
	shop, err := tt.run(context.Background(), testRequest{Text: text, Application: "csic-shop"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if shop.Result.Application == nil || shop.Result.Application.Name != "csic-shop" || shop.Result.Application.ParanoiaLevel != 2 || shop.Read.Application != "csic-shop" {
		t.Errorf("forced: application %+v", shop.Result.Application)
	}
	if shop.Result.Profile == nil || len(shop.Result.Profile.Findings) == 0 {
		t.Errorf("forced: the shop's profile found nothing in /other: %+v", shop.Result.Profile)
	}
	four, err := tt.run(context.Background(), testRequest{Text: text, Level: 4}, "")
	if err != nil {
		t.Fatal(err)
	}
	if four.Level != 4 || four.Result.Application.ParanoiaLevel != 4 {
		t.Errorf("level 4: %d, application's %d", four.Level, four.Result.Application.ParanoiaLevel)
	}
}

// TestTestsWaitForASlot (C3): at most maxTests tests run at once; another
// waits, and gives up when its client goes away.
func TestTestsWaitForASlot(t *testing.T) {
	tt := newTestTester(t, crsFirst)
	for range maxTests {
		tt.slots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := tt.run(ctx, testRequest{Text: "GET / HTTP/1.1\n"}, ""); err != context.DeadlineExceeded {
		t.Errorf("all slots taken: %v", err)
	}
	<-tt.slots
	if _, err := tt.run(context.Background(), testRequest{Text: "GET / HTTP/1.1\n"}, ""); err != nil {
		t.Errorf("a slot free: %v", err)
	}
}

// TestTestFiles: the picker lists the CRS tests and opens only what the
// listing shows.
func TestTestFiles(t *testing.T) {
	tt := newTestTester(t, crsTests)
	files, err := tt.files()
	if err != nil {
		t.Fatal(err)
	}
	tests := 0
	for _, f := range files {
		tests += f.Tests
	}
	if len(files) != 290 || tests != 5072 {
		t.Errorf("%d files with %d tests, want 290 with 5,072", len(files), tests)
	}
	list, err := tt.fileExamples("944200")
	if err != nil {
		t.Fatal(err)
	}
	notWritable := 0
	for _, ex := range list {
		if !ex.Writable {
			notWritable++
			if ex.Text != "" {
				t.Errorf("%s: not writable, but has text", ex.Name)
			}
		}
	}
	if notWritable != 1 || len(list[0].ExpectIDs) == 0 {
		t.Errorf("944200: %d not writable, first expects %v", notWritable, list[0].ExpectIDs)
	}
	for _, name := range []string{"../crs-tests", "nothing", "944200.json", "", "."} {
		if _, err := tt.fileExamples(name); err != errNoSuchFile {
			t.Errorf("%q: %v", name, err)
		}
	}
}

// TestTestAPI: the routes, the size limit, a cross-origin post, and that a
// test writes nothing into the records folder.
func TestTestAPI(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	before := folderState(t, dir)
	d := newDashboard(t, dir)
	d.srv.test = newTestTester(t, crsFirst, crsTests)
	session := d.login(t, "admin", d.password)

	w := d.do("GET", "/api/test", nil, session)
	var p testPage
	decode(t, w, &p)
	if !p.Enabled || len(p.Configs) != 2 || p.Configs[0].Name != "crs-first-engine.json" || p.Configs[0].Level != 1 || p.Configs[1].Level != 4 ||
		p.Configs[0].Fingerprint == "" || len(p.Examples) != 10 || len(p.Files) != 290 || p.MaxText != maxTestText {
		t.Errorf("GET /api/test: %+v", p)
	}

	post := func(query, text string, headers ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://127.0.0.1/api/test?"+query, strings.NewReader(text))
		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		r.AddCookie(session)
		rw := httptest.NewRecorder()
		d.h.ServeHTTP(rw, r)
		return rw
	}
	attack := "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: a\n"
	w = post("config=0", attack, "Sec-Fetch-Site", "same-origin")
	var a testAnswer
	decode(t, w, &a)
	if w.Code != 200 || !a.Result.Score.Exceeded || a.Result.URI == "" {
		t.Errorf("POST: %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || strings.Contains(w.Body.String(), "<script>") {
		t.Errorf("the answer is %s and holds <script> as HTML could read it", ct)
	}
	if w := post("config=1&level=2&crlf=1", attack); w.Code != 200 {
		t.Errorf("config 1 level 2: %d %s", w.Code, w.Body)
	}
	if w := post("config=x", attack); w.Code != 400 {
		t.Errorf("config=x: %d", w.Code)
	}
	if w := post("", "GET / HTTP/1.1\nHost a\n"); w.Code != 400 || !strings.Contains(w.Body.String(), "line 2") {
		t.Errorf("broken text: %d %s", w.Code, w.Body)
	}
	if w := post("", attack, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", w.Code)
	}

	// 1 MiB is accepted; one byte more is refused before it is read.
	head := "POST /upload HTTP/1.1\nHost: a\nContent-Type: application/x-www-form-urlencoded\n\nnote="
	full := head + strings.Repeat("A", maxTestText-len(head))
	start := time.Now()
	if w := post("", full); w.Code != 200 {
		t.Errorf("1 MiB: %d %.200s", w.Code, w.Body)
	}
	t.Logf("a 1 MiB request took %v through the API", time.Since(start).Round(time.Millisecond))
	if w := post("", full+"A"); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("1 MiB + 1: %d", w.Code)
	}

	if w := d.do("GET", "/api/test/files/920100", nil, session); w.Code != 200 || !strings.Contains(w.Body.String(), `"expect_ids"`) {
		t.Errorf("a file: %d %.200s", w.Code, w.Body)
	}
	for _, name := range []string{"..%2Fcrs-tests", "nothing"} {
		if w := d.do("GET", "/api/test/files/"+name, nil, session); w.Code != 404 {
			t.Errorf("file %q: %d", name, w.Code)
		}
	}
	if w := d.do("GET", "/test", nil, session); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/test" active aria-current="page">`) {
		t.Errorf("GET /test: %d", w.Code)
	}

	if after := folderState(t, dir); after != before {
		t.Errorf("the records folder changed:\n%s\n%s", before, after)
	}
}

// folderState describes every file of dir: name, size and time.
func folderState(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %d %s %x\n", e.Name(), info.Size(), info.ModTime(), sha256.Sum256(data))
	}
	return b.String()
}
