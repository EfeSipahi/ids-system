package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// secretsFile holds requests with a secret in each place a secret can be:
// a form password, a session cookie, Authorization and
// Proxy-Authorization, a token parameter, a JSON password, a multipart
// password, and a token in the Referer. Every secret contains "S3CR3T" and
// carries an attack, so that CRS rules match right at the secret.
const secretsFile = "../../testdata/requests/secrets.json"

// writeRecords runs the product configuration (CRS 4.30.0 at paranoia
// level 1) on the requests of a file and writes records, as ids-offline
// does.
func writeRecords(t *testing.T, rules *engine.RuleSet, cfg *config.Product, requests string, full bool) string {
	t.Helper()
	rc := *cfg.Records
	rc.Dir = t.TempDir()
	rc.FullRequests = full
	fingerprint, err := cfg.Fingerprint(rules.ParanoiaLevel())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := record.Open(rc, record.NewEngine(rules, fingerprint), rules.Statuses(), nil)
	if err != nil {
		t.Fatal(err)
	}
	examples, err := offline.LoadFile(requests)
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range examples {
		res := rules.Evaluate(ex.Request)
		if err := rec.Add(res.Request, res, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return rc.Dir
}

func loadProduct(t *testing.T) (*engine.RuleSet, *config.Product) {
	t.Helper()
	cfg, err := config.Load("../../configs/crs-first-engine.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		t.Fatal(err)
	}
	return rules, cfg
}

func hasSecret(text string) bool {
	return strings.Contains(strings.ToLower(text), "s3cr3t")
}

func TestNoSecretReachesTheDashboard(t *testing.T) {
	if testing.Short() {
		t.Skip("loads the CRS rules")
	}
	rules, cfg := loadProduct(t)
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full_requests=%v", full), func(t *testing.T) {
			dir := writeRecords(t, rules, cfg, secretsFile, full)

			// 1. The record files.
			files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
			if len(files) != 1 {
				t.Fatalf("record files %v", files)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if hasSecret(string(data)) {
				t.Fatal("a secret is in the record file")
			}

			// The test is only worth something if rules matched at the
			// secrets: every place must have a finding.
			var locations []string
			requests := 0
			for line := range strings.Lines(string(data)) {
				var rec record.Request
				if json.Unmarshal([]byte(line), &rec) != nil || rec.Type != record.TypeRequest {
					continue
				}
				requests++
				if !rec.Alert {
					t.Errorf("%s %s is not an alert", rec.HTTP.Method, rec.HTTP.Path)
				}
				if full != (rec.Full != nil) {
					t.Errorf("full request present: %v", rec.Full != nil)
				}
				if rec.Full != nil {
					for _, h := range rec.Full.Headers {
						secret := slices.Contains([]string{"authorization", "cookie", "proxy-authorization"}, strings.ToLower(h[0]))
						if secret && h[1] != record.Masked {
							t.Errorf("full header %s = %q", h[0], h[1])
						}
					}
				}
				for _, f := range rec.Findings {
					if !slices.Contains(locations, f.Location) {
						locations = append(locations, f.Location)
					}
				}
			}
			if requests != 7 {
				t.Errorf("%d request records", requests)
			}
			for _, want := range []string{"ARGS:password", "REQUEST_COOKIES:sid", "REQUEST_HEADERS:Authorization",
				"REQUEST_HEADERS:Proxy-Authorization", "ARGS:token", "ARGS:json.password", "REQUEST_HEADERS:Referer"} {
				if !slices.Contains(locations, want) {
					t.Errorf("no rule matched at %s; found %v", want, locations)
				}
			}

			// 2. Everything the dashboard answers.
			// The records have the real time.
			d := newDashboard(t, dir)
			d.clock.set(time.Now())
			session := d.login(t, "admin", d.password)
			var l list
			paths := []string{"/api/overview?range=all", "/api/alerts?range=all&kind=all", "/api/rules?range=all", "/api/engine",
				"/", "/alerts", "/rules", "/engine"}
			w := d.do("GET", paths[1], nil, session)
			decode(t, w, &l)
			if l.Total != 7 {
				t.Fatalf("the dashboard lists %d records", l.Total)
			}
			for _, r := range l.Rows {
				paths = append(paths, "/api/records/"+r.ID, "/alerts/"+r.ID)
			}
			for _, p := range paths {
				w := d.do("GET", p, nil, session)
				if w.Code != http.StatusOK {
					t.Errorf("%s: %d", p, w.Code)
				}
				if hasSecret(w.Body.String()) {
					t.Errorf("%s shows a secret", p)
				}
			}
		})
	}
}

// attackText is what an attacker could put in a request to run script in
// the dashboard of whoever looks at it.
const attackText = `<script>alert("x")</script><img src=x onerror=alert(1)>`

func TestAttackTextIsNeverHTML(t *testing.T) {
	dir := t.TempDir()
	rec := requestRecord("evil", "run1", t0, "203.0.113.5", 10, at{941100, "ARGS:q"})
	rec.HTTP.UserAgent = attackText
	rec.HTTP.Path = "/" + attackText
	rec.HTTP.Query = "q=" + attackText
	rec.Findings[0].Matched = attackText
	rec.Findings[0].Message = "XSS in " + attackText
	appendLines(t, filepath.Join(dir, record.CurrentFile), rec)

	// Another writer might not escape < and > in its JSON: write such a
	// line by hand too.
	raw, _ := json.Marshal(requestRecord("raw", "run1", t0, "", 10, at{941100, "ARGS:q"}))
	line := strings.Replace(string(raw), `"user_agent":"test-agent"`, `"user_agent":"`+strings.ReplaceAll(attackText, `"`, `\"`)+`"`, 1)
	if !strings.Contains(line, "<script>") {
		t.Fatal("the hand-written line has no raw <script>")
	}
	f, _ := os.OpenFile(filepath.Join(dir, record.CurrentFile), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(line + "\n")
	f.Close()

	d := newDashboard(t, dir)
	session := d.login(t, "admin", d.password)

	for _, p := range []string{"/api/alerts?range=all", "/api/records/evil", "/api/records/raw", "/api/overview?range=all"} {
		w := d.do("GET", p, nil, session)
		body := w.Body.String()
		if w.Code != http.StatusOK || strings.ContainsAny(body, "<>") {
			t.Errorf("%s: %d, raw < or > in %s", p, w.Code, body)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s: content type %q", p, ct)
		}
	}
	// The text itself is kept, only escaped.
	var got record.Request
	decode(t, d.do("GET", "/api/records/raw", nil, session), &got)
	if got.HTTP.UserAgent != attackText {
		t.Errorf("user agent = %q", got.HTTP.UserAgent)
	}

	// A page puts nothing of a record in its HTML; only the ID from the
	// address, escaped by html/template.
	w := d.do("GET", "/alerts/"+url.PathEscape(attackText), nil, session)
	body := w.Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("alert page: %s", body)
	}
	if w := d.do("GET", "/alerts/evil", nil, session); strings.Contains(w.Body.String(), "onerror") {
		t.Error("an alert page holds record text")
	}
}

// TestScriptBuildsNoHTML guards the rule of app.js: values go into the page
// as text nodes only.
func TestScriptBuildsNoHTML(t *testing.T) {
	data, err := webFiles.ReadFile("web/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	code := string(data)
	// Leave out the comments, which name what is not used.
	var lines []string
	for line := range strings.Lines(code) {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			lines = append(lines, line)
		}
	}
	code = strings.Join(lines, "")
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "srcdoc"} {
		if strings.Contains(code, bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
	// No page has inline script or style for the CSP to allow.
	entries, _ := webFiles.ReadDir("web/templates")
	for _, e := range entries {
		page, _ := webFiles.ReadFile("web/templates/" + e.Name())
		for _, bad := range []string{"<script>", "onclick=", "onload=", "onsubmit=", "style=", "javascript:"} {
			if strings.Contains(string(page), bad) {
				t.Errorf("%s has %s", e.Name(), bad)
			}
		}
	}
}

// profileSecrets is a profile that marks a path part, two JSON fields whose
// names are not secret by themselves, and a header as secret (F8).
const profileSecrets = `{
  "mode": "alert",
  "endpoints": [
    {"method": "POST", "path": "/reset/{token}", "path_params": {"token": {"secret": true}},
     "params": {"iban": {"in": "json", "secret": true}, "items.*.code": {"in": "json", "secret": true}}}
  ],
  "headers": [{"name": "X-Shop-Key", "secret": true}]
}`

// profileSecretRequests carry a secret, with "S3CR3T" in it, in each of
// those places, and an attack at the JSON fields and the header so that
// CRS rules match right at them.
const profileSecretRequests = `[
  {"name": "profile secrets", "method": "POST", "uri": "/reset/S3CR3T-path-token",
   "headers": [["Host", "shop.example.com"], ["X-Shop-Key", "S3CR3T/../../../etc/passwd"], ["Content-Type", "application/json"]],
   "body": "{\"iban\": \"S3CR3T' union select password from users --\", \"items\": [{\"code\": \"S3CR3T<script>alert(1)</script>\"}], \"q\": \"x\"}"}
]`

// F8: a profile's secrets reach neither the records nor the dashboard.
func TestNoProfileSecretReachesTheDashboard(t *testing.T) {
	if testing.Short() {
		t.Skip("loads the CRS rules")
	}
	rules, cfg := loadProduct(t)
	tmp := t.TempDir()
	profilePath := filepath.Join(tmp, "shop.json")
	requests := filepath.Join(tmp, "requests.json")
	for path, text := range map[string]string{profilePath: profileSecrets, requests: profileSecretRequests} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p, err := profile.Load(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	set, err := profile.NewSet(rules, []profile.AppConfig{{Name: "shop", Hosts: []string{"shop.example.com"}, Loaded: p}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("full_requests=%v", full), func(t *testing.T) {
			rc := *cfg.Records
			rc.Dir, rc.FullRequests = t.TempDir(), full
			rec, err := record.Open(rc, record.NewEngine(rules, "sha256:test"), rules.Statuses(), set)
			if err != nil {
				t.Fatal(err)
			}
			examples, err := offline.LoadFile(requests)
			if err != nil {
				t.Fatal(err)
			}
			for _, ex := range examples {
				app := set.Match(ex.Request)
				res := rules.EvaluateWith(ex.Request, app.Tuning)
				prof := set.Check(res.Request, app)
				if err := rec.Add(res.Request, res, &prof); err != nil {
					t.Fatal(err)
				}
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(rc.Dir, record.CurrentFile))
			if err != nil {
				t.Fatal(err)
			}
			if hasSecret(string(data)) {
				t.Fatalf("a secret is in the record file:\n%s", data)
			}
			var locations []string
			for line := range strings.Lines(string(data)) {
				var r record.Request
				if json.Unmarshal([]byte(line), &r) != nil || r.Type != record.TypeRequest {
					continue
				}
				if r.HTTP.Path != "/reset/"+record.Masked || r.Application == nil || r.Application.Name != "shop" {
					t.Errorf("path %q, application %+v", r.HTTP.Path, r.Application)
				}
				for _, f := range r.Findings {
					locations = append(locations, f.Location)
				}
			}
			for _, want := range []string{"ARGS:json.iban", "ARGS:json.items.0.code", "REQUEST_HEADERS:X-Shop-Key"} {
				if !slices.Contains(locations, want) {
					t.Errorf("no rule matched at %s; found %v", want, locations)
				}
			}

			d := newDashboard(t, rc.Dir)
			d.clock.set(time.Now())
			session := d.login(t, "admin", d.password)
			var l list
			decode(t, d.do("GET", "/api/alerts?range=all&kind=all", nil, session), &l)
			if l.Total != 1 {
				t.Fatalf("the dashboard lists %d records", l.Total)
			}
			for _, path := range []string{"/api/overview?range=all", "/api/alerts?range=all&kind=all&app=shop", "/api/rules?range=all&app=shop",
				"/api/engine", "/api/records/" + l.Rows[0].ID, "/alerts/" + l.Rows[0].ID} {
				w := d.do("GET", path, nil, session)
				if w.Code != http.StatusOK || hasSecret(w.Body.String()) {
					t.Errorf("%s: %d, secret shown %v", path, w.Code, hasSecret(w.Body.String()))
				}
			}
		})
	}
}
