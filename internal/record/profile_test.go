package record

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// shopProfile marks a path part, two JSON fields and a header as secret
// (F8). Its mode is alert, so its findings are alerts too (F6).
const shopProfile = `{
  "mode": "alert",
  "endpoints": [
    {"method": "POST", "path": "/api/reset/{token}", "content_type": ["application/json"],
     "path_params": {"token": {"secret": true}},
     "params": {
       "card.number": {"in": "json", "secret": true},
       "items.*.cvc": {"in": "json", "secret": true},
       "note": {"in": "json", "max_length": 4}}},
    {"method": "GET", "path": "/search", "params": {"note": {}, "q": {}}}
  ],
  "headers": [{"name": "X-Key", "secret": true}]
}`

// testApps returns the applications shop, with shopProfile, and blog,
// whose profile has no secrets, on the test rules.
func testApps(t testing.TB, rs *engine.RuleSet) *profile.Set {
	t.Helper()
	dir := t.TempDir()
	load := func(name, text string) *profile.Profile {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := profile.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	set, err := profile.NewSet(rs, []profile.AppConfig{
		{Name: "shop", Hosts: []string{"shop.example.com"}, Loaded: load("shop.json", shopProfile)},
		{Name: "blog", Hosts: []string{"blog.example.com"}, Loaded: load("blog.json", `{"endpoints": [{"method": "GET", "path": "/search", "params": {"note": {}, "q": {}}}]}`)},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// Every secret below contains "S3CR3T", which must not appear anywhere in a
// record. Those in fields carry the attack, so that rules match right at
// the secret.
func profiledRequest() *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{
		Method:     "POST",
		Target:     "/api/reset/S3CR3T-8tok",
		Version:    "HTTP/1.1",
		RemoteAddr: "203.0.113.7",
		RemotePort: 51234,
		Headers: []httpmodel.Header{
			{Name: "Host", Value: "shop.example.com"},
			{Name: "X-Key", Value: "S3CR3T-9"},
			{Name: "Content-Type", Value: "application/json"},
		},
		Body: []byte(`{"card": {"number": "S3CR3T-10 union select"}, "items": [{"cvc": "S3CR3T-11 union select"}], "note": "hello", "extra": "1"}`),
	})
}

// buildProfiled evaluates req for its application in set and builds its
// record, as the Recorder does.
func buildProfiled(t *testing.T, rs *engine.RuleSet, set *profile.Set, req *httpmodel.Request, full bool) (Request, []byte) {
	t.Helper()
	app := set.Match(req)
	var tuning *engine.Tuning
	b := testBuilder(full)
	if app != nil {
		tuning = app.Tuning
		b.masker = b.masker.forProfile(app.Profile)
	}
	res := rs.EvaluateWith(req, tuning)
	prof := set.Check(res.Request, app)
	rec := b.build(res.Request, res, &prof, "id2", "run1", time.Date(2026, 10, 25, 10, 15, 2, 0, time.UTC))
	line, err := marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, line
}

// F8, F9: a profiled request keeps its application, level and findings;
// the profile's secrets are masked like the built-in ones.
func TestProfiledRecord(t *testing.T) {
	rs := loadRules(t)
	rec, line := buildProfiled(t, rs, testApps(t, rs), profiledRequest(), true)
	if strings.Contains(string(line), "S3CR3T") {
		t.Fatalf("a secret is in the record:\n%s", line)
	}
	if rec.HTTP.Path != "/api/reset/"+Masked {
		t.Errorf("path %q", rec.HTTP.Path)
	}
	if a := rec.Application; a == nil || a.Name != "shop" || a.ParanoiaLevel != 1 || a.Mode != "alert" {
		t.Errorf("application %+v", a)
	}
	// Rule 2 matches both secret fields, 5 points each.
	if rec.Score.Total != 10 || !rec.Alert || !reflect.DeepEqual(rec.AlertBy, []string{"rules", "profile"}) || rec.DecidedBy != DecidedByProfile {
		t.Errorf("score %d, alert %v by %v, decided by %q", rec.Score.Total, rec.Alert, rec.AlertBy, rec.DecidedBy)
	}
	var kinds []string
	for _, f := range rec.Profile.Findings {
		kinds = append(kinds, f.Kind+" "+f.Location)
	}
	if want := []string{"unknown_param ARGS_POST:json.extra", "too_long ARGS_POST:json.note"}; !reflect.DeepEqual(kinds, want) || !rec.Profile.BodyChecked {
		t.Errorf("profile findings %q, want %q; body checked %v", kinds, want, rec.Profile.BodyChecked)
	}
	for _, f := range rec.Findings {
		if f.RuleID == 2 && f.Matched != Masked {
			t.Errorf("rule 2 at %s: matched %q, want it masked", f.Location, f.Matched)
		}
	}
	if rec.Full == nil || rec.Full.Headers[1] != [2]string{"X-Key", Masked} {
		t.Errorf("full request %+v", rec.Full)
	}
}

// The record line of a profiled request is pinned like TestLineFormat's.
func TestProfiledLineFormat(t *testing.T) {
	rs := loadRules(t)
	_, line := buildProfiled(t, rs, testApps(t, rs), profiledRequest(), true)
	golden := filepath.Join("testdata", "request-record-profile.json")
	if *update {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, line, "", "  "); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, append(pretty.Bytes(), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')
	if !bytes.Equal(compact.Bytes(), line) {
		t.Errorf("the record line changed:\n got %s\nwant %s", line, compact.Bytes())
	}
}

// One application's secrets are its own: blog's "note" is an ordinary
// field, and shop's secret header is a header like others for blog.
func TestProfileSecretsStayWithTheirApplication(t *testing.T) {
	rs := loadRules(t)
	set := testApps(t, rs)
	req := func(host string) *httpmodel.Request {
		return httpmodel.New(httpmodel.Received{
			Method: "GET", Target: "/search?q=1+union+select+2&note=hello", Version: "HTTP/1.1",
			Headers: []httpmodel.Header{{Name: "Host", Value: host}, {Name: "X-Key", Value: "plain-value"}},
		})
	}
	blog, _ := buildProfiled(t, rs, set, req("blog.example.com"), true)
	if blog.HTTP.Query != "q=1+union+select+2&note=hello" || blog.Full.Headers[1] != [2]string{"X-Key", "plain-value"} {
		t.Errorf("blog: query %q, headers %v", blog.HTTP.Query, blog.Full.Headers)
	}
	if blog.DecidedBy != DecidedBy || !reflect.DeepEqual(blog.AlertBy, []string{"rules"}) {
		t.Errorf("blog, mode monitor: decided by %q, alert by %v", blog.DecidedBy, blog.AlertBy)
	}
	shop, _ := buildProfiled(t, rs, set, req("shop.example.com"), true)
	if shop.Full.Headers[1] != [2]string{"X-Key", Masked} {
		t.Errorf("shop: headers %v", shop.Full.Headers)
	}
	other, _ := buildProfiled(t, rs, set, req("other.example.com"), true)
	if a := other.Application; a == nil || a.Name != profile.NoApplication || a.Mode != "" || other.Profile != nil || other.Full.Headers[1][1] != "plain-value" {
		t.Errorf("no application: %+v, profile %+v, headers %v", a, other.Profile, other.Full.Headers)
	}
}

// A run with applications lists them in its start record, counts the
// requests of no application, and records a request with only a profile
// finding (F9).
func TestRecorderWithApplications(t *testing.T) {
	rs := loadRules(t)
	set := testApps(t, rs)
	dir := filepath.Join(t.TempDir(), "records")
	c := &clock{t: time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)}
	r, err := open(Config{Dir: dir}, testEngine, rs.Statuses(), set, c.now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(host, target string) {
		req := httpmodel.New(httpmodel.Received{Method: "GET", Target: target, Version: "HTTP/1.1", Headers: []httpmodel.Header{{Name: "Host", Value: host}}})
		app := set.Match(req)
		var tuning *engine.Tuning
		if app != nil {
			tuning = app.Tuning
		}
		res := rs.EvaluateWith(req, tuning)
		prof := set.Check(res.Request, app)
		if err := r.Add(res.Request, res, &prof); err != nil {
			t.Fatal(err)
		}
	}
	add("shop.example.com", "/search?q=books")     // clean
	add("shop.example.com", "/admin")              // unknown endpoint: a profile alert
	add("blog.example.com", "/admin")              // unknown endpoint: recorded, mode monitor
	add("other.example.com", "/?q=1+union+select") // no application: a rule alert
	add("other.example.com", "/")                  // no application, clean
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readLines(t, filepath.Join(dir, CurrentFile))
	if len(lines) != 5 {
		t.Fatalf("%d lines, want start, 3 requests and counts", len(lines))
	}
	apps, _ := lines[0]["applications"].([]any)
	if len(apps) != 2 || apps[0].(map[string]any)["name"] != "shop" || apps[0].(map[string]any)["mode"] != "alert" {
		t.Errorf("start applications %v", lines[0]["applications"])
	}
	shop, blog, other := lines[1], lines[2], lines[3]
	if shop["alert"] != true || !reflect.DeepEqual(shop["alert_by"], []any{"profile"}) || shop["decided_by"] != DecidedByProfile {
		t.Errorf("shop: %v", shop)
	}
	if blog["alert"] != false || blog["alert_by"] != nil || blog["decided_by"] != DecidedBy || blog["profile"] == nil {
		t.Errorf("blog: %v", blog)
	}
	if other["alert"] != true || other["application"].(map[string]any)["name"] != "none" || other["profile"] != nil {
		t.Errorf("no application: %v", other)
	}
	counts := lines[4]
	if counts["analysed"] != 5.0 || counts["recorded"] != 3.0 || counts["alerts"] != 2.0 || counts["no_profile"] != 2.0 {
		t.Errorf("counts %v", counts)
	}
}

// Without applications, records have none of the new fields.
func TestRecordWithoutApplications(t *testing.T) {
	_, line := build(t, secretRequest(), false)
	for _, field := range []string{`"application"`, `"profile"`, `"alert_by"`} {
		if strings.Contains(string(line), field) {
			t.Errorf("the record has %s:\n%s", field, line)
		}
	}
}

func TestMaskPath(t *testing.T) {
	for _, tc := range []struct {
		path  string
		parts []int
		want  string
	}{
		{"/reset/abc", nil, "/reset/abc"},
		{"/reset/abc", []int{1}, "/reset/" + Masked},
		{"/a/b/c", []int{0, 2}, "/" + Masked + "/b/" + Masked},
		{"/a%2Fb", []int{-1}, Masked},
		{"/a", []int{5}, "/a"},
	} {
		if got := maskPath(tc.path, tc.parts); got != tc.want {
			t.Errorf("maskPath(%q, %v) = %q, want %q", tc.path, tc.parts, got, tc.want)
		}
	}
}

func TestArgMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"pwd", "pwd", true},
		{"pwd", "pwd2", false},
		{"json.items.*.cvc", "json.items.0.cvc", true},
		{"json.items.*.cvc", "json.items.12.cvc", true},
		{"json.items.*.cvc", "json.items.x.cvc", false},
		{"json.items.*.cvc", "json.items.0.cvc.x", false},
		{"json.card.number", "json.card.number", true},
	} {
		if got := argMatches(tc.pattern, tc.name); got != tc.want {
			t.Errorf("argMatches(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

// FuzzProfileSecretsAreMasked: one secret, put in a secret path part, two
// secret JSON fields and a secret header of shopProfile, never appears in
// the record (F8). The test rules match it in both JSON fields.
func FuzzProfileSecretsAreMasked(f *testing.F) {
	f.Add("hunter2 union select", "hello")
	f.Add("x' union select 1 <script>", "")
	f.Add("UNION SELECT tok", `{"a": 1}`)
	rs := loadRules(f)
	set := testApps(f, rs)
	app := set.ByName("shop")
	b := testBuilder(true)
	b.masker = b.masker.forProfile(app.Profile)
	f.Fuzz(func(t *testing.T, raw, note string) {
		var kept strings.Builder
		for _, r := range raw {
			if strings.ContainsRune(secretChars, r) {
				kept.WriteRune(r)
			}
		}
		secret := "Zx" + kept.String() + "Qk"
		if len(secret) < 8 || len(secret) > 80 || !utf8ValidJSON(note) || containsFold(note, "zx") {
			return
		}
		quoted, _ := json.Marshal(secret)
		noteJSON, _ := json.Marshal(note)
		// The path part is the secret without what a path cannot hold.
		token := strings.Map(func(r rune) rune {
			if strings.ContainsRune(" '<>();/!*@$", r) {
				return -1
			}
			return r
		}, secret)
		req := httpmodel.New(httpmodel.Received{
			Method:  "POST",
			Target:  "/api/reset/" + token,
			Version: "HTTP/1.1",
			Headers: []httpmodel.Header{
				{Name: "Host", Value: "shop.example.com"},
				{Name: "X-Key", Value: secret},
				{Name: "Content-Type", Value: "application/json"},
			},
			Body: []byte(`{"card": {"number": ` + string(quoted) + `}, "items": [{"cvc": ` + string(quoted) + `}], "note": ` + string(noteJSON) + `}`),
		})
		res := rs.EvaluateWith(req, app.Tuning)
		prof := set.Check(res.Request, app)
		line, err := marshal(b.build(res.Request, res, &prof, "id", "run", time.Time{}))
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, line)
		}
		walkStrings(v, func(s string) {
			for _, sec := range []string{secret, token, strings.TrimSuffix(strings.TrimPrefix(string(quoted), `"`), `"`)} {
				if containsFold(s, sec) {
					t.Fatalf("secret %q is in %q\nrecord: %s", sec, s, line)
				}
			}
		})
	})
}

func utf8ValidJSON(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00")
}

// A JSON body with a secret field is written again with the field masked,
// whatever escapes the client used; one without is kept as received.
func TestMaskJSON(t *testing.T) {
	m := newMasker(nil, nil)
	m.args = []string{"json.items.*.cvc"}
	for _, tc := range []struct{ name, body, want string }{
		{"no secret", `{ "q": "abc",  "n": 1 }`, `{ "q": "abc",  "n": 1 }`},
		{"escaped password", `{"user": "ali", "password": "hunter2 <x>"}`, `{"user":"ali","password":"[masked]"}`},
		{"object under a secret name", `{"card": {"number": "4111", "exp": [1, 2]}, "ok": true, "z": null}`, `{"card":"[masked]","ok":true,"z":null}`},
		{"profile pattern", `{"items": [{"cvc": "123"}, {"cvc": 456, "n": "x"}]}`, `{"items":[{"cvc":"[masked]"},{"cvc":"[masked]","n":"x"}]}`},
		{"broken after a secret", `{"pwd": "abc", "q": [1, `, `{"pwd":"[masked]","q":[1,…`},
		{"broken before a secret", `{"q": [1, `, `{"q": [1, `},
		{"not an object", `"pwd"`, `"pwd"`},
	} {
		if got := m.maskJSON([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
