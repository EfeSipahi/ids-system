package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

var (
	rulesOnce sync.Once
	rules     *engine.RuleSet
	rulesErr  error
)

// crsRules loads the product configuration's rules once.
func crsRules(t *testing.T) *engine.RuleSet {
	t.Helper()
	rulesOnce.Do(func() {
		path := "../../configs/crs-first-engine.json"
		data, err := os.ReadFile(path)
		if err != nil {
			rulesErr = err
			return
		}
		var file struct {
			engine.Config
			Records json.RawMessage `json:"records"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if rulesErr = dec.Decode(&file); rulesErr != nil {
			return
		}
		if rulesErr = file.Config.Prepare(filepath.Dir(path)); rulesErr != nil {
			return
		}
		rules, rulesErr = engine.Load(file.Config)
	})
	if rulesErr != nil {
		t.Fatal(rulesErr)
	}
	return rules
}

func writeProfile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadErrors(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
	}{
		{"unknown field", `{"mood": "alert"}`, `unknown field "mood"`},
		{"not JSON", `{"mode": }`, "invalid profile"},
		{"two objects", `{} {}`, "unexpected content after the profile"},
		{"mode", `{"mode": "block"}`, `mode "block" is not one of monitor, alert`},
		{"level", `{"paranoia_level": 5}`, "paranoia_level 5 is not supported"},
		{"no method", `{"endpoints": [{"path": "/"}]}`, "endpoints[0]: method is missing"},
		{"lower-case method", `{"endpoints": [{"method": "get", "path": "/"}]}`, `method "get" is not an HTTP method in upper case`},
		{"both methods", `{"endpoints": [{"method": "GET", "methods": ["POST"], "path": "/"}]}`, "either method or methods"},
		{"relative path", `{"endpoints": [{"method": "GET", "path": "a"}]}`, "a path starts with /"},
		{"star inside", `{"endpoints": [{"method": "GET", "path": "/a/*/b"}]}`, "* may only be the whole last part"},
		{"brace inside", `{"endpoints": [{"method": "GET", "path": "/a/x{id}"}]}`, "{name} must be a whole path part"},
		{"same endpoint", `{"endpoints": [{"method": "GET", "path": "/i/{a}"}, {"methods": ["POST", "GET"], "path": "/i/{b}"}]}`, "endpoints[1]: GET /i/{b} is already endpoints[0]"},
		{"path param without part", `{"endpoints": [{"method": "GET", "path": "/a", "path_params": {"id": {}}}]}`, "path_params.id: the path has no {id}"},
		{"type", `{"endpoints": [{"method": "GET", "path": "/", "params": {"id": {"type": "int"}}}]}`, `params.id: type "int" is not one of string, integer, number, boolean, enum`},
		{"in", `{"endpoints": [{"method": "GET", "path": "/", "params": {"id": {"in": "header"}}}]}`, `in "header" is not one of args, query, body, json`},
		{"length on integer", `{"endpoints": [{"method": "GET", "path": "/", "params": {"id": {"type": "integer", "max_length": 3}}}]}`, "min_length and max_length are for type string"},
		{"enum without values", `{"endpoints": [{"method": "GET", "path": "/", "params": {"m": {"type": "enum"}}}]}`, "type enum needs values"},
		{"min above max", `{"endpoints": [{"method": "GET", "path": "/", "params": {"n": {"type": "integer", "min": 5, "max": 1}}}]}`, "min is above max"},
		{"bad pattern", `{"endpoints": [{"method": "GET", "path": "/", "params": {"s": {"pattern": "("}}}]}`, "pattern: error parsing regexp"},
		{"json path", `{"endpoints": [{"method": "POST", "path": "/", "params": {"user..name": {"in": "json"}}}]}`, "is not a dotted path"},
		{"other params", `{"endpoints": [{"method": "GET", "path": "/", "other_params": "ignore"}]}`, `other_params "ignore" is not one of finding, allow`},
		{"content type", `{"endpoints": [{"method": "POST", "path": "/", "content_type": ["application/json; charset=utf-8"]}]}`, "without parameters"},
		{"cookie in", `{"cookies": {"sid": {"in": "query"}}}`, `cookies.sid: a cookie has no "in"`},
		{"header name", `{"headers": [{"name": "X Key"}]}`, `headers[0]: name "X Key" is not a header name`},
		{"exception reason", `{"exceptions": [{"rule": 942100, "off": true}]}`, "exceptions[0]: reason is missing"},
		{"exception kinds", `{"exceptions": [{"rule": 942100, "off": true, "skip": ["ARGS"], "reason": "r"}]}`, "give only one of"},
		{"exception none", `{"exceptions": [{"rule": 942100, "reason": "r"}]}`, "give one of"},
		{"setting value", `{"exceptions": [{"setting": "arg_length", "reason": "r"}]}`, "setting arg_length has no value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeProfile(t, tc.text))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("missing file: %v", err)
	}
}

// newSet loads one profile text as the application "shop" on host
// shop.example.
func newSet(t *testing.T, text string, require bool) *Set {
	t.Helper()
	p, err := Load(writeProfile(t, text))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(crsRules(t), []AppConfig{{Name: "shop", Hosts: []string{"shop.example"}, Loaded: p}}, require)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExceptionErrors(t *testing.T) {
	for _, tc := range []struct {
		name, exceptions, want string
	}{
		{"949", `{"rule": 949052, "off": true, "reason": "too many alerts"}`,
			"exceptions[0]: rule 949052 cannot be excepted.\nIt is in REQUEST-949-BLOCKING-EVALUATION.conf, which adds up the attack score; without it this application would never raise an alert.\nRemove this exception, or except the attack rule that causes the false alarm."},
		{"901", `{"rule": 901100, "skip": ["TX:inbound_anomaly_score_threshold"], "reason": "r"}`,
			"exceptions[0]: rule 901100 cannot be excepted.\nIt is in REQUEST-901-INITIALIZATION.conf, which sets up CRS: the alert threshold and the starting values."},
		{"unknown rule", `{"rule": 999999, "off": true, "reason": "r"}`, "exceptions[0]: rule 999999 is in none of the loaded rule files"},
		{"bad skip", `{"rule": 942100, "skip": ["ARGS", "!ARGS:id"], "reason": "r"}`, `exceptions[0]: skip[1] "!ARGS:id": write the variable without !`},
		{"setting not allowed", `{"setting": "inbound_anomaly_score_threshold", "value": "100", "reason": "r"}`, "the setting inbound_anomaly_score_threshold cannot be changed by a profile. These can: allow_method_override_parameter, allowed_http_versions,"},
		{"flag value", `{"setting": "crs_validate_utf8_encoding", "value": "no", "reason": "r"}`, "the value must be 0 or 1"},
		{"number value", `{"setting": "arg_length", "value": "0", "reason": "r"}`, "a whole number of at least 1"},
		{"same rule twice", `{"rule": 942100, "off": true, "reason": "r"}, {"rule": 942100, "skip": ["ARGS"], "reason": "r"}`, "exceptions[1]: rule 942100 already has exceptions[0]"},
		{"same setting twice", `{"setting": "arg_length", "value": "5", "reason": "r"}, {"setting": "arg_length", "value": "6", "reason": "r"}`, "the setting arg_length is already given"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load(writeProfile(t, `{"exceptions": [`+tc.exceptions+`]}`))
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewSet(crsRules(t), []AppConfig{{Name: "shop", Hosts: []string{"shop.example"}, Loaded: p}}, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error\n%v\nwant one containing\n%s", err, tc.want)
			}
		})
	}
}

func TestExceptionNotes(t *testing.T) {
	s := newSet(t, `{"exceptions": [
		{"rule": 932350, "skip": ["ARGS_NAMES:pwd"], "reason": "a parameter name"},
		{"rule": 920230, "skip": ["REQUEST_COOKIES:a"], "reason": "r"},
		{"setting": "crs_validate_utf8_encoding", "value": "0", "reason": "Latin-1"}]}`, false)
	app := s.Apps()[0]
	if len(app.Notes) != 3 {
		t.Fatalf("notes %q, want 3", app.Notes)
	}
	for i, want := range []string{
		"exceptions[0]: rule 932350 belongs to paranoia level 3 and does not run at level 1; this exception takes effect when the level is raised",
		"exceptions[1]: rule 920230 belongs to paranoia level 2 and does not run at level 1",
		"rule 920230 does not look at REQUEST_COOKIES, so skipping REQUEST_COOKIES:a changes nothing",
	} {
		if !strings.Contains(app.Notes[i], want) {
			t.Errorf("note %d %q, want one containing %q", i, app.Notes[i], want)
		}
	}
	if app.Exceptions[0].NoEffect == "" || app.Exceptions[2].NoEffect != "" {
		t.Errorf("exception notes %+v", app.Exceptions)
	}
}

func TestSetErrors(t *testing.T) {
	p, err := Load(writeProfile(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		apps []AppConfig
		want string
	}{
		{"name", []AppConfig{{Name: "my shop", Hosts: []string{"a"}, Loaded: p}}, `name "my shop"`},
		{"reserved name", []AppConfig{{Name: "none", Hosts: []string{"a"}, Loaded: p}}, "the name none is kept"},
		{"same name", []AppConfig{{Name: "a", Hosts: []string{"a"}, Loaded: p}, {Name: "a", Hosts: []string{"b"}, Loaded: p}}, "the name a is already used"},
		{"no hosts", []AppConfig{{Name: "a", Loaded: p}}, "hosts is empty"},
		{"same host", []AppConfig{{Name: "a", Hosts: []string{"x:80"}, Loaded: p}, {Name: "b", Hosts: []string{"X:80"}, Loaded: p}}, "host x:80 with path / already belongs to application a"},
		{"same host and path", []AppConfig{{Name: "a", Hosts: []string{"x"}, Paths: []string{"/s/"}, Loaded: p}, {Name: "b", Hosts: []string{"x"}, Paths: []string{"/s/"}, Loaded: p}}, "already belongs to application a"},
		{"path", []AppConfig{{Name: "a", Hosts: []string{"x"}, Paths: []string{"s/"}, Loaded: p}}, `path "s/" does not start with /`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSet(crsRules(t), tc.apps, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func request(method, target string, headers [][2]string, body string) *httpmodel.Request {
	rec := httpmodel.Received{Method: method, Target: target, Version: "HTTP/1.1", Body: []byte(body)}
	for _, h := range headers {
		rec.Headers = append(rec.Headers, httpmodel.Header{Name: h[0], Value: h[1]})
	}
	return httpmodel.New(rec)
}

func TestMatch(t *testing.T) {
	p, err := Load(writeProfile(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(crsRules(t), []AppConfig{
		{Name: "shop", Hosts: []string{"shop.example", "localhost:8080"}, Loaded: p},
		{Name: "admin", Hosts: []string{"localhost:8080"}, Paths: []string{"/admin/", "/adm/"}, Loaded: p},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, target, want string
	}{
		{"shop.example", "/x", "shop"},
		{"SHOP.example", "/x", "shop"},
		{"localhost:8080", "/x", "shop"},
		{"localhost:8080", "/admin/users", "admin"},
		{"localhost:8080", "/%61dmin/users", "admin"}, // matched on the decoded path
		{"localhost:8080", "/administrator", "shop"},
		{"localhost", "/x", ""},
		{"blog.example", "/x", ""},
	} {
		got := ""
		if a := s.Match(request("GET", tc.target, [][2]string{{"Host", tc.host}, {"X-Profile", "admin"}}, "")); a != nil {
			got = a.Name
		}
		if got != tc.want {
			t.Errorf("Host %s %s: application %q, want %q", tc.host, tc.target, got, tc.want)
		}
	}
	if s.Match(request("GET", "/x", nil, "")) != nil {
		t.Error("a request without Host matched an application")
	}
}

const shopProfile = `{
  "mode": "alert",
  "endpoints": [
    {"methods": ["GET", "POST"], "path": "/item.jsp",
     "params": {
       "id":     {"type": "integer", "required": true, "min": 1, "max": 9999},
       "price":  {"type": "number", "min": 0},
       "name":   {"max_length": 10, "min_length": 2},
       "code":   {"pattern": "[A-Z]{3}"},
       "mode":   {"type": "enum", "values": ["view", "buy"]},
       "gift":   {"type": "boolean"},
       "tag":    {"repeat": true},
       "pwd":    {"in": "body", "secret": true},
       "q":      {"in": "query"}
     }},
    {"method": "POST", "path": "/api/order", "content_type": ["application/json"],
     "params": {
       "user.name":  {"in": "json", "required": true},
       "items.*.id": {"in": "json", "type": "integer"}
     }},
    {"method": "GET", "path": "/reset/{token}", "path_params": {"token": {"pattern": "[0-9a-f]{8}", "secret": true}}},
    {"method": "GET", "path": "/user/{id}", "path_params": {"id": {"type": "integer"}}},
    {"method": "GET", "path": "/user/me"},
    {"method": "GET", "path": "/img/*"},
    {"method": "GET", "path": "/free", "other_params": "allow"}
  ],
  "cookies": {"sid": {"pattern": "[0-9A-F]{8}", "required": true}},
  "headers": [{"name": "X-Key", "paths": ["/api/*"], "required": true, "max_length": 8, "secret": true}]
}`

func TestCheck(t *testing.T) {
	s := newSet(t, shopProfile, false)
	app := s.Apps()[0]
	sid := [2]string{"Cookie", "sid=0A1B2C3D"}
	host := [2]string{"Host", "shop.example"}
	form := [2]string{"Content-Type", "application/x-www-form-urlencoded"}
	jsonCT := [2]string{"Content-Type", "application/json"}
	key := [2]string{"X-Key", "k1"}
	for _, tc := range []struct {
		name    string
		req     *httpmodel.Request
		want    []string // kind and location
		checked bool
	}{
		{"normal", request("GET", "/item.jsp?id=12&price=3.5&name=ab&code=ABC&mode=buy&gift=1&tag=a&tag=b", [][2]string{host, sid}, ""), nil, true},
		{"normal form", request("POST", "/item.jsp?q=x", [][2]string{host, sid, form}, "id=1&pwd=SECRETVALUE1"), nil, true},
		{"unknown endpoint", request("GET", "/admin.php", [][2]string{host, sid}, ""), []string{"unknown_endpoint REQUEST_FILENAME"}, true},
		{"method", request("DELETE", "/item.jsp?id=1", [][2]string{host, sid}, ""), []string{"method REQUEST_METHOD"}, true},
		{"unknown param", request("GET", "/item.jsp?id=1&debug=1", [][2]string{host, sid}, ""), []string{"unknown_param ARGS_GET:debug"}, true},
		{"missing", request("GET", "/item.jsp?name=ab", [][2]string{host, sid}, ""), []string{"missing ARGS:id"}, true},
		{"repeated", request("GET", "/item.jsp?id=1&id=2", [][2]string{host, sid}, ""), []string{"repeated ARGS_GET:id"}, true},
		{"wrong types", request("GET", "/item.jsp?id=1x&price=1e&gift=yes", [][2]string{host, sid}, ""),
			[]string{"wrong_type ARGS_GET:gift", "wrong_type ARGS_GET:id", "wrong_type ARGS_GET:price"}, true},
		{"plus sign", request("GET", "/item.jsp?id=%2B5", [][2]string{host, sid}, ""), []string{"wrong_type ARGS_GET:id"}, true},
		{"range", request("GET", "/item.jsp?id=0&price=-1", [][2]string{host, sid}, ""), []string{"out_of_range ARGS_GET:id", "out_of_range ARGS_GET:price"}, true},
		{"lengths", request("GET", "/item.jsp?id=1&name=abcdefghijk", [][2]string{host, sid}, ""), []string{"too_long ARGS_GET:name"}, true},
		{"short", request("GET", "/item.jsp?id=1&name=a", [][2]string{host, sid}, ""), []string{"too_short ARGS_GET:name"}, true},
		{"pattern", request("GET", "/item.jsp?id=1&code=ABCD", [][2]string{host, sid}, ""), []string{"pattern ARGS_GET:code"}, true},
		{"enum", request("GET", "/item.jsp?id=1&mode=steal", [][2]string{host, sid}, ""), []string{"not_in_list ARGS_GET:mode"}, true},
		{"query only", request("POST", "/item.jsp?id=1", [][2]string{host, sid, form}, "q=x"), []string{"unknown_param ARGS_POST:q"}, true},
		{"body only", request("GET", "/item.jsp?id=1&pwd=x", [][2]string{host, sid}, ""), []string{"unknown_param ARGS_GET:pwd"}, true},
		{"no cookie", request("GET", "/item.jsp?id=1", [][2]string{host}, ""), []string{"missing REQUEST_COOKIES:sid"}, true},
		{"bad cookie, other cookie", request("GET", "/item.jsp?id=1", [][2]string{host, {"Cookie", "sid=zz; _ga=1"}}, ""), []string{"pattern REQUEST_COOKIES:sid"}, true},
		{"json", request("POST", "/api/order", [][2]string{host, sid, jsonCT, key}, `{"user": {"name": "efe"}, "items": [{"id": 1}, {"id": 2}]}`), nil, true},
		{"json errors", request("POST", "/api/order", [][2]string{host, sid, jsonCT, key}, `{"user": {"age": 3}, "items": [{"id": "x"}]}`),
			[]string{"unknown_param ARGS_POST:json.user.age", "wrong_type ARGS_POST:json.items.0.id", "missing ARGS_POST:json.user.name"}, true},
		{"content type", request("POST", "/api/order", [][2]string{host, sid, form, key}, `user.name=a`), []string{"content_type REQUEST_HEADERS:Content-Type", "unknown_param ARGS_POST:user.name", "missing ARGS_POST:json.user.name"}, true},
		{"header", request("POST", "/api/order", [][2]string{host, sid, jsonCT}, `{"user": {"name": "efe"}}`), []string{"missing REQUEST_HEADERS:X-Key"}, true},
		{"long header", request("POST", "/api/order", [][2]string{host, sid, jsonCT, {"X-Key", "123456789"}}, `{"user": {"name": "efe"}}`), []string{"too_long REQUEST_HEADERS:X-Key"}, true},
		{"path param", request("GET", "/reset/0011aabb", [][2]string{host, sid}, ""), nil, true},
		{"bad path param", request("GET", "/reset/xyz", [][2]string{host, sid}, ""), []string{"pattern REQUEST_FILENAME:{token}"}, true},
		{"exact before template", request("GET", "/user/me", [][2]string{host, sid}, ""), nil, true},
		{"template", request("GET", "/user/abc", [][2]string{host, sid}, ""), []string{"wrong_type REQUEST_FILENAME:{id}"}, true},
		{"rest", request("GET", "/img/a/b.png", [][2]string{host, sid}, ""), nil, true},
		{"rest needs a part", request("GET", "/img", [][2]string{host, sid}, ""), []string{"unknown_endpoint REQUEST_FILENAME"}, true},
		{"dot dot", request("GET", "/img/../admin.php", [][2]string{host, sid}, ""), []string{"unknown_endpoint REQUEST_FILENAME"}, true},
		{"encoded dot dot", request("GET", "/img/%2e%2e/admin.php", [][2]string{host, sid}, ""), []string{"unknown_endpoint REQUEST_FILENAME"}, true},
		{"other params allowed", request("GET", "/free?anything=1", [][2]string{host, sid}, ""), nil, true},
		// A body without a reader is not read, so its parameters are not
		// judged: pwd, which may only come in the body, is not reported.
		{"body not read", request("POST", "/item.jsp?id=1", [][2]string{host, sid, {"Content-Type", "application/x-unknown"}}, "pwd=x&zzz=1"), nil, false},
		{"body not read, required", request("POST", "/api/order", [][2]string{host, sid, {"Content-Type", "application/json"}, key}, `{"user": `), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := app.Check(tc.req)
			var got []string
			for _, f := range res.Findings {
				got = append(got, f.Kind+" "+f.Location)
				if strings.Contains(f.Message, "SECRETVALUE") || strings.Contains(f.Message, "steal") || strings.Contains(f.Message, "abcdefghijk") {
					t.Errorf("a message holds a value: %q", f.Message)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("findings %q, want %q", got, tc.want)
			}
			if res.BodyChecked != tc.checked {
				t.Errorf("body checked %v, want %v", res.BodyChecked, tc.checked)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	s := newSet(t, shopProfile, false)
	app := s.Apps()[0]
	if got, want := app.Profile.SecretArgs(), []string{"pwd"}; !reflect.DeepEqual(got, want) {
		t.Errorf("secret parameters %q, want %q", got, want)
	}
	if got, want := app.Profile.SecretHeaders(), []string{"X-Key"}; !reflect.DeepEqual(got, want) {
		t.Errorf("secret headers %q, want %q", got, want)
	}
	jp, err := Load(writeProfile(t, `{"endpoints": [{"method": "POST", "path": "/api", "params": {
		"items.*.cvc": {"in": "json", "secret": true}, "card.number": {"in": "json", "secret": true}, "q": {}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := jp.SecretArgs(), []string{"json.card.number", "json.items.*.cvc"}; !reflect.DeepEqual(got, want) {
		t.Errorf("secret JSON fields %q, want %q", got, want)
	}
	res := app.Check(request("GET", "/reset/0011aabb", [][2]string{{"Host", "shop.example"}, {"Cookie", "sid=0A1B2C3D"}}, ""))
	if !reflect.DeepEqual(res.SecretPath, []int{1}) || !slices.Contains(res.SecretValues, "0011aabb") {
		t.Errorf("secret path %v values %q", res.SecretPath, res.SecretValues)
	}
	// A path that fits no endpoint has no known secret parts. A %2F turns
	// one part into two after decoding, so this one fits no endpoint.
	res = app.Check(request("GET", "/reset/0011aabb%2Fx", [][2]string{{"Host", "shop.example"}, {"Cookie", "sid=0A1B2C3D"}}, ""))
	if len(res.Findings) != 1 || res.Findings[0].Kind != KindUnknownEndpoint || res.SecretPath != nil {
		t.Errorf("findings %+v, secret path %v", res.Findings, res.SecretPath)
	}
}

func TestRequireProfile(t *testing.T) {
	s := newSet(t, `{}`, true)
	res := s.Check(request("GET", "/", [][2]string{{"Host", "other.example"}}, ""), nil)
	if len(res.Findings) != 1 || res.Findings[0].Kind != KindNoProfile {
		t.Errorf("findings %+v, want no_profile", res.Findings)
	}
	if res.Alert() {
		t.Error("a no_profile finding of no application is an alert")
	}
	s = newSet(t, `{}`, false)
	if res := s.Check(request("GET", "/", [][2]string{{"Host", "other.example"}}, ""), nil); len(res.Findings) != 0 {
		t.Errorf("findings without require_profile: %+v", res.Findings)
	}
}

func TestModeAndLevel(t *testing.T) {
	s := newSet(t, `{"mode": "monitor", "paranoia_level": 3, "endpoints": []}`, false)
	app := s.Apps()[0]
	res := app.Check(request("GET", "/x", [][2]string{{"Host", "shop.example"}}, ""))
	if len(res.Findings) != 1 || res.Alert() {
		t.Errorf("monitor: findings %+v, alert %v", res.Findings, res.Alert())
	}
	if app.ParanoiaLevel() != 3 {
		t.Errorf("level %d, want 3", app.ParanoiaLevel())
	}
	s = newSet(t, `{"mode": "alert"}`, false)
	if res := s.Apps()[0].Check(request("GET", "/x", [][2]string{{"Host", "shop.example"}}, "")); !res.Alert() {
		t.Error("alert mode with a finding is not an alert")
	}
	if s.Apps()[0].ParanoiaLevel() != 1 {
		t.Errorf("default level %d, want 1", s.Apps()[0].ParanoiaLevel())
	}
}

// TestSettingsAreCRSSettings checks the list of settings a profile may
// change against CRS itself. Each one is set by a setvar in
// crs-setup.conf.example. In REQUEST-901-INITIALIZATION.conf every setvar
// of it either fills it only when it is missing (after a test of
// &TX:name "@eq 0") or adds to the value it finds (%{tx.name}), so a
// profile's value is kept. Comment lines are not rules.
func TestSettingsAreCRSSettings(t *testing.T) {
	setup, err := os.ReadFile("../../coreruleset-4.30.0/crs-setup.conf.example")
	if err != nil {
		t.Fatal(err)
	}
	initFile, err := os.ReadFile("../../coreruleset-4.30.0/rules/REQUEST-901-INITIALIZATION.conf")
	if err != nil {
		t.Fatal(err)
	}
	var rulesText strings.Builder
	for _, line := range strings.Split(string(initFile), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			rulesText.WriteString(line + "\n")
		}
	}
	rulesOnly := rulesText.String()
	for _, name := range SettingNames() {
		if !strings.Contains(string(setup), "tx."+name+"=") {
			t.Errorf("%s is not set in crs-setup.conf.example", name)
		}
		sets := strings.Count(rulesOnly, "tx."+name+"=")
		guards := strings.Count(rulesOnly, "&TX:"+name+` "@eq 0"`)
		adds := strings.Count(rulesOnly, "tx."+name+"=%{tx."+name+"}")
		if sets != guards+adds {
			t.Errorf("%s: REQUEST-901 sets it %d times: %d after a test that it is missing, %d adding to it", name, sets, guards, adds)
		}
	}
}

// TestEverySettingIsAccepted gives every allowed setting at once on the
// product configuration: no loaded rule may overwrite any of them.
func TestEverySettingIsAccepted(t *testing.T) {
	var exceptions []string
	for _, name := range SettingNames() {
		value := "1"
		if settings[name] == "text" {
			value = "x"
		}
		exceptions = append(exceptions, `{"setting": "`+name+`", "value": "`+value+`", "reason": "test"}`)
	}
	newSet(t, `{"exceptions": [`+strings.Join(exceptions, ", ")+`]}`, false)
}

// F4g: the survey counts requests, not values; JSON list indexes become *,
// and a body that was not read adds no body parameters.
func TestSurvey(t *testing.T) {
	host := [2]string{"Host", "shop.example"}
	jsonType := [2]string{"Content-Type", "application/json"}
	s := NewSurvey()
	s.Add(request("POST", "/api/order", [][2]string{host, jsonType, {"Cookie", "sid=abc; sid=def; n=5"}}, `{"items": [{"id": "1"}, {"id": "22"}], "user": "efe"}`))
	s.Add(request("POST", "/api/order", [][2]string{host, {"Content-Type", "application/json; charset=utf-8"}}, `{"user": `))
	s.Add(request("GET", "/api/order?page=3", [][2]string{host, {"Cookie", "sid=x"}}, ""))

	var got []string
	for _, ep := range s.Endpoints() {
		line := fmt.Sprintf("%s %s %d not read %d types %v", ep.Method, ep.Path, ep.Count, ep.BodyNotRead, ep.ContentTypes)
		for _, p := range ep.Params {
			line += fmt.Sprintf(" | %s %s %d %d %v %v", p.In, p.Name, p.Count, p.MaxLength, p.Repeated, p.AllInteger)
		}
		got = append(got, line)
	}
	for _, p := range s.Cookies() {
		got = append(got, fmt.Sprintf("cookie %s %d %d %v %v", p.Name, p.Count, p.MaxLength, p.Repeated, p.AllInteger))
	}
	want := []string{
		"GET /api/order 1 not read 0 types [] | query page 1 1 false true",
		"POST /api/order 2 not read 1 types [application/json] | json items.*.id 1 2 true true | json user 1 3 false false",
		"cookie n 1 1 false true",
		"cookie sid 2 3 true false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("survey\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
