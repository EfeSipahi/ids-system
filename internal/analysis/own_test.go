package analysis_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// everyPath is the profile the dashboard gives a new application: every
// path and parameter, in monitor mode.
const everyPath = `{"mode": "monitor", "endpoints": [{"methods": ["GET", "POST"], "path": "/*", "other_params": "allow"}]}`

// ownProduct writes CRS's first-engine configuration with the own rules of
// testdata and the given applications, all with the every-path profile.
func ownProduct(t *testing.T, own string, apps ...string) string {
	t.Helper()
	data, err := os.ReadFile("../../configs/crs-first-engine.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	base, err := filepath.Abs("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range cfg["files"].([]any) {
		cfg["files"].([]any)[i] = filepath.Join(base, f.(string))
	}
	delete(cfg, "records")
	dir := t.TempDir()
	if own != "" {
		if cfg["own_rules"], err = filepath.Abs(own); err != nil {
			t.Fatal(err)
		}
	}
	var list []map[string]any
	for _, name := range apps {
		list = append(list, map[string]any{"name": name, "hosts": []string{name + ".test"}, "profile": "every-path.json"})
	}
	if list != nil {
		cfg["applications"] = list
	}
	if err := os.WriteFile(filepath.Join(dir, "every-path.json"), []byte(everyPath), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ids.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func from(host, target, addr string, headers ...httpmodel.Header) *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{Method: "GET", Target: target, Version: "HTTP/1.1", RemoteAddr: addr,
		Headers: append([]httpmodel.Header{{Name: "Host", Value: host}, {Name: "User-Agent", Value: "test"}, {Name: "Accept", Value: "*/*"}}, headers...)})
}

// Each own rule runs for the applications it names (N5 of
// docs/development-plan-own-rules.md): 1000 for shop only, 1001 for every
// request, 1002 for requests of no application only. With CRS's own
// scoring, a critical rule alone makes an alert.
func TestOwnRulesByApplication(t *testing.T) {
	rules, apps := load(t, ownProduct(t, "../../testdata/own-rules/own-rules.conf", "shop", "blog"))
	scanner := httpmodel.Header{Name: "User-Agent", Value: "evil-scanner"}
	for _, c := range []struct {
		name  string
		req   *httpmodel.Request
		rules []int
		score int
	}{
		{"shop admin from outside", from("shop.test", "/admin", "203.0.113.5"), []int{1000}, 5},
		{"shop admin from the office", from("shop.test", "/admin", "10.1.2.3"), nil, 0},
		{"blog admin from outside", from("blog.test", "/admin", "203.0.113.5"), nil, 0},
		{"no application's admin", from("other.test", "/admin", "203.0.113.5"), nil, 0},
		{"a scanner on the blog", from("blog.test", "/", "203.0.113.5", scanner), []int{1001}, 3},
		{"a scanner of no application", from("other.test", "/", "203.0.113.5", scanner), []int{1001}, 3},
		{"no application's debug page", from("other.test", "/debug", "203.0.113.5"), []int{1002}, 4},
		{"the shop's debug page", from("shop.test", "/debug", "203.0.113.5"), nil, 0},
	} {
		req := c.req
		res, _ := analysis.Run(rules, apps, req, apps.Match(req))
		var own []int
		for _, id := range res.MatchedIDs() {
			if id < 100000 {
				own = append(own, id)
			}
		}
		if !slices.Equal(own, c.rules) {
			t.Errorf("%s: own rules %v, want %v (all %v)", c.name, own, c.rules, res.MatchedIDs())
		}
		if got := res.Score("blocking_inbound_anomaly_score"); got != c.score {
			t.Errorf("%s: score %d, want %d", c.name, got, c.score)
		}
	}
}

// Without own rules for some applications only, requests of no application
// run with no tuning, as before own rules.
func TestNoApplicationTuning(t *testing.T) {
	_, apps := load(t, ownProduct(t, "", "shop"))
	if apps.NoApplicationTuning() != nil {
		t.Error("a tuning without own rules")
	}
	dir := t.TempDir()
	own := filepath.Join(dir, "own.conf")
	rule := `SecRule REQUEST_FILENAME "@streq /x" "id:1000,phase:1,block,msg:'x',severity:'NOTICE',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}'"`
	if err := os.WriteFile(own, []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	_, apps = load(t, ownProduct(t, own, "shop"))
	if apps.NoApplicationTuning() != nil {
		t.Error("a tuning with an own rule for every request")
	}
}

// An own rule for an application the configuration doesn't have is an
// error that names the rule, its file and line, and the application.
func TestOwnRuleOfAnUnknownApplication(t *testing.T) {
	cfg, err := config.Load(ownProduct(t, "../../testdata/own-rules/own-rules.conf", "blog"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err == nil || !strings.Contains(err.Error(), "own rule 1000 (own-rules.conf:9) is for the application shop, which the configuration does not have") {
		t.Errorf("%v", err)
	}
}
