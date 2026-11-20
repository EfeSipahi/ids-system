package analysis_test

import (
	"testing"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

func load(t *testing.T, path string) (*engine.RuleSet, *profile.Set) {
	t.Helper()
	cfg, err := config.Load(path)
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
	return rules, apps
}

func request(host, target string) *httpmodel.Request {
	return httpmodel.New(httpmodel.Received{Method: "GET", Target: target, Version: "HTTP/1.1",
		Headers: []httpmodel.Header{{Name: "Host", Value: host}, {Name: "User-Agent", Value: "test"}, {Name: "Accept", Value: "*/*"}}})
}

// TestRun: without applications there is no profile result; with them
// every request gets one, and its application's exceptions and level
// apply to the rules.
func TestRun(t *testing.T) {
	rules, apps := load(t, "../../configs/crs-first-engine.json")
	res, prof := analysis.Run(rules, apps, request("a", "/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"), nil)
	if total := res.Score("blocking_inbound_anomaly_score"); prof != nil || total < 5 {
		t.Errorf("no applications: profile %v, score %d", prof, total)
	}
	if _, prof := analysis.Run(rules, nil, request("a", "/"), nil); prof != nil {
		t.Errorf("nil set: profile %v", prof)
	}

	rules, apps = load(t, "../../configs/csic-shop.json")
	shop := apps.ByName("csic-shop")
	if shop == nil {
		t.Fatal("csic-shop.json has no application csic-shop")
	}
	_, prof = analysis.Run(rules, apps, request("elsewhere", "/"), nil)
	if prof == nil || prof.App != nil {
		t.Errorf("no application: profile %+v", prof)
	}
	_, prof = analysis.Run(rules, apps, request("localhost:8080", "/no/such/page"), shop)
	if prof == nil || prof.App != shop || len(prof.Findings) == 0 {
		t.Errorf("the shop: profile %+v", prof)
	}
}
