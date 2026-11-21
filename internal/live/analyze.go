package live

import (
	"sync"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// Analyzer runs for each copy what ids-offline runs for each request: it
// finds the application, runs analysis.Run (the rules with the
// application's exceptions and level, then the profile), and records the
// result. It is safe for use by many workers: the rules and the
// applications are only read (M21), and the recorder is safe for many
// goroutines.
type Analyzer struct {
	Rules    *engine.RuleSet
	Apps     *profile.Set
	Recorder *record.Recorder
	// Parsing are the options for reading each request, such as the body
	// limit (T3).
	Parsing httpmodel.Options

	// mu guards Rules, Apps and Parsing, which Use replaces while the
	// workers run.
	mu sync.RWMutex
}

// Use makes the copies analysed from now on use new rules, applications
// and options (W13 of docs/development-plan-dashboard-control.md). A copy
// being analysed finishes with the ones it started with.
func (a *Analyzer) Use(rules *engine.RuleSet, apps *profile.Set, parsing httpmodel.Options) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Rules, a.Apps, a.Parsing = rules, apps, parsing
}

// Analyze analyses one copy and records it. The error is the recorder's.
func (a *Analyzer) Analyze(c *copyframe.Copy) error {
	a.mu.RLock()
	rules, apps, parsing := a.Rules, a.Apps, a.Parsing
	a.mu.RUnlock()
	req := Request(c, parsing)
	live := NewLive(c)
	app := application(apps, c, req, live)
	res, prof := analysis.Run(rules, apps, req, app)
	return a.Recorder.AddWith(res.Request, res, prof, live)
}

// application returns the request's application (T6): the one the proxy
// names, or, when it names none, the one of the request's Host and path
// (F3). A name the configuration does not have gives no application, and
// is counted in live.
func application(apps *profile.Set, c *copyframe.Copy, req *httpmodel.Request, live *record.Live) *profile.App {
	name := c.Meta.Application
	if name == "" {
		return apps.Match(req)
	}
	app := apps.ByName(name)
	if app == nil {
		live.UnknownApplication = name
	}
	return app
}
