package live

import (
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
}

// Analyze analyses one copy and records it. The error is the recorder's.
func (a *Analyzer) Analyze(c *copyframe.Copy) error {
	req := Request(c, a.Parsing)
	live := NewLive(c)
	app := a.application(c, req, live)
	res, prof := analysis.Run(a.Rules, a.Apps, req, app)
	return a.Recorder.AddWith(res.Request, res, prof, live)
}

// application returns the request's application (T6): the one the proxy
// names, or, when it names none, the one of the request's Host and path
// (F3). A name the configuration does not have gives no application, and
// is counted in live.
func (a *Analyzer) application(c *copyframe.Copy, req *httpmodel.Request, live *record.Live) *profile.App {
	name := c.Meta.Application
	if name == "" {
		return a.Apps.Match(req)
	}
	app := a.Apps.ByName(name)
	if app == nil {
		live.UnknownApplication = name
	}
	return app
}
