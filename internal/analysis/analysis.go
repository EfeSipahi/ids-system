// Package analysis is the one analysis of a request that every input runs:
// ids-offline for request files, ids-live for copies from a proxy, and the
// dashboard's test tab for a request a person writes
// (docs/development-plan-test-tab.md, stage 3). Keeping it in one place
// means the three can't give different results for the same request.
package analysis

import (
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// Run evaluates the rules on req with the exceptions and the paranoia
// level of its application (F5, F11), and then checks req against that
// application's profile. The caller chooses the application: by the name a
// proxy gives, by -application, or by Host and path (apps.Match, F3); nil
// means no application.
//
// The profile result is nil when the configuration has no applications,
// since then there is no profile layer at all.
func Run(rules *engine.RuleSet, apps *profile.Set, req *httpmodel.Request, app *profile.App) (*engine.Result, *profile.Result) {
	var tuning *engine.Tuning
	if app != nil {
		tuning = app.Tuning
	}
	res := rules.EvaluateWith(req, tuning)
	if apps == nil || len(apps.Apps()) == 0 {
		return res, nil
	}
	checked := apps.Check(res.Request, app)
	return res, &checked
}
