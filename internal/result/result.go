// Package result turns what the rule engine found into records that can be
// written out.
//
// This is where analysis and recording are separated (M11). The engine
// works with the real values of a request. A record holds what explains the
// result: which rule, where in the request, which score. The values
// themselves, and any rule text built from them, are left out unless the
// caller asks for them with Options.ShowValues.
//
// A record carries the findings of the rule layer and, for a request of an
// application with a profile, those of the profile layer, side by side
// (M10). It is not a combined decision; that is a later component (M04).
package result

import (
	"path/filepath"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// Hidden replaces a rule text that contains request content.
const Hidden = "[hidden: contains request content]"

// Options controls what a record may contain.
type Options struct {
	// ShowValues adds matched values, rule texts built from them, and the
	// request URI. It is meant for looking at test data on one's own
	// machine, never for stored records.
	ShowValues bool
}

// Startup describes the loaded rules: what runs, what does not, and why.
type Startup struct {
	Ruleset       string         `json:"ruleset"`
	ParanoiaLevel int            `json:"paranoia_level"`
	ActiveRules   int            `json:"active_rules"`
	ExcludedRules []ExcludedRule `json:"excluded_rules"`

	// IgnoredTargetUpdates are rule ids named by SecRuleUpdateTargetById
	// lines that changed nothing, because the rule is not loaded or is
	// excluded.
	IgnoredTargetUpdates []int `json:"ignored_target_updates"`

	// Applications are set when the configuration has applications (F9,
	// F11), and RequireProfile when a request of no application is a
	// finding (F7).
	Applications   []AppStartup `json:"applications,omitempty"`
	RequireProfile bool         `json:"require_profile,omitempty"`
}

// AppStartup describes one application: where its requests come from, its
// profile, and what its exceptions change in the rules.
type AppStartup struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Paths []string `json:"paths,omitempty"`
	// Profile is the profile's file name.
	Profile       string `json:"profile"`
	Mode          string `json:"mode"`
	ParanoiaLevel int    `json:"paranoia_level"`
	// Exceptions are the profile's rule exceptions, each with its reason
	// and, when it changes nothing at the moment, why not.
	Exceptions []profile.ExceptionStatus `json:"exceptions"`
	// Notes name exceptions that change nothing, as text for people.
	Notes []string `json:"notes,omitempty"`
}

// ExcludedRule is one rule that is in the loaded files but does not run.
type ExcludedRule struct {
	ID     int    `json:"id"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

// NewStartup builds the startup report of a rule set.
func NewStartup(rs *engine.RuleSet) Startup {
	s := Startup{
		Ruleset:              rs.Signature(),
		ParanoiaLevel:        rs.ParanoiaLevel(),
		ExcludedRules:        []ExcludedRule{},
		IgnoredTargetUpdates: rs.IgnoredTargetUpdates(),
	}
	if s.IgnoredTargetUpdates == nil {
		s.IgnoredTargetUpdates = []int{}
	}
	for _, st := range rs.Statuses() {
		if st.Active {
			s.ActiveRules++
			continue
		}
		s.ExcludedRules = append(s.ExcludedRules, ExcludedRule{
			ID:     st.ID,
			File:   filepath.Base(st.Pos.File),
			Line:   st.Pos.Line,
			Reason: st.Reason,
		})
	}
	return s
}

// SetApplications adds the applications of set to the report.
func (s *Startup) SetApplications(set *profile.Set) {
	s.RequireProfile = set.RequireProfile()
	s.Applications = AppStartups(set)
}

// AppStartups describes the applications of set, or returns nil when it
// has none.
func AppStartups(set *profile.Set) []AppStartup {
	var apps []AppStartup
	for _, a := range set.Apps() {
		app := AppStartup{
			Name:          a.Name,
			Hosts:         a.Hosts,
			Paths:         a.Paths,
			Profile:       filepath.Base(a.Profile.Path),
			Mode:          a.Profile.Mode,
			ParanoiaLevel: a.ParanoiaLevel(),
			Exceptions:    a.Exceptions,
			Notes:         a.Notes,
		}
		if app.Exceptions == nil {
			app.Exceptions = []profile.ExceptionStatus{}
		}
		apps = append(apps, app)
	}
	return apps
}

// Record is the outcome for one request.
type Record struct {
	Method string `json:"method"`
	// URI is only set with Options.ShowValues.
	URI string `json:"uri,omitempty"`

	Analysis Analysis  `json:"analysis"`
	Findings []Finding `json:"findings"`
	Score    Score     `json:"score"`
}

// Analysis says how much of the request was inspected (M05). A request
// with no finding is clean only as far as Complete says.
type Analysis struct {
	// Complete is false when part of the request could not be inspected.
	Complete bool `json:"complete"`

	// Body is "empty", "inspected", "partly inspected" or "not inspected".
	Body string `json:"body"`
	// BodyFormat is the parser used: "form", "json", "multipart" or "xml".
	BodyFormat string  `json:"body_format,omitempty"`
	BodyReason string  `json:"body_reason,omitempty"`
	Issues     []Issue `json:"issues,omitempty"`
}

// Issue is something the request parser noticed.
type Issue struct {
	Part    string `json:"part"`
	Message string `json:"message"`
}

// Finding is one match of a rule that logs.
type Finding struct {
	RuleID   int    `json:"rule_id"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message"`

	// Location is where in the request the rule matched, such as
	// "ARGS:arg" or "REQUEST_HEADERS:User-Agent".
	Location string `json:"location,omitempty"`

	// Action is what the rule asks for: "pass" or "deny". Nothing is
	// blocked; deny is information.
	Action string   `json:"action"`
	Tags   []string `json:"tags,omitempty"`

	// Value and Data are only set with Options.ShowValues.
	Value *string `json:"value,omitempty"`
	Data  *string `json:"data,omitempty"`
}

// Score is the CRS anomaly score of the request.
type Score struct {
	// Total is the inbound anomaly score that CRS compares with Threshold.
	Total     int  `json:"total"`
	Threshold int  `json:"threshold"`
	Exceeded  bool `json:"exceeded"`

	// Categories holds the scores per attack type that are above zero,
	// for example "lfi".
	Categories map[string]int `json:"categories,omitempty"`
}

// Application is the application a request belongs to (F9, F11). It is
// given only when the configuration has applications.
type Application struct {
	// Name is the application's name, or profile.NoApplication ("none")
	// when no application has the request's host and path.
	Name string `json:"name"`
	// ParanoiaLevel is the level the request's rules ran at.
	ParanoiaLevel int `json:"paranoia_level"`
	// Mode is the profile's mode, "monitor" or "alert". It is left out
	// for a request of no application.
	Mode string `json:"mode,omitempty"`
}

// NewApplication describes the application of a request; app is nil for
// a request of no application, whose rules ran at the configuration's
// level, defaultLevel.
func NewApplication(app *profile.App, defaultLevel int) Application {
	if app == nil {
		return Application{Name: profile.NoApplication, ParanoiaLevel: defaultLevel}
	}
	return Application{Name: app.Name, ParanoiaLevel: app.ParanoiaLevel(), Mode: app.Profile.Mode}
}

// Profile is what the profile layer found in one request (F6). It is kept
// apart from the rule findings and the score (M10).
type Profile struct {
	// Findings never hold a value of the request (M11).
	Findings []profile.Finding `json:"findings"`
	// BodyChecked is false when the body was not read to its end, so its
	// parameters were not judged (M05).
	BodyChecked bool `json:"body_checked"`
}

// NewProfile returns the profile part of a record, or nil when there is
// nothing to say: the request has no application and no finding.
func NewProfile(res profile.Result) *Profile {
	if res.App == nil && len(res.Findings) == 0 {
		return nil
	}
	p := &Profile{Findings: res.Findings, BodyChecked: res.BodyChecked}
	if p.Findings == nil {
		p.Findings = []profile.Finding{}
	}
	return p
}

// What made a request an alert (F6): the rules' anomaly score, and the
// profile's findings when the profile's mode is "alert".
const (
	AlertByRules   = "rules"
	AlertByProfile = "profile"
)

// AlertBy names what made the request an alert, or returns nil when it is
// not one.
func AlertBy(score Score, prof profile.Result) []string {
	var by []string
	if score.Exceeded {
		by = append(by, AlertByRules)
	}
	if prof.Alert() {
		by = append(by, AlertByProfile)
	}
	return by
}

// categories are the per-attack score variables that CRS keeps, without
// their "_score" ending.
var categories = []string{
	"lfi", "sql_injection", "xss", "rfi", "rce", "php_injection", "http_violation", "session_fixation",
}

// NewRecord builds the record of one request from the engine's result.
func NewRecord(req *httpmodel.Request, res *engine.Result, opt Options) Record {
	rec := Record{
		Method:   req.Received.Method,
		Analysis: NewAnalysis(req),
		Findings: []Finding{},
		Score:    NewScore(res),
	}
	if opt.ShowValues {
		rec.URI = Printable(req.Received.Target)
	}
	for _, m := range res.Matches {
		f := Finding{
			RuleID:   m.RuleID,
			Severity: m.Severity,
			Message:  m.Message,
			Location: Printable(m.VarName),
			Action:   m.Action,
			Tags:     m.Tags,
		}
		switch {
		case opt.ShowValues:
			value, data := Printable(m.Value), Printable(m.Data)
			f.Message = Printable(m.Message)
			f.Value = &value
			if m.Data != "" {
				f.Data = &data
			}
		case m.MessageSensitive:
			f.Message = Hidden
		}
		rec.Findings = append(rec.Findings, f)
	}
	return rec
}

// NewAnalysis says how far the request was inspected (M05).
func NewAnalysis(req *httpmodel.Request) Analysis {
	a := Analysis{
		Complete:   req.Status.Body.Complete(),
		Body:       req.Status.Body.String(),
		BodyFormat: req.Status.BodyFormat,
		BodyReason: req.Status.BodyReason,
	}
	for _, issue := range req.Status.Issues {
		a.Issues = append(a.Issues, Issue{Part: issue.Part, Message: issue.Message})
	}
	return a
}

// NewScore reads the anomaly scores the CRS rules left in the TX variables.
func NewScore(res *engine.Result) Score {
	s := Score{
		Total:     res.Score("blocking_inbound_anomaly_score"),
		Threshold: res.Score("inbound_anomaly_score_threshold"),
	}
	s.Exceeded = s.Threshold > 0 && s.Total >= s.Threshold
	for _, name := range categories {
		if n := res.Score(name + "_score"); n > 0 {
			if s.Categories == nil {
				s.Categories = map[string]int{}
			}
			s.Categories[name] = n
		}
	}
	return s
}

// Printable returns s unchanged when it is valid, printable text. Otherwise
// it returns s with control characters and invalid bytes written as escapes
// such as \x00, so that nothing is lost or silently replaced on output.
func Printable(s string) string {
	clean := utf8.ValidString(s)
	if clean {
		for _, r := range s {
			if !unicode.IsPrint(r) {
				clean = false
				break
			}
		}
	}
	if clean {
		return s
	}
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
}
