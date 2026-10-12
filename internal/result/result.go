// Package result turns what the rule engine found into records that can be
// written out.
//
// This is where analysis and recording are separated (M11). The engine
// works with the real values of a request. A record holds what explains the
// result: which rule, where in the request, which score. The values
// themselves, and any rule text built from them, are left out unless the
// caller asks for them with Options.ShowValues.
//
// A record carries the findings of the rule layer only. It is not an alert
// decision; combining layers is a later component (M04, M10).
package result

import (
	"path/filepath"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
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

// categories are the per-attack score variables that CRS keeps, without
// their "_score" ending.
var categories = []string{
	"lfi", "sql_injection", "xss", "rfi", "rce", "php_injection", "http_violation", "session_fixation",
}

// NewRecord builds the record of one request from the engine's result.
func NewRecord(req *httpmodel.Request, res *engine.Result, opt Options) Record {
	rec := Record{
		Method:   req.Received.Method,
		Analysis: newAnalysis(req),
		Findings: []Finding{},
		Score:    newScore(res),
	}
	if opt.ShowValues {
		rec.URI = printable(req.Received.Target)
	}
	for _, m := range res.Matches {
		f := Finding{
			RuleID:   m.RuleID,
			Severity: m.Severity,
			Message:  m.Message,
			Location: printable(m.VarName),
			Action:   m.Action,
			Tags:     m.Tags,
		}
		switch {
		case opt.ShowValues:
			value, data := printable(m.Value), printable(m.Data)
			f.Message = printable(m.Message)
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

func newAnalysis(req *httpmodel.Request) Analysis {
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

func newScore(res *engine.Result) Score {
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

// printable returns s unchanged when it is valid, printable text. Otherwise
// it returns s with control characters and invalid bytes written as escapes
// such as \x00, so that nothing is lost or silently replaced on output.
func printable(s string) string {
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
