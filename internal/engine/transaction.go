package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/engine/operator"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// Match is one logged rule match on one value. A rule that matches in two
// places of a request gives two entries.
//
// Value and Data come from the request and may hold sensitive content. They
// are here for the analysis; what is written to a record is decided by the
// output layer (M11).
type Match struct {
	RuleID   int
	Phase    int
	Message  string
	Severity string
	Tags     []string

	// Action is "pass" or "deny". deny means the rule would block in a
	// blocking deployment; this engine never blocks.
	Action string

	// VarName is where the match was found, such as "ARGS:arg". It is
	// empty for a SecAction, which tests nothing.
	VarName string
	// Value is the value that matched, after the rule's transformations.
	Value string
	// Data is the rule's logdata text with its macros filled in.
	Data string

	// MessageSensitive and DataSensitive are true when Message or Data
	// can contain content of the request, because the rule's text uses the
	// matched value or a capture.
	MessageSensitive bool
	DataSensitive    bool
}

// Result is what the rules produced for one request.
type Result struct {
	// Matches are the matches of rules that log, in the order they
	// happened. Setup and control rules do not log and are not listed.
	Matches []Match

	// Variables are the TX variables at the end, with lower-case names.
	// The anomaly scores are among them.
	Variables map[string]string

	// Request is the request as the rules of phase 2 saw it. It is the one
	// passed to Evaluate, unless a rule chose another body reader; then it
	// is a copy with the body read that way, and its Status says how far
	// that got.
	Request *httpmodel.Request
}

// LogLine returns the match as one line of text, in the bracket form of a
// ModSecurity log line:
//
//	[id "930110"] [msg "Path Traversal Attack (/../)"] [data "Matched Data: ..."]
//
// The CRS regression tests that look at log text are written for that
// form. The line can contain content of the request, so it is for tests and
// not for records.
func (m Match) LogLine() string {
	return fmt.Sprintf("[id %q] [msg %q] [data %q]", strconv.Itoa(m.RuleID), m.Message, m.Data)
}

// LogLines returns the log line of every match.
func (r *Result) LogLines() []string {
	lines := make([]string, len(r.Matches))
	for i, m := range r.Matches {
		lines[i] = m.LogLine()
	}
	return lines
}

// MatchedIDs returns the ids of the rules in Matches, each once, in the
// order of their first match.
func (r *Result) MatchedIDs() []int {
	var ids []int
	seen := map[int]bool{}
	for _, m := range r.Matches {
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			ids = append(ids, m.RuleID)
		}
	}
	return ids
}

// Score returns a TX variable as a number, or 0 if it is not set.
func (r *Result) Score(name string) int {
	return int(operator.ParseInt(r.Variables[name]))
}

// transaction is the working state of one request (M21). It is created by
// Evaluate, used by one goroutine, and dropped when Evaluate returns.
type transaction struct {
	rs  *RuleSet
	req *httpmodel.Request

	vars           map[string]string // TX variables, lower-case names
	matchedVar     string            // %{MATCHED_VAR}
	matchedVarName string            // %{MATCHED_VAR_NAME}
	matches        []Match

	// matchedVars is what the rules of the current chain have matched so
	// far. It is the MATCHED_VARS variable and starts empty for every
	// chain.
	matchedVars []namedValue
	// removedTargets holds the ctl:ruleRemoveTargetByTag actions that ran
	// in this request, and removedRules the ctl:ruleRemoveById and
	// ctl:ruleRemoveByTag actions.
	removedTargets []targetRemoval
	removedRules   []ruleRemoval
	// bodyFormat is the body reader that a ctl:requestBodyProcessor action
	// chose, or "" when none did.
	bodyFormat string

	// valueCache holds the values of variables that depend on the request
	// only, by what they select; see namedValuesOf. collected is memory
	// that collect reuses.
	valueCache map[targetKey][]keyedValue
	collected  []namedValue

	// tuning holds the exceptions of the request's application, or nil.
	tuning *Tuning
}

// Evaluate runs the rules on one request. It does not change the RuleSet or
// the request, and it may be called from many goroutines at once.
func (rs *RuleSet) Evaluate(req *httpmodel.Request) *Result {
	return rs.EvaluateWith(req, nil)
}

// EvaluateWith runs the rules on one request with the exceptions of the
// request's application, made by NewTuning from this RuleSet. A nil t is
// the same as Evaluate. Neither the RuleSet nor t is changed, so both may
// be used by many goroutines at once.
func (rs *RuleSet) EvaluateWith(req *httpmodel.Request, t *Tuning) *Result {
	initial := rs.initial
	if t != nil {
		initial = t.initial
	}
	tx := &transaction{rs: rs, req: req, vars: make(map[string]string, len(initial)), tuning: t}
	for name, value := range initial {
		tx.vars[name] = value
	}
	tx.runPhase(phaseRequestHeaders)
	// The body is read between the two phases. A rule of phase 1 may have
	// chosen another reader than the Content-Type did; the body is then
	// read again with that one. The request passed in stays as it is.
	if tx.bodyFormat != "" && tx.bodyFormat != req.Status.BodyFormat && len(req.Received.Body) > 0 {
		tx.req = req.WithBodyFormat(tx.bodyFormat)
		tx.valueCache = nil // the values were those of the old reading
	}
	tx.runPhase(phaseRequestBody)
	return &Result{Matches: tx.matches, Variables: tx.vars, Request: tx.req}
}

// runPhase runs the rules of one phase in load order. After a rule with
// skipAfter matches, everything up to the named marker is skipped.
func (tx *transaction) runPhase(phase int) {
	skipTo := ""
	for _, it := range tx.rs.phases[phase] {
		if it.rule == nil {
			if it.marker == skipTo {
				skipTo = ""
			}
			continue
		}
		if skipTo != "" || tx.isRemoved(it.rule) {
			continue
		}
		if tx.runChain(it.rule) && it.rule.skipAfter != "" {
			skipTo = it.rule.skipAfter
		}
	}
}

// runChain runs a rule and, while each one matches, the rules chained to
// it. It reports whether the whole chain matched.
func (tx *transaction) runChain(first *rule) bool {
	tx.matchedVars = tx.matchedVars[:0]
	for r := first; r != nil; r = r.next {
		if !tx.runRule(r, first) {
			return false
		}
	}
	return true
}

// runRule tests one rule against all of its values and reports whether any
// of them matched.
func (tx *transaction) runRule(r, first *rule) bool {
	if r.always {
		tx.onMatch(r, first, nil)
		return true
	}

	var expand func(string) string
	if r.opArg.macro {
		expand = func(string) string { return r.opArg.expand(tx) }
	}

	matched := false
	test := func(name, value string) {
		res := r.op.Match(value, expand)
		if !res.Matched {
			return
		}
		matched = true
		tx.matchedVar, tx.matchedVarName = value, name
		tx.matchedVars = append(tx.matchedVars, namedValue{name: name, value: value})
		tx.onMatch(r, first, res.Captures)
	}

	for _, v := range tx.collect(r, first) {
		value := v.value
		if r.multiMatch && len(r.transforms) > 0 {
			// Test the value as received, then again after every
			// transformation that changed it.
			test(v.name, value)
			for _, t := range r.transforms {
				if next := t.Apply(value); next != value {
					value = next
					test(v.name, value)
				}
			}
			continue
		}
		for _, t := range r.transforms {
			value = t.Apply(value)
		}
		test(v.name, value)
	}
	return matched
}

// onMatch does what a rule asks for when one value matched: store the
// captures, run the setvar actions and, on the last rule of a chain, record
// the match.
func (tx *transaction) onMatch(r, first *rule, captures []string) {
	if r.capture && captures != nil {
		for i := 0; i < 10; i++ {
			key := strconv.Itoa(i)
			if i < len(captures) {
				tx.vars[key] = captures[i]
			} else {
				delete(tx.vars, key)
			}
		}
	}

	for _, sv := range r.setvars {
		tx.setvar(sv)
	}
	tx.removedTargets = append(tx.removedTargets, r.removals...)
	tx.removedRules = append(tx.removedRules, r.ruleRemovals...)
	if r.bodyFormat != "" {
		tx.bodyFormat = r.bodyFormat
	}

	if r.next != nil || !first.log {
		return
	}
	m := Match{
		RuleID:           first.id,
		Phase:            first.phase,
		Message:          first.msg.expand(tx),
		Severity:         first.severity,
		Tags:             first.tags,
		Action:           first.action,
		Data:             first.logdata.expand(tx),
		MessageSensitive: first.msgSensitive,
		DataSensitive:    first.logdataSensitive,
	}
	if !r.always {
		m.VarName, m.Value = tx.matchedVarName, tx.matchedVar
	}
	tx.matches = append(tx.matches, m)
}

// isRemoved reports whether the application's exceptions switch the rule
// off, or a ctl action that ran earlier in this request took it out.
func (tx *transaction) isRemoved(r *rule) bool {
	if tx.tuning != nil && tx.tuning.off != nil && tx.tuning.off[r.index] {
		return true
	}
	for _, rr := range tx.removedRules {
		if rr.removes(r) {
			return true
		}
	}
	return false
}

func (tx *transaction) setvar(sv setvar) {
	key := sv.key
	if sv.keyParts.macro {
		key = strings.ToLower(sv.keyParts.expand(tx))
	}
	if sv.unset {
		delete(tx.vars, key)
		return
	}
	value := sv.value.expand(tx)
	if sv.relative {
		// The sign is part of the text, so "+5" and "-5" read as numbers.
		n := operator.ParseInt(tx.vars[key]) + operator.ParseInt(value)
		if n < 0 {
			n = 0 // counters never go below zero
		}
		value = strconv.FormatInt(n, 10)
	}
	tx.vars[key] = value
}
