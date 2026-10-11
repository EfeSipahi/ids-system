package engine

import (
	"strconv"

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
}

// Evaluate runs the rules on one request. It does not change the RuleSet or
// the request, and it may be called from many goroutines at once.
func (rs *RuleSet) Evaluate(req *httpmodel.Request) *Result {
	tx := &transaction{rs: rs, req: req, vars: map[string]string{}}
	tx.runPhase(phaseRequestHeaders)
	tx.runPhase(phaseRequestBody)
	return &Result{Matches: tx.matches, Variables: tx.vars}
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
		if skipTo != "" {
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
		tx.onMatch(r, first, res.Captures)
	}

	for _, v := range tx.collect(r) {
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

func (tx *transaction) setvar(sv setvar) {
	if sv.unset {
		delete(tx.vars, sv.key)
		return
	}
	value := sv.value.expand(tx)
	if sv.relative {
		// The sign is part of the text, so "+5" and "-5" read as numbers.
		n := operator.ParseInt(tx.vars[sv.key]) + operator.ParseInt(value)
		if n < 0 {
			n = 0 // counters never go below zero
		}
		value = strconv.FormatInt(n, 10)
	}
	tx.vars[sv.key] = value
}
