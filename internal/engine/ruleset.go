// Package engine loads SecLang rules and runs them against requests.
//
// It has two halves, kept apart on purpose (M21):
//
//   - RuleSet: the rules, read, checked and compiled once by Load. After
//     Load returns it is never changed, so any number of requests can use it
//     at the same time.
//   - transaction: the working state of one request: its TX variables,
//     scores and matches. Evaluate creates a new one for every request and
//     nothing else can reach it.
//
// The engine only detects. A rule's deny action is recorded on the match;
// no request is blocked (M09, M15).
package engine

import (
	"github.com/EfeSipahi/ids-system/internal/engine/operator"
	"github.com/EfeSipahi/ids-system/internal/engine/transform"
	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// The request phases. Every phase 1 rule runs before any phase 2 rule.
const (
	phaseRequestHeaders = 1
	phaseRequestBody    = 2
)

// RuleSet is the prepared, read-only set of rules.
type RuleSet struct {
	// phases[p] is what runs in phase p, in load order: the rules of that
	// phase and every marker.
	phases [phaseRequestBody + 1][]item

	statuses    []RuleStatus
	signature   string
	uninspected []string
}

// item is one step of a phase: a rule to run, or a marker to jump to.
type item struct {
	rule   *rule
	marker string
}

// rule is one compiled SecRule or SecAction. For a chain, next points to
// the following rule of the chain.
type rule struct {
	id    int
	pos   seclang.Position
	phase int

	// always is true for a SecAction: there is nothing to test.
	always   bool
	targets  []target
	excludes []target
	op       operator.Operator
	opArg    template // the operator argument, when it contains a macro

	transforms []transform.Transformation
	multiMatch bool
	capture    bool
	setvars    []setvar

	next *rule

	// The fields below are only used on the first rule of a chain.
	log       bool
	action    string // "pass" or "deny"
	skipAfter string
	msg       template
	logdata   template
	// msgSensitive and logdataSensitive say whether the expanded text can
	// contain content of the request (M11).
	msgSensitive     bool
	logdataSensitive bool
	severity         string
	tags             []string
}

// setvar is one compiled setvar action on a TX variable.
type setvar struct {
	key      string // lower case
	unset    bool
	relative bool // the value starts with + or -: add it to the current number
	value    template
}

// RuleStatus says what the engine does with one rule of the loaded files.
type RuleStatus struct {
	ID    int
	Pos   seclang.Position
	Phase int

	// Active is true when the rule runs. Otherwise Reason is the reason
	// given in the configuration for leaving it out.
	Active bool
	Reason string

	// NotInspected lists variables the rule names that the engine cannot
	// provide. The rule runs on its other variables.
	NotInspected []string
}

// Statuses returns one entry for every rule with an id in the loaded files,
// in load order. No rule is left out of this list.
func (rs *RuleSet) Statuses() []RuleStatus {
	return append([]RuleStatus(nil), rs.statuses...)
}

// Signature returns the text of SecComponentSignature, such as
// "OWASP_CRS/4.30.0", or "" if the files have none.
func (rs *RuleSet) Signature() string {
	return rs.signature
}

// NotInspected returns the variables that active rules name but the engine
// cannot provide, such as XML. A request with no match is clean only for
// what was inspected (M05).
func (rs *RuleSet) NotInspected() []string {
	return append([]string(nil), rs.uninspected...)
}
