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
	"regexp"

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

	statuses  []RuleStatus
	signature string

	// initial holds the TX variables every request starts with. They are
	// the settings of the configuration, such as the paranoia level.
	initial map[string]string
	level   int

	// ignoredUpdates are the rule ids of SecRuleUpdateTargetById lines
	// whose rule is not active, one entry per line.
	ignoredUpdates []int

	// byID holds the first rule of every active chain, and chains counts
	// them. A rule's index is its place among them; a Tuning's tables are
	// indexed by it.
	byID   map[int]*rule
	chains int
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
	// index is the place of a chain's first rule among the first rules of
	// all active chains, from 0. It is not set on chained rules.
	index int

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
	removals   []targetRemoval
	// ruleRemovals are the ctl:ruleRemoveById and ctl:ruleRemoveByTag
	// actions: rules that do not run for the rest of the request.
	ruleRemovals []ruleRemoval
	// bodyFormat is set by ctl:requestBodyProcessor: the body reader to
	// use, as httpmodel names it ("form", "json", ...).
	bodyFormat string

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
	key string // lower case
	// keyParts is set when the name contains a macro, as in
	// tx.rfi_parameter_%{MATCHED_VAR_NAME}. The name is then built for
	// each match and key is not used.
	keyParts template
	unset    bool
	relative bool // the value starts with + or -: add it to the current number
	value    template
}

// ruleRemoval is a compiled ctl:ruleRemoveById or ctl:ruleRemoveByTag
// action. It names rules by id, from first to last, or by a tag pattern.
type ruleRemoval struct {
	first, last int
	tag         *regexp.Regexp
}

// removes reports whether the removal applies to a rule.
func (rr ruleRemoval) removes(r *rule) bool {
	if rr.tag == nil {
		return r.id >= rr.first && r.id <= rr.last
	}
	for _, tag := range r.tags {
		if rr.tag.MatchString(tag) {
			return true
		}
	}
	return false
}

// targetRemoval is a compiled ctl:ruleRemoveTargetByTag=TAG;VARIABLE action.
// When its rule matches, every rule with a tag that fits stops looking at
// the variable for the rest of the request.
type targetRemoval struct {
	tag    *regexp.Regexp
	target target
}

// RuleStatus says what the engine does with one rule of the loaded files.
type RuleStatus struct {
	ID    int
	Pos   seclang.Position
	Phase int

	// ParanoiaLevel is the CRS level the rule belongs to, read from its
	// tag "paranoia-level/N". It is 0 for a rule without that tag, such as
	// a setup or scoring rule. A rule runs when the configured level is at
	// least its own; the CRS files decide that with their own gate rules.
	ParanoiaLevel int

	// Msg is the rule's msg text as written, with any macro such as
	// %{MATCHED_VAR} left unexpanded. It is "" for a rule without one.
	Msg string

	// Active is true when the rule runs. Otherwise Reason is the reason
	// given in the configuration for leaving it out.
	Active bool
	Reason string
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

// ParanoiaLevel returns the CRS paranoia level the rules run at.
func (rs *RuleSet) ParanoiaLevel() int {
	return rs.level
}

// IgnoredTargetUpdates returns the rule ids named by SecRuleUpdateTargetById
// lines that changed nothing, because the rule is not loaded or is
// excluded. Each id is listed once, in the order first seen.
func (rs *RuleSet) IgnoredTargetUpdates() []int {
	var ids []int
	seen := map[int]bool{}
	for _, id := range rs.ignoredUpdates {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}
