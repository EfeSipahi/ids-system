package engine

// Own rules (docs/development-plan-own-rules.md): rules people write for
// their own sites, kept in a file of their own (OwnRules) that is loaded
// right before CRS's REQUEST-949 file, which adds up the score.
//
// An own rule may only detect (N4): match, add its severity's score at
// level 1 (N6), and say what it found. What could take detection away or
// reach outside the file is refused here, with the reason, before the
// compiler sees the file:
//
//	ctl          switches rules off or changes how the request is read;
//	             turning rules off is what exceptions are for
//	setvar       any other than the score's: it could raise the threshold
//	skipAfter    jumps over the rules after it, the scoring among them
//	@pmFromFile  reads its words from a second file, outside the rule
//
// Which requests a rule is for (N5) is written as tags: application/NAME
// for an application, application/none for requests of no application.
// A rule without such a tag is for every request.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// The ids own rules may use: ModSecurity keeps 1–99,999 for local rules,
// and the dashboard gives them from 1,000 up (N3).
const (
	OwnFirstID = 1000
	OwnLastID  = 99999
)

// ApplicationTag starts the tag that names the application an own rule is
// for, as in application/shop. NoApplicationTag names requests of no
// application.
const (
	ApplicationTag   = "application/"
	NoApplicationTag = "none"
)

// ownSeverities are the severities an own rule may have, with the name of
// the CRS variable that holds their score: critical 5, error 4, warning 3,
// notice 2 (REQUEST-901).
var ownSeverities = map[string]string{"CRITICAL": "critical", "ERROR": "error", "WARNING": "warning", "NOTICE": "notice"}

// OwnScore returns the setvar an own rule of severity adds its score with,
// as written in the rule: tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}.
// It is "" for a severity own rules can't have.
func OwnScore(severity string) string {
	name, ok := ownSeverities[strings.ToUpper(severity)]
	if !ok {
		return ""
	}
	return "tx.inbound_anomaly_score_pl1=+%{tx." + name + "_anomaly_score}"
}

// isScoringFile reports whether file is CRS's REQUEST-949 file, which adds
// up the score; own rules load right before it.
func isScoringFile(file string) bool {
	return strings.HasPrefix(filepath.Base(file), "REQUEST-949-")
}

// addOwnFile reads, checks and compiles the own-rules file. A problem of
// the check is added to c.errs; the file is then not compiled, so that the
// check's reasons come first and alone.
func (c *compiler) addOwnFile(cfg Config) error {
	read := cfg.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	data, err := read(cfg.OwnRules)
	if err != nil {
		return fmt.Errorf("own_rules: %w", err)
	}
	directives, err := seclang.Parse(cfg.OwnRules, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if errs := checkOwn(directives); len(errs) > 0 {
		c.errs = append(c.errs, errs...)
		return nil
	}
	c.own = true
	c.addFile(directives)
	c.own = false
	return nil
}

func checkOwn(directives []seclang.Directive) []error {
	var errs []error
	fail := func(pos seclang.Position, format string, args ...any) {
		errs = append(errs, &seclang.Error{Pos: pos, Msg: fmt.Sprintf(format, args...)})
	}
	for i := 0; i < len(directives); i++ {
		d := directives[i]
		end := i + 1
		for end < len(directives) && directives[end].Chained {
			end++
		}
		if d.Kind == seclang.KindRule {
			checkOwnChain(directives[i:end], fail)
		} else {
			fail(d.Pos, "%s is not allowed in own rules; write each rule as a SecRule with its conditions", d.Kind)
		}
		i = end - 1
	}
	return errs
}

// checkOwnChain checks one rule: its first SecRule and the chained ones
// after it.
func checkOwnChain(chain []seclang.Directive, fail func(seclang.Position, string, ...any)) {
	first := chain[0]
	id := first.ID
	if id < OwnFirstID || id > OwnLastID {
		fail(first.Pos, "rule %d: own rules use ids %d to %d, which ModSecurity keeps for local rules", id, OwnFirstID, OwnLastID)
	}
	if phases := first.ActionValues("phase"); len(phases) > 0 {
		if p := phases[len(phases)-1]; p != "1" && p != "2" {
			fail(first.Pos, "rule %d: phase %s: own rules run in phase 1 (the request's headers) or 2 (its body too)", id, p)
		}
	}
	if len(first.ActionValues("msg")) == 0 {
		fail(first.Pos, "rule %d has no msg; say what the rule finds, as it is shown with every match", id)
	}
	severity := ""
	if values := first.ActionValues("severity"); len(values) == 0 {
		fail(first.Pos, "rule %d has no severity; give CRITICAL, ERROR, WARNING or NOTICE, which sets its score", id)
	} else if severity = values[len(values)-1]; OwnScore(severity) == "" {
		fail(first.Pos, "rule %d: severity %s: give CRITICAL, ERROR, WARNING or NOTICE, which sets its score", id, severity)
		severity = ""
	}
	for _, tag := range first.ActionValues("tag") {
		if level, ok := strings.CutPrefix(tag, "paranoia-level/"); ok && level != "1" {
			fail(first.Pos, "rule %d: tag %s: own rules run at every level and count at level 1; leave the tag out or write paranoia-level/1", id, tag)
		}
		if name, ok := strings.CutPrefix(tag, ApplicationTag); ok && !isOwnAppName(name) {
			fail(first.Pos, "rule %d: tag %s: an application's name has letters, digits, ., - and _, at most 64", id, tag)
		}
	}

	scores := 0
	for i, d := range chain {
		last := i == len(chain)-1
		if op := strings.ToLower(d.Operator.Name); op == "pmfromfile" || op == "pmf" {
			fail(d.Pos, "rule %d: @%s is not allowed in own rules: its words are in another file, outside the rule; write them in the rule with @pm", id, d.Operator.Name)
		}
		for _, a := range d.Actions {
			switch strings.ToLower(a.Name) {
			case "id", "phase", "chain", "msg", "logdata", "severity", "tag", "block", "t", "capture", "multimatch":
				// Allowed. Where in a chain each may stand is the
				// compiler's check, as for every rule.
			case "setvar":
				scores++
				want := OwnScore(severity)
				switch {
				case !last:
					fail(d.Pos, "rule %d: setvar belongs on the last rule of the chain, so that the score is added only when every condition matches", id)
				case want != "" && !sameScore(a.Value, want):
					fail(d.Pos, "rule %d: setvar:%s: an own rule only adds its severity's score: setvar:'%s'", id, a.Value, want)
				}
			case "ctl":
				fail(d.Pos, "rule %d: ctl is not allowed in own rules: it switches rules off or changes how the request is read; turn a rule off with an exception", id)
			case "skipafter":
				fail(d.Pos, "rule %d: skipAfter is not allowed in own rules: it jumps over the rules after it, and the scoring is among them", id)
			default:
				fail(d.Pos, "rule %d: action %s is not allowed in own rules; they use id, phase, block, chain, msg, logdata, severity, tag, t, capture, multiMatch and the score's setvar", id, a.Name)
			}
		}
	}
	switch {
	case scores == 0 && severity != "":
		fail(chain[len(chain)-1].Pos, "rule %d adds no score; end it with setvar:'%s'", id, OwnScore(severity))
	case scores > 1:
		fail(first.Pos, "rule %d adds its score %d times; once, on its last rule, is enough", id, scores)
	}
}

// sameScore compares a setvar with the one wanted, ignoring the case of
// the variable names and spaces around the parts.
func sameScore(got, want string) bool {
	gotName, gotValue, _ := strings.Cut(got, "=")
	wantName, wantValue, _ := strings.Cut(want, "=")
	return strings.EqualFold(strings.TrimSpace(gotName), wantName) && strings.EqualFold(strings.TrimSpace(gotValue), wantValue)
}

// applicationsOf returns the applications an own rule is for, from its
// application/ tags in the order written, or nil for every request.
func applicationsOf(d seclang.Directive) []string {
	var names []string
	for _, tag := range d.ActionValues("tag") {
		if name, ok := strings.CutPrefix(tag, ApplicationTag); ok && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// isOwnAppName is the rule for application names of package profile.
func isOwnAppName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
