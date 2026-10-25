package engine

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// TuningSpec is what one application changes in the shared rules (A04,
// decision F5, option B). The rules themselves stay as loaded; a Tuning
// made from the spec is applied to each request of that application.
//
// The spec says nothing about which changes are wise. Which settings a
// profile may change and which rules it may not touch is decided by the
// profile layer, which calls NewTuning only with what it allows.
type TuningSpec struct {
	// ParanoiaLevel is the application's CRS level, 1 to 4, or 0 for the
	// level of the RuleSet (decision F11).
	ParanoiaLevel int

	// Settings are TX variables every request of the application starts
	// with, by lower-case name, such as crs_validate_utf8_encoding. CRS's
	// setup rules only fill a setting that is missing, so these win.
	Settings map[string]string

	// Skips names, for a rule id, the variables the rule stops looking at,
	// written as in a SecRule but without "!": "ARGS_NAMES:pwd" or
	// "ARGS:/^json\./". As with SecRuleUpdateTargetById, only the first
	// rule of a chain is changed.
	Skips map[int][]string

	// Off lists rules that do not run for the application.
	Off []int
}

// Tuning is a TuningSpec prepared for one RuleSet. It is read-only, so one
// Tuning may serve any number of requests at once.
type Tuning struct {
	level   int
	initial map[string]string

	// excludes[i], for the first rule with index i, is its own exclusion
	// list with the skipped variables added, or nil when the application
	// changes nothing there. off[i] is true when the rule does not run.
	// Each table is nil when the application has no entry of its kind.
	excludes [][]target
	off      []bool
}

// ParanoiaLevel returns the level the application's requests run at.
func (t *Tuning) ParanoiaLevel() int {
	return t.level
}

// CheckTarget reports whether s is a variable a rule can be told to skip:
// one entry of a variable list, written without "!" or "&".
func CheckTarget(s string) error {
	_, err := skipTarget(s)
	return err
}

func skipTarget(s string) (target, error) {
	vars, err := seclang.ParseVariables(s)
	if err != nil {
		return target{}, err
	}
	switch v := vars[0]; {
	case len(vars) > 1:
		return target{}, errors.New("give one variable per entry, without |")
	case v.Exclude:
		return target{}, errors.New("write the variable without !; skipping already means leaving it out")
	case v.Count:
		return target{}, errors.New("a count (&) cannot be skipped")
	}
	return compileTarget(vars[0])
}

// NewTuning prepares spec for this RuleSet. It fails when a rule id is not
// an active rule, a variable cannot be read, or the level is out of range.
// The notes name changes that do nothing, such as skipping a variable the
// rule never looks at.
func (rs *RuleSet) NewTuning(spec TuningSpec) (*Tuning, []string, error) {
	t := &Tuning{level: rs.level, initial: make(map[string]string, len(rs.initial)+len(spec.Settings)+1)}
	if spec.ParanoiaLevel != 0 {
		if spec.ParanoiaLevel < 1 || spec.ParanoiaLevel > MaxParanoiaLevel {
			return nil, nil, fmt.Errorf("paranoia level %d is not supported; it must be 1 to %d", spec.ParanoiaLevel, MaxParanoiaLevel)
		}
		t.level = spec.ParanoiaLevel
	}
	for name, value := range rs.initial {
		t.initial[name] = value
	}
	for name, value := range spec.Settings {
		if !isSettingName(name) {
			return nil, nil, fmt.Errorf("setting %q: a TX variable name has lower-case letters, digits and _ only", name)
		}
		if name == "blocking_paranoia_level" || name == "detection_paranoia_level" {
			return nil, nil, fmt.Errorf("setting %s: give the paranoia level as the level, not as a setting", name)
		}
		if r := rs.overwriter(name); r != nil {
			return nil, nil, fmt.Errorf("setting %s: rule %d (%s:%d) also sets it while a request runs, so the application's value would be overwritten; remove the setting from that rule, or from the application", name, r.id, filepath.Base(r.pos.File), r.pos.Line)
		}
		t.initial[name] = value
	}
	t.initial["blocking_paranoia_level"] = strconv.Itoa(t.level)

	var notes []string
	ids := make([]int, 0, len(spec.Skips))
	for id := range spec.Skips {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		r, ok := rs.byID[id]
		if !ok {
			return nil, nil, fmt.Errorf("rule %d is not an active rule", id)
		}
		extra := []target{}
		for _, s := range spec.Skips[id] {
			tg, err := skipTarget(s)
			if err != nil {
				return nil, nil, fmt.Errorf("rule %d, variable %q: %v", id, s, err)
			}
			if !slices.ContainsFunc(r.targets, func(own target) bool { return own.col == tg.col }) {
				notes = append(notes, fmt.Sprintf("rule %d does not look at %s, so skipping %s changes nothing", id, tg.name, s))
			}
			extra = append(extra, tg)
		}
		if len(extra) == 0 {
			continue
		}
		if t.excludes == nil {
			t.excludes = make([][]target, rs.chains)
		}
		t.excludes[r.index] = append(slices.Clone(r.excludes), extra...)
	}
	for _, id := range spec.Off {
		r, ok := rs.byID[id]
		if !ok {
			return nil, nil, fmt.Errorf("rule %d is not an active rule", id)
		}
		if t.off == nil {
			t.off = make([]bool, rs.chains)
		}
		t.off[r.index] = true
	}
	return t, notes, nil
}

// overwriter returns the first rule that sets the TX variable name while a
// request runs, or nil. A setup file's SecAction does that, and its value
// would replace an application's. CRS's own defaults don't count: a rule
// that tests &TX:name first only fills the variable when it is missing.
// Nor does a setvar that adds to the value it finds, such as CRS's rules
// 901360 and 901370, which add JSON types to allowed_request_content_type.
func (rs *RuleSet) overwriter(name string) *rule {
	for _, items := range rs.phases {
		for _, it := range items {
			first := it.rule
			if first == nil {
				continue
			}
			if len(first.targets) == 1 && first.targets[0].count && first.targets[0].col == colTX && strings.EqualFold(first.targets[0].selector, name) {
				continue
			}
			for r := first; r != nil; r = r.next {
				for _, sv := range r.setvars {
					if !sv.unset && !sv.keyParts.macro && sv.key == name && !sv.relative && !sv.value.refersTo(name) {
						return first
					}
				}
			}
		}
	}
	return nil
}

// refersTo reports whether the template uses the TX variable name, as in
// tx.allowed_request_content_type=%{tx.allowed_request_content_type} |x|:
// such a setvar adds to the value it finds instead of replacing it.
func (t template) refersTo(name string) bool {
	for _, p := range t.parts {
		if p.source == sourceTX && p.key == name {
			return true
		}
	}
	return false
}

func isSettingName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
