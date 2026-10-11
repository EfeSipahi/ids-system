// Package operator implements SecLang operators: the test a rule applies to
// a value after its transformations have run.
//
// An Operator is prepared once, when the rules are loaded, and is then used
// by many requests at the same time (M21). It keeps no per-request data, so
// that is safe.
//
// Behaviour follows ModSecurity v2 (apache2/re_operators.c).
package operator

import (
	"fmt"
	"strings"
)

// Result is the outcome of testing one value.
type Result struct {
	Matched bool

	// Captures holds what a regular expression matched: the whole match
	// first, then each group, at most ten entries. A rule with the capture
	// action stores them in TX.0 to TX.9. It is nil when nothing matched
	// and for operators that capture nothing.
	Captures []string
}

// Operator tests values.
type Operator interface {
	// Match tests value. expand replaces macros such as %{tx.name} with
	// their current text; an operator calls it only when its argument
	// contains a macro.
	Match(value string, expand func(string) string) Result
}

type constructor func(argument string) (Operator, error)

// constructors returns the operators by lower-case name. dir is the
// directory that data files are looked up in.
func constructors(dir string) map[string]constructor {
	numeric := func(compare func(left, right int64) bool) constructor {
		return func(argument string) (Operator, error) { return newNumeric(argument, compare), nil }
	}
	return map[string]constructor{
		"rx":                newRx,
		"eq":                numeric(func(l, r int64) bool { return l == r }),
		"lt":                numeric(func(l, r int64) bool { return l < r }),
		"ge":                numeric(func(l, r int64) bool { return l >= r }),
		"pm":                newPm,
		"pmfromfile":        newPmFromFile(dir),
		"contains":          newContains,
		"validatebyterange": newByteRange,
		"streq":             newStreq,
		"detectsqli":        func(string) (Operator, error) { return detectSQLi{}, nil },
		"detectxss":         func(string) (Operator, error) { return detectXSS{}, nil },
	}
}

// Supported reports whether an operator called name is implemented. Names
// are compared without regard to case.
func Supported(name string) bool {
	_, ok := constructors("")[strings.ToLower(name)]
	return ok
}

// New prepares the operator @name with its argument. With negated set, the
// result is the opposite test, as written with "!@name". dir is the
// directory of the rule file; an operator that reads a data file looks for
// it there.
//
// An operator that is not implemented, or an argument the operator cannot
// use, is an error. The caller reports it when the rules are loaded.
func New(name, argument string, negated bool, dir string) (Operator, error) {
	build, ok := constructors(dir)[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("operator @%s is not supported", name)
	}
	op, err := build(argument)
	if err != nil {
		return nil, fmt.Errorf("@%s: %w", name, err)
	}
	if negated {
		op = not{op}
	}
	return op, nil
}

// not inverts another operator. A negated test has nothing to capture.
type not struct {
	inner Operator
}

func (n not) Match(value string, expand func(string) string) Result {
	return Result{Matched: !n.inner.Match(value, expand).Matched}
}

// hasMacro reports whether s contains the start of a macro.
func hasMacro(s string) bool {
	return strings.Contains(s, "%{")
}
