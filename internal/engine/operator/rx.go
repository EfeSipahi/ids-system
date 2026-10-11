package operator

import (
	"errors"
	"regexp"
)

// maxCaptures is the number of TX.0 to TX.9 slots.
const maxCaptures = 10

// rx is the @rx operator: it matches when the pattern is found anywhere in
// the value.
//
// The pattern is compiled once in newRx. A compiled *regexp.Regexp is safe
// to use from many goroutines at once.
//
// Differences from ModSecurity, which uses the PCRE library:
//
//   - Go's regexp package uses RE2 syntax. It has no backreferences and no
//     lookaround; a pattern that needs them fails in newRx. In exchange,
//     matching time grows only linearly with the input.
//   - Go reads the value as UTF-8 text, PCRE as single bytes. A valid
//     multi-byte character counts as one character here and as several
//     there; each invalid byte counts as one in both. Patterns that only
//     name ASCII characters, such as those of rules 930100 and 930110, are
//     not affected.
//   - A pattern containing a macro is not supported.
type rx struct {
	re *regexp.Regexp
}

func newRx(pattern string) (Operator, error) {
	if hasMacro(pattern) {
		return nil, errors.New("a pattern containing a macro is not supported")
	}
	// (?s) lets "." match a newline, as ModSecurity's PCRE_DOTALL does.
	// "$" already means only the very end of the value in Go, which is
	// what PCRE_DOLLAR_ENDONLY sets.
	re, err := regexp.Compile("(?s)" + pattern)
	if err != nil {
		return nil, err
	}
	return rx{re: re}, nil
}

func (o rx) Match(value string, _ func(string) string) Result {
	m := o.re.FindStringSubmatch(value)
	if m == nil {
		return Result{}
	}
	if len(m) > maxCaptures {
		m = m[:maxCaptures]
	}
	return Result{Matched: true, Captures: m}
}
