package seclang

import (
	"errors"
	"strings"
)

// Operator is the test a SecRule applies to each value.
//
//	"@rx ^abc"    Name "rx", Argument "^abc"
//	"!@lt 2"      Name "lt", Argument "2", Negated
//	"^abc"        Name "rx", Argument "^abc" (no @name means @rx)
type Operator struct {
	// Name is the operator name without "@", as written in the file.
	Name string

	// Argument is everything after the name, unchanged. For @rx it is the
	// pattern; it may contain macros such as %{tx.name}.
	Argument string

	// Negated is true when the operator is written with a leading "!".
	Negated bool
}

// String writes the operator back in SecLang form.
func (o Operator) String() string {
	s := "@" + o.Name
	if o.Negated {
		s = "!" + s
	}
	if o.Argument != "" {
		s += " " + o.Argument
	}
	return s
}

func parseOperator(s string) (Operator, error) {
	var op Operator
	rest := strings.TrimLeft(s, " \t")
	if strings.HasPrefix(rest, "!") {
		op.Negated = true
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	if !strings.HasPrefix(rest, "@") {
		op.Name = "rx"
		op.Argument = rest
		return op, nil
	}

	rest = rest[1:]
	end := 0
	for end < len(rest) && isNameChar(rest[end]) {
		end++
	}
	if end == 0 {
		return Operator{}, errors.New("operator name expected after @")
	}
	if end < len(rest) && !isSpace(rest[end]) {
		return Operator{}, errors.New("operator name must be followed by a space")
	}
	op.Name = rest[:end]
	op.Argument = strings.TrimLeft(rest[end:], " \t")
	return op, nil
}
