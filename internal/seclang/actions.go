package seclang

import (
	"errors"
	"fmt"
	"strings"
)

// Action is one entry of an action list.
//
//	phase:2                        Name "phase", Value "2"
//	multiMatch                     Name "multiMatch", Value ""
//	setvar:'tx.lfi_score=+5'       Name "setvar", Value "tx.lfi_score=+5"
type Action struct {
	// Name is the action name as written in the file. Compare it without
	// regard to case.
	Name string

	// Value is the text after the colon, with surrounding single quotes
	// removed. It is empty for actions that take no value.
	Value string
}

// parseActions parses a comma-separated action list. A value in single
// quotes may contain commas; inside the quotes \' stands for a quote.
func parseActions(s string) ([]Action, error) {
	var actions []Action
	i := 0
	for {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i == len(s) {
			if len(actions) == 0 {
				return nil, errors.New("empty action list")
			}
			return nil, errors.New("action list ends with a comma")
		}

		start := i
		for i < len(s) && isNameChar(s[i]) {
			i++
		}
		if i == start {
			return nil, fmt.Errorf("action name expected, found %q", s[i])
		}
		a := Action{Name: s[start:i]}

		if i < len(s) && s[i] == ':' {
			i++
			if i < len(s) && s[i] == '\'' {
				value, next, err := scanQuotedValue(s, i)
				if err != nil {
					return nil, fmt.Errorf("action %s: %w", a.Name, err)
				}
				a.Value, i = value, next
			} else {
				vstart := i
				for i < len(s) && s[i] != ',' {
					i++
				}
				a.Value = strings.TrimSpace(s[vstart:i])
			}
		}
		actions = append(actions, a)

		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i == len(s) {
			return actions, nil
		}
		if s[i] != ',' {
			return nil, fmt.Errorf("action %s: unexpected character %q, comma expected", a.Name, s[i])
		}
		i++
	}
}

// scanQuotedValue reads a single-quoted value whose opening quote is at
// s[i]. It returns the value without quotes and the index after the
// closing quote.
func scanQuotedValue(s string, i int) (value string, next int, err error) {
	var b strings.Builder
	i++ // opening quote
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) && s[i+1] == '\'' {
			b.WriteByte('\'')
			i += 2
			continue
		}
		i++
		if c == '\'' {
			return b.String(), i, nil
		}
		b.WriteByte(c)
	}
	return "", 0, errors.New("missing closing single quote")
}
