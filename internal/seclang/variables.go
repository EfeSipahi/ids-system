package seclang

import (
	"errors"
	"fmt"
	"strings"
)

// Variable is one entry of a SecRule's variable list: where the rule looks.
//
//	ARGS                       Collection "ARGS"
//	REQUEST_HEADERS:Referer    Collection "REQUEST_HEADERS", Selector "Referer"
//	!REQUEST_HEADERS:Referer   the same, with Exclude set
//	&TX:crs_setup_version      Collection "TX", Selector "crs_setup_version", Count set
//	TX:/^header_name_/         Collection "TX", Selector "^header_name_", Regex set
type Variable struct {
	// Collection is the variable name in upper case.
	Collection string

	// Selector picks entries of the collection. It is empty when the whole
	// collection is meant.
	Selector string

	// Regex is true when the selector was written as /.../ and selects
	// every key that matches the pattern.
	Regex bool

	// Exclude is true for a "!" entry: remove this from the list.
	Exclude bool

	// Count is true for a "&" entry: use the number of values, not the values.
	Count bool
}

// String writes the variable back in SecLang form.
func (v Variable) String() string {
	var b strings.Builder
	if v.Exclude {
		b.WriteByte('!')
	}
	if v.Count {
		b.WriteByte('&')
	}
	b.WriteString(v.Collection)
	if v.Selector != "" {
		b.WriteByte(':')
		if v.Regex {
			b.WriteString("/" + v.Selector + "/")
		} else {
			b.WriteString(v.Selector)
		}
	}
	return b.String()
}

// ParseVariables parses a variable list written as in a SecRule, such as
// ARGS|!REQUEST_HEADERS:Referer. Application profiles use it to read the
// variables of their rule exceptions exactly as rule files are read.
func ParseVariables(s string) ([]Variable, error) {
	return parseVariables(s)
}

// parseVariables parses a list such as ARGS|!REQUEST_HEADERS:Referer|XML:/*.
func parseVariables(s string) ([]Variable, error) {
	if s == "" {
		return nil, errors.New("empty variable list")
	}
	var vars []Variable
	i := 0
	for {
		var v Variable
		if i < len(s) && s[i] == '!' {
			v.Exclude = true
			i++
		} else if i < len(s) && s[i] == '&' {
			v.Count = true
			i++
		}

		start := i
		for i < len(s) && isNameChar(s[i]) {
			i++
		}
		if i == start {
			return nil, fmt.Errorf("variable name expected at position %d of %q", start+1, s)
		}
		v.Collection = strings.ToUpper(s[start:i])

		if i < len(s) && s[i] == ':' {
			sel, regex, next, err := scanSelector(v.Collection, s, i+1)
			if err != nil {
				return nil, err
			}
			v.Selector, v.Regex = sel, regex
			i = next
		}
		vars = append(vars, v)

		if i == len(s) {
			return vars, nil
		}
		if s[i] != '|' {
			return nil, fmt.Errorf("unexpected character %q after variable %s", s[i], v)
		}
		i++
	}
}

// scanSelector reads the selector that starts at s[i] and returns it with
// the index of the first character after it.
//
// A selector written as /.../ is a regular expression and may itself contain
// "|", so it ends at a "/" that is followed by "|" or by the end of the
// list. XML selectors are XPath expressions such as /* and are never regular
// expressions.
func scanSelector(collection, s string, i int) (sel string, regex bool, next int, err error) {
	if collection != "XML" && i < len(s) && s[i] == '/' {
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == '/' && (j+1 == len(s) || s[j+1] == '|') {
				if j == i+1 {
					return "", false, 0, fmt.Errorf("empty regular expression selector for %s", collection)
				}
				return s[i+1 : j], true, j + 1, nil
			}
		}
		return "", false, 0, fmt.Errorf("regular expression selector for %s has no closing /", collection)
	}

	end := strings.IndexByte(s[i:], '|')
	if end < 0 {
		end = len(s)
	} else {
		end += i
	}
	if end == i {
		return "", false, 0, fmt.Errorf("empty selector for %s", collection)
	}
	return s[i:end], false, end, nil
}

func isNameChar(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
