package engine

import (
	"fmt"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// A template is text that may contain macros such as %{tx.lfi_score}. It is
// split into parts once, when the rules are loaded, and filled in for each
// request.
type template struct {
	parts []templatePart
	macro bool // true when at least one part is a macro
}

type templatePart struct {
	text string // literal text, used when source is sourceText

	source macroSource
	key    string // the TX variable name, in lower case
	target target // the variable, when source is sourceVariable
}

type macroSource int

const (
	sourceText macroSource = iota
	sourceTX
	sourceMatchedVar
	sourceMatchedVarName
	// sourceVariable is any other variable of the request, such as
	// %{REQUEST_LINE} or %{request_headers.host}. Of a variable with
	// several values the first one is used.
	sourceVariable
)

// parseTemplate splits s at its macros. A macro is %{NAME} or
// %{COLLECTION.key}. A "%" that does not start a complete macro is ordinary
// text.
//
// A macro that names a variable the engine cannot provide is an error, so
// it is found when the rules are loaded and not while a request is checked.
func parseTemplate(s string) (template, error) {
	var t template
	rest := s
	for {
		start := strings.Index(rest, "%{")
		if start < 0 {
			break
		}
		end := strings.IndexByte(rest[start:], '}')
		if end < 0 {
			// "%{" without a closing brace: the rest is text.
			break
		}
		end += start
		if end == start+2 {
			// "%{}" names nothing: keep it as text and look further.
			t.parts = append(t.parts, templatePart{text: rest[:end+1]})
			rest = rest[end+1:]
			continue
		}

		name, key, _ := strings.Cut(rest[start+2:end], ".")
		part := templatePart{}
		switch strings.ToUpper(name) {
		case "TX":
			if key == "" {
				return template{}, fmt.Errorf("macro %s names no TX variable", rest[start:end+1])
			}
			part.source, part.key = sourceTX, strings.ToLower(key)
		case "MATCHED_VAR":
			part.source = sourceMatchedVar
		case "MATCHED_VAR_NAME":
			part.source = sourceMatchedVarName
		default:
			target, err := compileTarget(seclang.Variable{Collection: strings.ToUpper(name), Selector: key})
			if err != nil {
				return template{}, fmt.Errorf("macro %s is not supported", rest[start:end+1])
			}
			part.source, part.target = sourceVariable, target
		}
		if (part.source == sourceMatchedVar || part.source == sourceMatchedVarName) && key != "" {
			return template{}, fmt.Errorf("macro %s is not supported", rest[start:end+1])
		}

		if start > 0 {
			t.parts = append(t.parts, templatePart{text: rest[:start]})
		}
		t.parts = append(t.parts, part)
		t.macro = true
		rest = rest[end+1:]
	}
	if rest != "" {
		t.parts = append(t.parts, templatePart{text: rest})
	}
	return t, nil
}

// expand fills the macros in from one request's state. A TX variable that
// does not exist gives an empty text.
func (t template) expand(tx *transaction) string {
	if len(t.parts) == 1 && t.parts[0].source == sourceText {
		return t.parts[0].text
	}
	var b strings.Builder
	for _, p := range t.parts {
		switch p.source {
		case sourceText:
			b.WriteString(p.text)
		case sourceTX:
			b.WriteString(tx.vars[p.key])
		case sourceMatchedVar:
			b.WriteString(tx.matchedVar)
		case sourceMatchedVarName:
			b.WriteString(tx.matchedVarName)
		case sourceVariable:
			if values := tx.valuesOf(p.target); len(values) > 0 {
				b.WriteString(values[0].value)
			}
		}
	}
	return b.String()
}

// usesRequestContent reports whether the expanded text can contain content
// of the request: the matched value, a regex capture, or a TX variable that
// was itself filled from one of those (tainted).
func (t template) usesRequestContent(tainted map[string]bool) bool {
	for _, p := range t.parts {
		switch p.source {
		case sourceMatchedVar, sourceVariable:
			return true
		case sourceTX:
			if isCaptureKey(p.key) || tainted[p.key] {
				return true
			}
		}
	}
	return false
}

// isCaptureKey reports whether key is one of TX.0 to TX.9, where a rule
// with the capture action stores what its pattern matched.
func isCaptureKey(key string) bool {
	return len(key) == 1 && key[0] >= '0' && key[0] <= '9'
}
