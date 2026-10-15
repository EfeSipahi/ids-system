// Package transform implements SecLang transformations: the t: actions a
// rule applies to a value before its operator tests it.
//
// A transformation takes a value and returns a new one. It never changes
// its input, so the shared request stays untouched (M16). Values are Go
// strings used as byte sequences; they may hold NUL bytes and invalid UTF-8.
//
// Behaviour follows ModSecurity v2 (apache2/msc_util.c and re_tfns.c).
// Known differences are listed on each function.
package transform

import (
	"fmt"
	"strings"
)

// Transformation is one named transformation.
type Transformation struct {
	// Name is the canonical spelling, for example "urlDecodeUni".
	Name string
	// Apply returns the transformed value.
	Apply func(string) string
}

var registry = []Transformation{
	{Name: "utf8toUnicode", Apply: UTF8ToUnicode},
	{Name: "urlDecodeUni", Apply: URLDecodeUni},
	{Name: "removeNulls", Apply: RemoveNulls},
	{Name: "cmdLine", Apply: CmdLine},
	{Name: "normalizePath", Apply: NormalizePath},
	{Name: "normalizePathWin", Apply: NormalizePathWin},
	{Name: "escapeSeqDecode", Apply: EscapeSeqDecode},
	{Name: "base64Decode", Apply: Base64Decode},
	{Name: "replaceComments", Apply: ReplaceComments},
	{Name: "removeCommentsChar", Apply: RemoveCommentsChar},
	{Name: "removeWhitespace", Apply: RemoveWhitespace},
	{Name: "compressWhitespace", Apply: CompressWhitespace},
	{Name: "lowercase", Apply: Lowercase},
	{Name: "htmlEntityDecode", Apply: HTMLEntityDecode},
	{Name: "jsDecode", Apply: JSDecode},
	{Name: "cssDecode", Apply: CSSDecode},
	{Name: "length", Apply: Length},
}

// Lookup finds a transformation by name, without regard to case.
func Lookup(name string) (Transformation, bool) {
	for _, t := range registry {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return Transformation{}, false
}

// Resolve turns the t: values of a rule into the transformations to run, in
// order. "none" is not a transformation: it discards everything listed
// before it, which is how a rule drops inherited defaults. A name that is
// not implemented is an error, so a rule is never run with a step missing.
func Resolve(names []string) ([]Transformation, error) {
	var chain []Transformation
	for _, name := range names {
		if strings.EqualFold(name, "none") {
			chain = nil
			continue
		}
		t, ok := Lookup(name)
		if !ok {
			return nil, fmt.Errorf("transformation %q is not supported", name)
		}
		chain = append(chain, t)
	}
	return chain, nil
}
