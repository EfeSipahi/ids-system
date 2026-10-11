// Package seclang reads SecLang rule files, such as the OWASP CRS files,
// and turns their text into Go values.
//
// The package only understands the syntax. It does not know what an HTTP
// request is and it does not execute anything: whether an operator, a
// transformation or an action is supported is decided later by the engine.
package seclang

import (
	"fmt"
	"strings"
)

// Kind says which SecLang directive a Directive came from.
type Kind int

const (
	KindRule               Kind = iota + 1 // SecRule
	KindAction                             // SecAction
	KindMarker                             // SecMarker
	KindDefaultAction                      // SecDefaultAction
	KindComponentSignature                 // SecComponentSignature
)

func (k Kind) String() string {
	switch k {
	case KindRule:
		return "SecRule"
	case KindAction:
		return "SecAction"
	case KindMarker:
		return "SecMarker"
	case KindDefaultAction:
		return "SecDefaultAction"
	case KindComponentSignature:
		return "SecComponentSignature"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Position is the place in a file where a directive starts.
type Position struct {
	File string
	Line int
}

func (p Position) String() string {
	return fmt.Sprintf("%s:%d", p.File, p.Line)
}

// Directive is one parsed directive. Which fields are filled depends on Kind:
//
//	SecRule                Variables, Operator, Actions, ID, Chained
//	SecAction              Actions, ID
//	SecDefaultAction       Actions
//	SecMarker              Text (the marker name)
//	SecComponentSignature  Text (the signature)
type Directive struct {
	Kind Kind
	Pos  Position

	// ID is the value of the id action, or 0 when the directive has none.
	ID int

	Variables []Variable
	Operator  Operator
	Actions   []Action

	// Chained is true for a SecRule that continues the chain started by
	// the rule before it. Such a rule has no id of its own.
	Chained bool

	Text string
}

// ActionValues returns the values of every action called name, in the order
// they are written. Action names are compared without regard to case.
func (d Directive) ActionValues(name string) []string {
	var values []string
	for _, a := range d.Actions {
		if strings.EqualFold(a.Name, name) {
			values = append(values, a.Value)
		}
	}
	return values
}

// HasAction reports whether the directive has an action called name.
func (d Directive) HasAction(name string) bool {
	for _, a := range d.Actions {
		if strings.EqualFold(a.Name, name) {
			return true
		}
	}
	return false
}

// Error is a syntax error at a known position.
type Error struct {
	Pos Position
	Msg string
}

func (e *Error) Error() string {
	return e.Pos.String() + ": " + e.Msg
}
