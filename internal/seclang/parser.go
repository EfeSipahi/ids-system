package seclang

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ParseFile reads one rule file and returns its directives in file order.
func ParseFile(path string) ([]Directive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(path, f)
}

// Parse reads directives from r. The file name is only used in positions
// and error messages.
//
// Parse stops at the first problem and returns an *Error. A directive it
// does not know is a problem: nothing is skipped silently.
func Parse(file string, r io.Reader) ([]Directive, error) {
	lines, err := readLogicalLines(r)
	if err != nil {
		var le *lineError
		if errors.As(err, &le) {
			return nil, &Error{Pos: Position{File: file, Line: le.line}, Msg: le.msg}
		}
		return nil, fmt.Errorf("%s: %w", file, err)
	}

	var (
		directives []Directive
		seenIDs    = map[int]Position{}
		// chainFrom is the position of the rule whose chain the next
		// SecRule must continue, or nil when no chain is open.
		chainFrom *Position
	)
	for _, l := range lines {
		pos := Position{File: file, Line: l.line}
		d, err := parseDirective(l.text)
		if err != nil {
			return nil, &Error{Pos: pos, Msg: err.Error()}
		}
		d.Pos = pos

		if chainFrom != nil {
			if d.Kind != KindRule {
				return nil, &Error{Pos: pos, Msg: fmt.Sprintf("%s found, but the rule at line %d ends with chain and must be followed by a SecRule", d.Kind, chainFrom.Line)}
			}
			d.Chained = true
		}

		if err := checkID(d); err != nil {
			return nil, &Error{Pos: pos, Msg: err.Error()}
		}
		if d.ID != 0 {
			if first, dup := seenIDs[d.ID]; dup {
				return nil, &Error{Pos: pos, Msg: fmt.Sprintf("id %d is already used at line %d", d.ID, first.Line)}
			}
			seenIDs[d.ID] = pos
		}

		chainFrom = nil
		if d.HasAction("chain") {
			chainFrom = &pos
		}
		directives = append(directives, d)
	}
	if chainFrom != nil {
		return nil, &Error{Pos: *chainFrom, Msg: "rule ends with chain but no SecRule follows it"}
	}
	return directives, nil
}

// parseDirective parses one logical line.
func parseDirective(text string) (Directive, error) {
	name, rest := text, ""
	if i := strings.IndexAny(text, " \t"); i >= 0 {
		name, rest = text[:i], text[i+1:]
	}
	args, err := splitArgs(rest)
	if err != nil {
		return Directive{}, fmt.Errorf("%s: %w", name, err)
	}

	var d Directive
	switch strings.ToLower(name) {
	case "secrule":
		d.Kind = KindRule
		if len(args) != 2 && len(args) != 3 {
			return d, fmt.Errorf("SecRule takes variables, an operator and optional actions, found %d arguments", len(args))
		}
		if d.Variables, err = parseVariables(args[0]); err != nil {
			return d, fmt.Errorf("SecRule variables: %w", err)
		}
		if d.Operator, err = parseOperator(args[1]); err != nil {
			return d, fmt.Errorf("SecRule operator: %w", err)
		}
		if len(args) == 3 {
			if d.Actions, err = parseActions(args[2]); err != nil {
				return d, fmt.Errorf("SecRule actions: %w", err)
			}
		}

	case "secaction", "secdefaultaction":
		d.Kind = KindAction
		if strings.EqualFold(name, "SecDefaultAction") {
			d.Kind = KindDefaultAction
		}
		if len(args) != 1 {
			return d, fmt.Errorf("%s takes one argument, found %d", d.Kind, len(args))
		}
		if d.Actions, err = parseActions(args[0]); err != nil {
			return d, fmt.Errorf("%s actions: %w", d.Kind, err)
		}

	case "secmarker", "seccomponentsignature":
		d.Kind = KindMarker
		if strings.EqualFold(name, "SecComponentSignature") {
			d.Kind = KindComponentSignature
		}
		if len(args) != 1 || args[0] == "" {
			return d, fmt.Errorf("%s takes one non-empty argument, found %d", d.Kind, len(args))
		}
		d.Text = args[0]

	case "secruleupdatetargetbyid":
		d.Kind = KindUpdateTargetByID
		if len(args) == 3 {
			return d, errors.New("SecRuleUpdateTargetById with a replaced target is not supported")
		}
		if len(args) != 2 {
			return d, fmt.Errorf("SecRuleUpdateTargetById takes a rule id and a variable list, found %d arguments", len(args))
		}
		id, err := strconv.Atoi(args[0])
		if err != nil || id <= 0 {
			return d, fmt.Errorf("SecRuleUpdateTargetById: rule id must be one positive number, found %q", args[0])
		}
		d.TargetID = id
		if d.Variables, err = parseVariables(args[1]); err != nil {
			return d, fmt.Errorf("SecRuleUpdateTargetById variables: %w", err)
		}

	default:
		return d, fmt.Errorf("unsupported directive %s", name)
	}

	if d.ID, err = idOf(d); err != nil {
		return d, err
	}
	return d, nil
}

// idOf returns the value of the directive's id action, or 0 if it has none.
func idOf(d Directive) (int, error) {
	ids := d.ActionValues("id")
	switch len(ids) {
	case 0:
		return 0, nil
	case 1:
		id, err := strconv.Atoi(ids[0])
		if err != nil || id <= 0 {
			return 0, fmt.Errorf("id must be a positive number, found %q", ids[0])
		}
		return id, nil
	}
	return 0, fmt.Errorf("%d id actions on one directive", len(ids))
}

// checkID enforces which directives must and must not carry an id.
func checkID(d Directive) error {
	switch d.Kind {
	case KindRule:
		if d.Chained && d.ID != 0 {
			return fmt.Errorf("a chained SecRule must not have its own id, found %d", d.ID)
		}
		if !d.Chained && d.ID == 0 {
			return errors.New("SecRule has no id")
		}
	case KindAction:
		if d.ID == 0 {
			return errors.New("SecAction has no id")
		}
	case KindDefaultAction:
		if d.ID != 0 {
			return errors.New("SecDefaultAction must not have an id")
		}
	}
	return nil
}
