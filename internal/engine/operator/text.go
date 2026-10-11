package operator

import "strings"

// text is the family @contains and @streq: compare the value with the
// argument as plain text, letter case included.
//
//	@contains <!--     the value has the argument somewhere in it
//	@streq POST        the value is exactly the argument
//
// The argument may be a macro; it is then expanded for every test.
type text struct {
	argument string
	macro    bool
	compare  func(value, argument string) bool
}

func newText(compare func(value, argument string) bool) constructor {
	return func(argument string) (Operator, error) {
		return text{argument: argument, macro: hasMacro(argument), compare: compare}, nil
	}
}

func (o text) Match(value string, expand func(string) string) Result {
	argument := o.argument
	if o.macro {
		argument = expand(argument)
	}
	return Result{Matched: o.compare(value, argument)}
}

var (
	newContains = newText(strings.Contains)
	newStreq    = newText(func(value, argument string) bool { return value == argument })
)
