package operator

import "strings"

// text is the family of operators that compare the value with the argument
// as plain text, letter case included.
//
//	@contains <!--        the value has the argument somewhere in it
//	@streq POST           the value is exactly the argument
//	@beginsWith /admin    the value starts with the argument
//	@endsWith .example    the value ends with the argument
//	@within GET HEAD POST the value is somewhere in the argument
//
// @within is @contains the other way round. It is a plain search in the
// text, not a search in a list of words: "GE" is within "GET HEAD POST".
// An empty value is within anything.
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

	newBeginsWith = newText(strings.HasPrefix)
	newEndsWith   = newText(strings.HasSuffix)
	newWithin     = newText(func(value, argument string) bool { return strings.Contains(argument, value) })
)
