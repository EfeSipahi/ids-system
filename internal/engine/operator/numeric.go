package operator

import "math"

// numeric is the family @eq, @lt, @ge, @gt: read the value and the argument as
// whole numbers and compare them, value on the left.
//
//	SecRule TX:detection_paranoia_level "@lt 2"   matches when the level is below 2
//
// The argument may be a macro, as in "@ge %{tx.inbound_anomaly_score_threshold}".
// It is then expanded for every test, because its value belongs to the
// request.
type numeric struct {
	argument string
	macro    bool
	right    int64 // the argument as a number, when it has no macro
	compare  func(left, right int64) bool
}

func newNumeric(argument string, compare func(left, right int64) bool) Operator {
	o := numeric{argument: argument, macro: hasMacro(argument), compare: compare}
	if !o.macro {
		o.right = ParseInt(argument)
	}
	return o
}

func (o numeric) Match(value string, expand func(string) string) Result {
	right := o.right
	if o.macro {
		right = ParseInt(expand(o.argument))
	}
	return Result{Matched: o.compare(ParseInt(value), right)}
}

// ParseInt reads a number the way C's atoi does, which is what ModSecurity
// uses: skip leading white space, accept one sign, then read digits until
// the first other character. Text with no digits there is 0, so "abc" and
// "" both count as 0 and "12abc" as 12.
//
// Difference from ModSecurity: a number too large for 64 bits stops at the
// largest or smallest 64-bit value. In C the result of atoi is then not
// defined.
func ParseInt(s string) int64 {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	negative := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		negative = s[i] == '-'
		i++
	}
	var n uint64
	const limit = uint64(math.MaxInt64) + 1 // the magnitude of the smallest int64
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		digit := uint64(s[i] - '0')
		if n > (limit-digit)/10 {
			n = limit
			break
		}
		n = n*10 + digit
	}
	switch {
	case negative && n >= limit:
		return math.MinInt64
	case negative:
		return -int64(n)
	case n >= limit:
		return math.MaxInt64
	}
	return int64(n)
}

// isCSpace reports what C's isspace accepts in the default locale.
func isCSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}
