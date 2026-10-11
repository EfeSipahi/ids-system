package operator

import (
	"fmt"
	"strconv"
	"strings"
)

// byteRange is the @validateByteRange operator. Its argument lists the
// byte values that are allowed, as numbers and ranges:
//
//	@validateByteRange 32,45-47,48-57,65-90,95,97-122
//
// It matches when the value holds a byte that is NOT in the list. Rules
// often negate it with "!" to ask the opposite: are all bytes allowed?
type byteRange struct {
	allowed [256]bool
}

func newByteRange(argument string) (Operator, error) {
	var o byteRange
	for _, part := range strings.Split(argument, ",") {
		part = strings.TrimSpace(part)
		low, high, isRange := strings.Cut(part, "-")
		if !isRange {
			high = low
		}
		from, err1 := strconv.Atoi(low)
		to, err2 := strconv.Atoi(high)
		if err1 != nil || err2 != nil || from < 0 || to > 255 || from > to {
			return nil, fmt.Errorf("%q is not a byte value or a range of byte values", part)
		}
		for b := from; b <= to; b++ {
			o.allowed[b] = true
		}
	}
	return o, nil
}

func (o byteRange) Match(value string, _ func(string) string) Result {
	for i := 0; i < len(value); i++ {
		if !o.allowed[value[i]] {
			return Result{Matched: true}
		}
	}
	return Result{}
}
