package operator

import (
	"errors"
	"regexp"
)

// maxCaptures is the number of TX.0 to TX.9 slots.
const maxCaptures = 10

// rx is the @rx operator: it matches when the pattern is found anywhere in
// the value.
//
// The pattern is compiled once in newRx. A compiled *regexp.Regexp is safe
// to use from many goroutines at once.
//
// Differences from ModSecurity, which uses the PCRE library:
//
//   - Go's regexp package uses RE2 syntax. It has no backreferences and no
//     lookaround; a pattern that needs them fails in newRx. In exchange,
//     matching time grows only linearly with the input.
//   - Go reads the value as UTF-8 text, PCRE as single bytes. A valid
//     multi-byte character counts as one character here and as several
//     there; each invalid byte counts as one in both. Patterns that only
//     name ASCII characters are not affected. A pattern that names a byte
//     above 0x7F is matched byte by byte instead; see byteMode.
//   - A pattern containing a macro is not supported.
type rx struct {
	re *regexp.Regexp
	// byteMode is set for a pattern that names bytes above 0x7F, written
	// as \x80 to \xff or as \x{80} to \x{ff}. In Go such an escape means the character with that
	// number, which in UTF-8 is two bytes, so the pattern would never find
	// the single byte it is looking for. In byte mode every byte of the
	// value is turned into the character with the same number before
	// matching, which makes "one character" mean "one byte" on both
	// sides, as it does in PCRE.
	byteMode bool
}

// highByteEscape finds \x80 to \xff in a pattern, also in the form \x{80}.
var highByteEscape = regexp.MustCompile(`\\x(?:[89a-fA-F][0-9a-fA-F]|\{0*[89a-fA-F][0-9a-fA-F]\})`)

func newRx(pattern string) (Operator, error) {
	if hasMacro(pattern) {
		return nil, errors.New("a pattern containing a macro is not supported")
	}
	// (?s) lets "." match a newline, as ModSecurity's PCRE_DOTALL does.
	// "$" already means only the very end of the value in Go, which is
	// what PCRE_DOLLAR_ENDONLY sets.
	re, err := regexp.Compile("(?s)" + pattern)
	if err != nil {
		return nil, err
	}
	return rx{re: re, byteMode: highByteEscape.MatchString(pattern)}, nil
}

func (o rx) Match(value string, _ func(string) string) Result {
	if o.byteMode && !isASCII(value) {
		m := o.re.FindStringSubmatch(bytesAsRunes(value))
		if m == nil {
			return Result{}
		}
		if len(m) > maxCaptures {
			m = m[:maxCaptures]
		}
		for i := range m {
			m[i] = runesAsBytes(m[i])
		}
		return Result{Matched: true, Captures: m}
	}
	m := o.re.FindStringSubmatch(value)
	if m == nil {
		return Result{}
	}
	if len(m) > maxCaptures {
		m = m[:maxCaptures]
	}
	return Result{Matched: true, Captures: m}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// bytesAsRunes returns a string in which every byte of s has become the
// character with the same number.
func bytesAsRunes(s string) string {
	runes := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		runes[i] = rune(s[i])
	}
	return string(runes)
}

// runesAsBytes is the reverse of bytesAsRunes.
func runesAsBytes(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		out = append(out, byte(r))
	}
	return string(out)
}
