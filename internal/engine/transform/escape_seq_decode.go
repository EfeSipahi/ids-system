package transform

import "strings"

// EscapeSeqDecode resolves the escape sequences of C and of shells such as
// bash with $'...':
//
//	\n \t \r \a \b \f \v   the control character
//	\\ \? \' \"            the character after the backslash
//	\x41                   two hex digits: one byte, here "A"
//	\101                   one to three octal digits: one byte, here "A";
//	                       of a number above 255 only the low byte is kept
//
// For any other character after a backslash, the backslash is dropped and
// the character kept: "\q" becomes "q", and "\x4" becomes "x4". A backslash
// at the very end is kept.
//
// "c\at /e\tc/p\x61sswd" becomes "c" + BEL + "t /e" + TAB + "c/passwd".
//
// This is a port of ansi_c_sequences_decode_inplace in ModSecurity v2
// (apache2/msc_util.c). Coraza's escapeSeqDecode is the same algorithm.
func EscapeSeqDecode(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 == len(s) {
			out = append(out, s[i])
			i++
			continue
		}
		next := s[i+1]
		if c, ok := simpleEscapes[next]; ok {
			out = append(out, c)
			i += 2
			continue
		}
		if (next == 'x' || next == 'X') && i+3 < len(s) && isHex(s[i+2]) && isHex(s[i+3]) {
			out = append(out, unhex(s[i+2])<<4|unhex(s[i+3]))
			i += 4
			continue
		}
		if isOctal(next) {
			j, n := i+1, 0
			for j < len(s) && j < i+4 && isOctal(s[j]) {
				n = n*8 + int(s[j]-'0')
				j++
			}
			out = append(out, byte(n))
			i = j
			continue
		}
		// Not an escape it knows: drop the backslash.
		out = append(out, next)
		i += 2
	}
	return string(out)
}

var simpleEscapes = map[byte]byte{
	'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v',
	'\\': '\\', '?': '?', '\'': '\'', '"': '"',
}
