package transform

import "strings"

// Base64Decode decodes base64 text, "PHNjcmlwdD4=" becomes "<script>". It
// is forgiving in the way a rule needs: it never fails, it returns what it
// could decode.
//
//   - Decoding stops at the first character outside the base64 alphabet,
//     at "=" and at a space. What was decoded up to there is the result.
//   - Line breaks (CR and LF) are skipped, so base64 split into lines, as
//     in e-mail, decodes as a whole.
//   - A last group of two or three characters gives one or two bytes; a
//     single character left over gives nothing.
//
// This follows base64decode of Coraza v3.8.1. ModSecurity v2 calls
// apr_base64_decode of the APR library, which does the same except that it
// stops at a line break. That would let an attacker hide the rest of an
// encoded value behind a line break, so the Coraza behaviour is used.
func Base64Decode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 3 / 4)
	n, x := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			continue
		}
		d := base64Value(c)
		if d < 0 {
			break // "=", a space, or any other character outside the alphabet
		}
		x = x<<6 | d
		n++
		if n == 4 {
			b.WriteByte(byte(x >> 16))
			b.WriteByte(byte(x >> 8))
			b.WriteByte(byte(x))
			n, x = 0, 0
		}
	}
	switch n {
	case 2:
		b.WriteByte(byte(x >> 4))
	case 3:
		b.WriteByte(byte(x >> 10))
		b.WriteByte(byte(x >> 2))
	}
	return b.String()
}

// base64Value returns the value of a character of the base64 alphabet, or
// -1 for any other byte.
func base64Value(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}
