package transform

import "strings"

// JSDecode resolves the escape sequences of JavaScript strings:
//
//	\uHHHH   the low byte of the code; full-width forms ff01 to ff5e
//	         become ASCII, as in URLDecodeUni
//	\xHH     one byte
//	\OOO     one byte from one to three octal digits, at most \377
//	\n \t    and the other single-letter escapes; any other escaped
//	         character stands for itself, so \' becomes '
//
// A backslash at the very end is kept.
//
// "\x3cscript\x3e" becomes "<script>".
func JSDecode(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out = append(out, s[i])
			i++
			continue
		}
		switch {
		case i+5 < len(s) && s[i+1] == 'u' && isHex(s[i+2]) && isHex(s[i+3]) && isHex(s[i+4]) && isHex(s[i+5]):
			c := unhex(s[i+4])<<4 | unhex(s[i+5])
			if c > 0x00 && c < 0x5f && (s[i+2] == 'f' || s[i+2] == 'F') && (s[i+3] == 'f' || s[i+3] == 'F') {
				c += 0x20
			}
			out = append(out, c)
			i += 6

		case i+3 < len(s) && s[i+1] == 'x' && isHex(s[i+2]) && isHex(s[i+3]):
			out = append(out, unhex(s[i+2])<<4|unhex(s[i+3]))
			i += 4

		case i+1 < len(s) && isOctal(s[i+1]):
			// Up to three octal digits.
			n := 1
			for n < 3 && i+1+n < len(s) && isOctal(s[i+1+n]) {
				n++
			}
			// Three digits starting above 3 would not fit one byte.
			if n == 3 && s[i+1] > '3' {
				n = 2
			}
			var c byte
			for k := 0; k < n; k++ {
				c = c<<3 | (s[i+1+k] - '0')
			}
			out = append(out, c)
			i += 1 + n

		case i+1 < len(s):
			c := s[i+1]
			switch c {
			case 'a':
				c = '\a'
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'v':
				c = '\v'
			}
			out = append(out, c)
			i += 2

		default:
			out = append(out, s[i])
			i++
		}
	}
	return string(out)
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}
