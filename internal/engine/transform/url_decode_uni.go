package transform

import "strings"

// URLDecodeUni decodes percent-encoding, including the IIS form %uXXXX.
//
//	%2f      one byte, 0x2f
//	%u002f   the low byte of the code, 0x2f; the high byte is ignored
//	%uff0f   full-width forms ff01 to ff5e map to ASCII: low byte + 0x20
//	+        a space
//
// A "%" that does not start a valid sequence is kept as written. For a
// broken %u sequence the "u" is kept with it.
//
// Difference from ModSecurity: ModSecurity can be configured with a Unicode
// mapping file (SecUnicodeMapFile) that maps a %uXXXX code to a chosen byte,
// for example %u2215 (division slash) to "/". No mapping is used here, so
// %u2215 gives the low byte 0x15.
func URLDecodeUni(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
			i++

		case c != '%':
			b.WriteByte(c)
			i++

		case i+1 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U'):
			if i+5 < len(s) && isHex(s[i+2]) && isHex(s[i+3]) && isHex(s[i+4]) && isHex(s[i+5]) {
				low := unhex(s[i+4])<<4 | unhex(s[i+5])
				if low > 0x00 && low < 0x5f && (s[i+2] == 'f' || s[i+2] == 'F') && (s[i+3] == 'f' || s[i+3] == 'F') {
					low += 0x20
				}
				b.WriteByte(low)
				i += 6
			} else {
				b.WriteString(s[i : i+2])
				i += 2
			}

		case i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 3

		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
