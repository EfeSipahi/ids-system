package transform

import "strings"

// UTF8ToUnicode rewrites every valid multi-byte UTF-8 sequence as the text
// %uXXXX, where XXXX is the code point as four lower-case hex digits. ASCII
// bytes are copied.
//
//	"é"  (0xc3 0xa9)  becomes  "%u00e9"
//	"．" (U+FF0E)     becomes  "%uff0e"
//
// A code point above U+FFFF needs five or six hex digits. ModSecurity v2
// keeps only the first four, so "😀" (U+1F600) becomes "%u1f60". That is
// reproduced here so that results agree with it.
//
// It is meant to run before URLDecodeUni, which then turns the %uXXXX text
// into one byte. Together they make a full-width "．．／" look like "../".
//
// A byte that does not start a valid sequence is copied as it is. That
// covers a missing or wrong continuation byte, an overlong form such as
// 0xc0 0xaf, a surrogate (U+D800 to U+DFFF), and lead bytes 0xf5 and above.
//
// Differences from ModSecurity v2: its NUL handling (a NUL followed by a
// byte of 0x80 or above is read as a two-byte sequence) is not reproduced;
// a NUL is copied like any ASCII byte. Coraza differs from both: it writes
// %ufffd for an invalid byte.
func UTF8ToUnicode(s string) string {
	start := 0
	for start < len(s) && s[start] < 0x80 {
		start++
	}
	if start == len(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:start])
	for i := start; i < len(s); {
		code, size := decodeUTF8(s[i:])
		if size == 0 {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString("%u")
		writeHex4(&b, code)
		i += size
	}
	return b.String()
}

// decodeUTF8 reads one multi-byte sequence from the start of s. It returns
// size 0 when s does not start with a sequence this transformation accepts.
func decodeUTF8(s string) (code uint32, size int) {
	c := s[0]
	switch {
	case c&0xE0 == 0xC0:
		if len(s) < 2 || !isContinuation(s[1]) {
			return 0, 0
		}
		code = uint32(c&0x1F)<<6 | uint32(s[1]&0x3F)
		if code < 0x80 {
			return 0, 0
		}
		return code, 2

	case c&0xF0 == 0xE0:
		if len(s) < 3 || !isContinuation(s[1]) || !isContinuation(s[2]) {
			return 0, 0
		}
		code = uint32(c&0x0F)<<12 | uint32(s[1]&0x3F)<<6 | uint32(s[2]&0x3F)
		if code < 0x800 || (code >= 0xD800 && code <= 0xDFFF) {
			return 0, 0
		}
		return code, 3

	case c&0xF8 == 0xF0:
		if c >= 0xF5 || len(s) < 4 || !isContinuation(s[1]) || !isContinuation(s[2]) || !isContinuation(s[3]) {
			return 0, 0
		}
		code = uint32(c&0x07)<<18 | uint32(s[1]&0x3F)<<12 | uint32(s[2]&0x3F)<<6 | uint32(s[3]&0x3F)
		if code < 0x10000 {
			return 0, 0
		}
		return code, 4
	}
	return 0, 0
}

func isContinuation(c byte) bool {
	return c&0xC0 == 0x80
}

// writeHex4 writes v in lower-case hex as exactly four digits: padded with
// zeros when shorter, cut after the fourth digit when longer.
func writeHex4(b *strings.Builder, v uint32) {
	const digits = "0123456789abcdef"
	for v > 0xFFFF {
		v >>= 4
	}
	b.WriteByte(digits[v>>12&0xF])
	b.WriteByte(digits[v>>8&0xF])
	b.WriteByte(digits[v>>4&0xF])
	b.WriteByte(digits[v&0xF])
}
