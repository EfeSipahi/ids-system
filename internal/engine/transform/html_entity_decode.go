package transform

import (
	"html"
	"strconv"
	"strings"
)

// HTMLEntityDecode resolves HTML entities the way a browser does:
//
//	&#60;  &#x3c;   a number, decimal or hex
//	&lt;  &colon;   a name of the HTML standard
//
// "javascript&colon;alert(1)" becomes "javascript:alert(1)".
//
// A few old names, such as lt, gt, amp and quot, also count without the
// semicolon and directly before other letters: "&LTscript" becomes
// "<script". The other names need their semicolon, and all names are
// case-sensitive: "&colon;" is an entity, "&COLON;" is not. An unknown
// name, or an ampersand that starts no entity, is kept as written.
//
// A number above 127 gives the character with that number, written as
// UTF-8: "&#233;" becomes "é", two bytes.
//
// This is the behaviour of Coraza v3.8.1 and gives the same results. It is
// a deliberate difference from ModSecurity v2, whose function reads the
// whole run of letters after "&" as the name and so leaves "&LTscript"
// alone, which a browser reads as "<script". In the other direction
// ModSecurity decodes some things a browser does not: names in any letter
// case, every name without its semicolon, and of a large number only the
// low byte.
//
// The names and their characters come from Go's standard html package. Its
// own UnescapeString is not used for the whole value, because it reads a
// few broken numbers differently from the decoder Coraza uses: "&#1" at
// the very end of a value, for example.
func HTMLEntityDecode(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		var decoded string
		var n int
		if i+1 < len(s) && s[i+1] == '#' {
			decoded, n = numberEntity(s[i:])
		} else {
			decoded, n = nameEntity(s[i:])
		}
		b.WriteString(decoded)
		i += n
	}
	return b.String()
}

// numberEntity reads "&#60", "&#x3c" and the like at the start of s. It
// returns the character and the number of bytes read. When no digit
// follows, it returns the "&" alone.
func numberEntity(s string) (string, int) {
	i := 2 // after "&#"
	base := 10
	if i < len(s) && (s[i] == 'x' || s[i] == 'X') {
		base = 16
		i++
	}
	first := i
	code := 0
	for ; i < len(s) && isDigit(s[i], base); i++ {
		// A number already too large for any character stops growing.
		if code <= 0x10FFFF {
			code = code*base + int(unhex(s[i]))
		}
	}
	if i == first {
		return "&", 1
	}
	if i < len(s) && s[i] == ';' {
		i++
	}
	// The standard library picks the character, which also covers the
	// special cases of the HTML standard: 0 and numbers that are no
	// character give the replacement character U+FFFD, and 128 to 159 are
	// read as Windows-1252.
	return html.UnescapeString("&#" + strconv.Itoa(code) + ";"), i
}

// nameEntity reads a name such as "&lt;" at the start of s: the letters and
// digits after the "&" and one semicolon. An unknown name is returned as
// written.
func nameEntity(s string) (string, int) {
	i := 1
	for i < len(s) && isAlnum(s[i]) {
		i++
	}
	if i < len(s) && s[i] == ';' {
		i++
	}
	return html.UnescapeString(s[:i]), i
}

func isDigit(c byte, base int) bool {
	if base == 16 {
		return isHex(c)
	}
	return c >= '0' && c <= '9'
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
