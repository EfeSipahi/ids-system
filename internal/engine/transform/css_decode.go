package transform

import "strings"

// CSSDecode resolves the escape sequences of CSS:
//
//   - a backslash followed by one to six hex digits is one byte, taken from
//     the last two digits. For codes ff01 to ff5e, the full-width forms of
//     ASCII, the ASCII character is used. One white space byte after the
//     digits belongs to the escape and is dropped.
//   - a backslash followed by a line feed is dropped together with it.
//   - a backslash followed by anything else stands for that character.
//   - a backslash at the very end is dropped.
//
// "ja\76 ascript" becomes "javascript".
func CSSDecode(s string) string {
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
		i++ // the backslash
		if i == len(s) {
			break
		}

		n := 0
		for n < 6 && i+n < len(s) && isHex(s[i+n]) {
			n++
		}
		switch {
		case n == 0 && s[i] == '\n':
			i++
		case n == 0:
			out = append(out, s[i])
			i++
		default:
			var c byte
			fullWidthCheck := false
			if n == 1 {
				c = unhex(s[i])
			} else {
				c = unhex(s[i+n-2])<<4 | unhex(s[i+n-1])
				// Only a code that is exactly ffXX can be a
				// full-width form: four digits, or more with
				// leading zeros.
				fullWidthCheck = n == 4 || (n == 5 && s[i] == '0') || (n == 6 && s[i] == '0' && s[i+1] == '0')
			}
			if fullWidthCheck && c > 0x00 && c < 0x5f &&
				(s[i+n-3] == 'f' || s[i+n-3] == 'F') && (s[i+n-4] == 'f' || s[i+n-4] == 'F') {
				c += 0x20
			}
			out = append(out, c)
			i += n
			if i < len(s) && (s[i] == ' ' || (s[i] >= '\t' && s[i] <= '\r')) {
				i++
			}
		}
	}
	return string(out)
}
