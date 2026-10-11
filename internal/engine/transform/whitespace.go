package transform

// nbsp is the non-breaking space in Latin-1. ModSecurity counts this one
// byte as white space in addition to what C's isspace accepts.
const nbsp = 0xA0

func isWhitespace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r') || c == nbsp
}

// RemoveWhitespace deletes every white space byte: space, tab, line feed,
// vertical tab, form feed, carriage return and the Latin-1 non-breaking
// space.
func RemoveWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isWhitespace(s[i]) {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// CompressWhitespace turns every run of white space bytes into one space.
// A single tab or line feed becomes a space too.
func CompressWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	pending := false // white space was read and not yet written
	for i := 0; i < len(s); i++ {
		if isWhitespace(s[i]) {
			pending = true
			continue
		}
		if pending {
			out = append(out, ' ')
			pending = false
		}
		out = append(out, s[i])
	}
	if pending {
		out = append(out, ' ')
	}
	return string(out)
}

// Lowercase makes ASCII letters lower case. Other bytes are not changed.
func Lowercase(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			out := []byte(s)
			for j := i; j < len(out); j++ {
				if out[j] >= 'A' && out[j] <= 'Z' {
					out[j] += 'a' - 'A'
				}
			}
			return string(out)
		}
	}
	return s
}
