package transform

// CmdLine normalises a value the way a command shell would read it, so that
// tricks used to hide a command no longer hide it:
//
//   - deletes  "  '  \  ^
//   - turns each run of space , ; tab CR LF into one space
//   - deletes that space when a / or ( comes next
//   - makes ASCII letters lower case
//
// For example `C^md  /c "dir"` becomes `cmd/c dir`.
//
// Difference from ModSecurity v2: its C implementation stops at the first
// NUL byte and drops the rest of the value. Here the whole value is
// processed.
func CmdLine(s string) string {
	out := make([]byte, 0, len(s))
	// space is true while the last byte of out is a space written by the
	// second case below.
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\'', '\\', '^':
			// deleted

		case ' ', ',', ';', '\t', '\r', '\n':
			if !space {
				out = append(out, ' ')
				space = true
			}

		case '/', '(':
			if space {
				out = out[:len(out)-1]
				space = false
			}
			out = append(out, c)

		default:
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out = append(out, c)
			space = false
		}
	}
	return string(out)
}
