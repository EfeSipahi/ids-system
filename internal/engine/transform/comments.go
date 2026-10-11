package transform

import "strings"

// ReplaceComments replaces every C-style comment /* ... */ with one space.
// A comment that is opened and never closed runs to the end of the value
// and is replaced by one space as well.
//
// SQL treats a comment as white space, so "UNION/**/SELECT" is the same
// query as "UNION SELECT". After this step both look alike.
func ReplaceComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	out := make([]byte, 0, len(s))
	inComment := false
	for i := 0; i < len(s); {
		switch {
		case !inComment && s[i] == '/' && i+1 < len(s) && s[i+1] == '*':
			inComment = true
			i += 2
		case !inComment:
			out = append(out, s[i])
			i++
		case s[i] == '*' && i+1 < len(s) && s[i+1] == '/':
			inComment = false
			out = append(out, ' ')
			i += 2
		default:
			i++
		}
	}
	if inComment {
		out = append(out, ' ')
	}
	return string(out)
}

// RemoveCommentsChar deletes the character sequences that start or end a
// comment in SQL, HTML or C, and leaves everything between them in place:
//
//	/*   */   <!--   -->   --   #
func RemoveCommentsChar(s string) string {
	out := make([]byte, 0, len(s))
	has := func(i int, text string) bool {
		return strings.HasPrefix(s[i:], text)
	}
	for i := 0; i < len(s); {
		switch {
		case has(i, "/*"), has(i, "*/"):
			i += 2
		case has(i, "<!--"):
			i += 4
		case has(i, "-->"):
			i += 3
		case has(i, "--"):
			i += 2
		case s[i] == '#':
			i++
		default:
			out = append(out, s[i])
			i++
		}
	}
	return string(out)
}
