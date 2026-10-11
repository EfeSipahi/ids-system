package transform

import "strings"

// RemoveNulls deletes every NUL byte.
//
// Attackers insert NUL bytes to split a pattern: "..\x00/" does not contain
// "../" until the NUL is removed.
func RemoveNulls(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
