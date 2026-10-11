package transform

import (
	"path"
	"strings"
)

// NormalizePathWin cleans up a file path so that different spellings of the
// same path look alike:
//
//   - every backslash becomes a forward slash
//   - several slashes in a row become one
//   - "./" segments are removed
//   - "segment/../" is removed together with the segment before it
//   - dots and spaces at the end of a segment are removed, because Windows
//     ignores them: "win.ini.." and "win.ini " both open "win.ini"
//   - in the last segment everything from the first ":" on is removed,
//     because Windows reads it as the name of a data stream of the same
//     file: "web.config::$DATA" opens "web.config". A drive letter such as
//     "C:" at the start is kept.
//
// For example `C:\Windows\.\System32\..\win.ini` becomes
// "C:/Windows/win.ini", and "/etc//./passwd" becomes "/etc/passwd".
//
// A path that climbs above its start keeps the ".." it cannot resolve:
// "../../etc/passwd" stays as it is, and "/../etc" becomes "/etc". A slash
// at the end is kept.
//
// This follows normalisePathWin of Coraza v3.8.1 and gives the same results,
// including one odd one: a path that is only "/" becomes "//". It is a
// deliberate difference from ModSecurity v2, whose function reads a segment
// ending in two dots as a back-reference and removes it, so that
// "win.ini.." disappears from the value and a rule looking for "win.ini"
// finds nothing.
func NormalizePathWin(s string) string {
	if s == "" {
		return s
	}
	clean := cleanPath(strings.ReplaceAll(s, `\`, "/"))
	return trimSegments(cutDataStream(clean))
}

// cleanPath resolves ".", ".." and repeated slashes. A slash at the end of
// the input is put back after cleaning.
func cleanPath(s string) string {
	clean := path.Clean(s)
	if clean == "." {
		return ""
	}
	if strings.HasSuffix(s, "/") {
		return clean + "/"
	}
	return clean
}

// cutDataStream cuts the last segment at its first colon. A drive letter
// and a slash at the end are set aside first and put back afterwards.
func cutDataStream(s string) string {
	drive := ""
	if len(s) >= 2 && s[1] == ':' && isLetter(s[0]) {
		drive, s = s[:2], s[2:]
	}
	slash := ""
	if strings.HasSuffix(s, "/") {
		slash, s = "/", s[:len(s)-1]
	}
	last := strings.LastIndexByte(s, '/') + 1
	if colon := strings.IndexByte(s[last:], ':'); colon >= 0 {
		s = s[:last+colon]
	}
	return drive + s + slash
}

// trimSegments removes the dots and spaces at the end of every segment. A
// segment of dots only, such as "..", is navigation and stays. A segment
// that has nothing left after trimming is dropped.
func trimSegments(s string) string {
	segments := strings.Split(s, "/")
	kept := segments[:0]
	changed := false
	for _, seg := range segments {
		if strings.Trim(seg, ".") != "" {
			trimmed := strings.TrimRight(seg, ". ")
			if trimmed != seg {
				changed = true
			}
			if trimmed == "" {
				continue
			}
			seg = trimmed
		}
		kept = append(kept, seg)
	}
	if !changed {
		return s
	}
	return strings.Join(kept, "/")
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
