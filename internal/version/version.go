// Package version says which build of the IDS is running, so that every
// record can be traced back to the code that wrote it (R7).
package version

import "runtime/debug"

// Version is the version of the IDS.
const Version = "0.1.0-dev"

// Revision returns the version control revision the program was built
// from, with "-modified" when the working tree had changes, or "" when the
// build carries no such information, as with go test.
func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision != "" && modified == "true" {
		revision += "-modified"
	}
	return revision
}
