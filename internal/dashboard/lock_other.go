//go:build !linux

package dashboard

import "os"

// lockFile does nothing on systems other than Linux: there, one writer of
// the state folder is a rule that is not enforced, as for the records.
func lockFile(path string, wait bool) (*os.File, error) {
	return nil, nil
}

func unlockFile(f *os.File) {}
