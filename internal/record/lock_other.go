//go:build !linux

package record

import "os"

// lockDir does nothing on systems other than Linux: there, one writer per
// directory is a rule that is not enforced (docs/records-format.md).
func lockDir(dir string) (*os.File, error) {
	return nil, nil
}

func unlock(f *os.File) {}
