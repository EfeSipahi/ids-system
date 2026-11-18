//go:build linux

package record

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockDir takes the lock file of dir, so that a second writer fails
// instead of mixing its lines into the same files. The lock belongs to the
// open file and ends when it is closed, also when the program dies; the
// file itself stays.
func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, err
	}
	return f, nil
}

func unlock(f *os.File) {
	if f != nil {
		f.Close()
	}
}
