//go:build linux

package dashboard

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on the file at path, making the file
// when it is missing. With wait it waits for another holder to let go;
// without, it fails at once with errInUse. The lock belongs to the open
// file and ends when it is closed, also when the program dies; the file
// itself stays.
func lockFile(path string, wait bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errInUse
		}
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) {
	if f != nil {
		f.Close()
	}
}
