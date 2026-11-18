//go:build unix

package live

import "syscall"

// withUmask runs fn with the process's umask set to mask.
func withUmask(mask int, fn func() error) error {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	return fn()
}
