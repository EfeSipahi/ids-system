//go:build !unix

package live

// withUmask runs fn; this system has no umask.
func withUmask(mask int, fn func() error) error {
	return fn()
}
