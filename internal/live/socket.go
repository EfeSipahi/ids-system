package live

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"
)

// SocketMode is the permission of the socket: only the IDS's user and
// group may connect. Anyone who can connect can add records.
const SocketMode = 0o660

// listen opens the Unix socket at path. A socket file left by an earlier
// run is removed only when nothing answers on it; any other file there is
// an error and is left alone. The socket has SocketMode from the moment it
// exists.
//
// It changes the process's umask while it makes the socket, so it must
// not run while other goroutines create files.
func listen(path string) (*net.UnixListener, error) {
	if len(path) > MaxSocketPath {
		return nil, fmt.Errorf("socket %s: the path is %d bytes long; Linux allows at most %d", path, len(path), MaxSocketPath)
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	var ln *net.UnixListener
	err := withUmask(0o777&^SocketMode, func() error {
		var err error
		ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("socket %s: %w", path, err)
	}
	// On systems without a umask the mode is set here, a moment later.
	if err := os.Chmod(path, SocketMode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("socket %s: %w", path, err)
	}
	return ln, nil
}

// removeStale removes a socket file at path that no program listens on.
func removeStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("socket %s: %w", path, err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("socket %s: a file that is not a socket is in the way; it was left alone", path)
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("socket %s: another program is listening on it, perhaps another ids-live", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("socket %s: it exists, and whether a program listens on it cannot be told: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("socket %s: the socket of an earlier run cannot be removed: %w", path, err)
	}
	return nil
}
