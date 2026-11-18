package live

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The socket has permission 0660 (docs/copy-format.md): only the IDS's
// user and group may send copies.
func TestSocketPermission(t *testing.T) {
	path := filepath.Join(shortDir(t), "copy.sock")
	ln, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != SocketMode {
		t.Errorf("mode %v, want a socket with %v", info.Mode(), os.FileMode(SocketMode))
	}
}

// A socket left by a run that died is removed; one that a program listens
// on, or a file that is not a socket, is left alone with an error.
func TestStaleSocket(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "copy.sock")

	// A stale socket: its file stays when the listener is closed without
	// removing it, as after a crash.
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close()
	ln, err := listen(path)
	if err != nil {
		t.Fatalf("a stale socket: %v", err)
	}

	// A socket someone listens on.
	if _, err := listen(path); err == nil || !strings.Contains(err.Error(), "another program is listening on it") {
		t.Errorf("a live socket: %v", err)
	}
	ln.Close()

	// A file that is not a socket.
	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(file); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("a regular file: %v", err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep me" {
		t.Errorf("the file was changed: %q, %v", data, err)
	}
}

// A path longer than Linux allows gets a clear error, not "invalid
// argument".
func TestSocketPathTooLong(t *testing.T) {
	path := filepath.Join(shortDir(t), strings.Repeat("x", MaxSocketPath))
	if _, err := listen(path); err == nil || !strings.Contains(err.Error(), "Linux allows at most 107") {
		t.Errorf("error %v", err)
	}
	cfg := Config{Socket: path}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Choose a shorter path") {
		t.Errorf("Validate: %v", err)
	}
}

// Shutdown relies on this behaviour of Linux: after the reading side of a
// Unix socket is shut, what the peer wrote before can still be read, then
// the reader sees the end; the peer's next write fails. So a copier learns
// that its copies are not taken, while those already sent are analysed.
func TestCloseReadKeepsWhatWasSent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux behaviour")
	}
	path := filepath.Join(shortDir(t), "pair.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	writer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if _, err := writer.Write([]byte("sent before the stop")); err != nil {
		t.Fatal(err)
	}
	if err := reader.CloseRead(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "sent before the stop" {
		t.Errorf("read %q, %v", got, err)
	}
	if _, err := writer.Write([]byte("after")); err == nil {
		t.Error("the peer can still write after the stop")
	}
}
