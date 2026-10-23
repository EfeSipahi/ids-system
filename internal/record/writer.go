package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// CurrentFile is the name of the file records are added to. A full file is
// renamed to RotatedPrefix + its closing time + ".jsonl".
const (
	CurrentFile   = "records.jsonl"
	RotatedPrefix = "records-"
	rotatedSuffix = ".jsonl"
	rotatedLayout = "20060102T150405.000000000Z"
)

// writer appends JSON lines to the current file and starts a new file when
// it is full (R5). It is safe for use by many goroutines: each line is
// written whole with one call, so a reader never sees two lines mixed.
type writer struct {
	mu      sync.Mutex
	dir     string
	maxSize int64
	keep    int
	now     func() time.Time

	f    *os.File
	size int64
	// header is written at the top of every new file, so that each file
	// says which rules produced its records.
	header []byte
}

// openWriter opens the current file of dir, creating dir and the file
// when they do not exist. Only the user running the IDS may read them:
// records contain IP addresses and parts of requests.
func openWriter(dir string, maxSize int64, keep int, now func() time.Time) (*writer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &writer{dir: dir, maxSize: maxSize, keep: keep, now: now}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *writer) open() error {
	f, err := os.OpenFile(filepath.Join(w.dir, CurrentFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, info.Size()
	return nil
}

// marshal returns v as one line of JSON.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	// Encode, unlike Marshal, ends with a newline. Characters such as
	// "<" are written as <, so a record is safe to embed in HTML.
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// setHeader writes v and remembers it as the first line of every new file.
func (w *writer) setHeader(v any) error {
	line, err := marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.header = line
	if w.full(line) {
		// A new file starts with the header anyway.
		return w.rotate()
	}
	return w.append(line)
}

// write adds v as one line.
func (w *writer) write(v any) error {
	line, err := marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.full(line) {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	return w.append(line)
}

// full reports whether line does not fit into the current file. A line
// longer than the limit still goes into an empty file.
func (w *writer) full(line []byte) bool {
	return w.size > 0 && w.size+int64(len(line)) > w.maxSize
}

func (w *writer) append(line []byte) error {
	if w.f == nil {
		return os.ErrClosed
	}
	n, err := w.f.Write(line)
	w.size += int64(n)
	return err
}

// rotate closes the current file, gives it its final name, and starts a new
// one with the header line. Files beyond keep are deleted, oldest first.
func (w *writer) rotate() error {
	if w.f == nil {
		return os.ErrClosed
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	w.f = nil
	current := filepath.Join(w.dir, CurrentFile)
	// The name holds the time, so names sort from oldest to newest. Two
	// rotations in the same nanosecond get times one nanosecond apart.
	t := w.now().UTC()
	var name string
	for {
		name = filepath.Join(w.dir, RotatedPrefix+t.Format(rotatedLayout)+rotatedSuffix)
		if _, err := os.Lstat(name); os.IsNotExist(err) {
			break
		}
		t = t.Add(time.Nanosecond)
	}
	if err := os.Rename(current, name); err != nil {
		return err
	}
	if err := w.open(); err != nil {
		return err
	}
	if len(w.header) > 0 {
		if err := w.append(w.header); err != nil {
			return err
		}
	}
	return w.prune()
}

// prune deletes the oldest rotated files until keep files are left, the
// current one included.
func (w *writer) prune() error {
	rotated, err := RotatedFiles(w.dir)
	if err != nil {
		return err
	}
	for len(rotated) > w.keep-1 {
		if err := os.Remove(filepath.Join(w.dir, rotated[0])); err != nil {
			return err
		}
		rotated = rotated[1:]
	}
	return nil
}

// RotatedFiles returns the names of the full record files in dir, oldest
// first. The current file is not among them.
func RotatedFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(name, RotatedPrefix) && strings.HasSuffix(name, rotatedSuffix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (w *writer) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}
	return nil
}
