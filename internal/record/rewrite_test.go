package record

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// W19: a run deleted, and the records older than a date, while no writer
// holds the folder.
func TestRewrite(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"type":"start","run":"a","time":"2026-11-01T00:00:00Z"}`,
		`{"type":"request","run":"a","time":"2026-11-01T01:00:00Z","id":"1"}`,
		`{"type":"counts","run":"a","to":"2026-11-01T01:01:00Z"}`,
		`not json`,
		`{"type":"start","run":"b","time":"2026-11-10T00:00:00Z"}`,
		`{"type":"request","run":"b","time":"2026-11-10T01:00:00Z","id":"2"}`,
	}
	os.WriteFile(filepath.Join(dir, "records-20261102T000000.000000000Z.jsonl"), []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, CurrentFile), []byte(strings.Join(lines[4:], "\n")+"\n"), 0o600)

	r, err := Open(Config{Dir: dir}, Engine{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rewrite(dir, func(Line) bool { return true }); !errors.Is(err, ErrInUse) {
		t.Errorf("while a writer has the folder: %v", err)
	}
	r.Close()

	// Run a goes, and with it the full file, which has no request left.
	n, err := Rewrite(dir, func(l Line) bool { return l.Run == "a" })
	if err != nil || n != 3 {
		t.Fatalf("%d dropped, %v", n, err)
	}
	if left, _ := RotatedFiles(dir); len(left) != 0 {
		t.Errorf("rotated files left: %v", left)
	}
	// Older than 5 November: nothing of b.
	n, err = Rewrite(dir, func(l Line) bool {
		return l.Type == TypeRequest && l.Time.Before(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	})
	if err != nil || n != 0 {
		t.Errorf("%d dropped, %v", n, err)
	}
	current, _ := os.ReadFile(filepath.Join(dir, CurrentFile))
	if !strings.Contains(string(current), `"id":"2"`) {
		t.Errorf("current file: %s", current)
	}
}

// W19: full files closed more than max_age_days ago are deleted.
func TestMaxAge(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"records-20261001T000000.000000000Z.jsonl", "records-20261115T000000.000000000Z.jsonl"} {
		os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600)
	}
	w, err := openWriter(dir, 1<<20, 10, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	w.setLimits(1<<20, 10, 30*24*time.Hour)
	if err := w.pruneDaily(); err != nil {
		t.Fatal(err)
	}
	left, _ := RotatedFiles(dir)
	if len(left) != 1 || left[0] != "records-20261115T000000.000000000Z.jsonl" {
		t.Errorf("left: %v", left)
	}
	if err := (Config{Dir: dir, MaxAgeDays: 4000}).Validate(); err == nil {
		t.Error("max_age_days 4000 is accepted")
	}
}
