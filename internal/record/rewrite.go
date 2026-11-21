package record

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Line is what Rewrite tells its caller of one line of a record file.
type Line struct {
	Type string
	Run  string
	// Time is the record's time: a request's, the end of a counts or a
	// gap record's period, a run's start.
	Time time.Time
}

// Rewrite writes the record files of dir again without the lines drop
// chooses, for the dashboard's Records page (W19 of
// docs/development-plan-dashboard-control.md): a run deleted, or every
// record older than a date. It holds the directory's lock, so it fails
// with ErrInUse while a writer, such as ids-live, has it. A line that
// can't be read is kept. A full file left with no request record is
// deleted. It returns how many lines were dropped.
func Rewrite(dir string, drop func(Line) bool) (int, error) {
	lock, err := lockDir(dir)
	if err != nil {
		return 0, err
	}
	defer unlock(lock)
	rotated, err := RotatedFiles(dir)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, name := range append(rotated, CurrentFile) {
		n, err := rewriteFile(filepath.Join(dir, name), name != CurrentFile, drop)
		total += n
		if err != nil {
			return total, fmt.Errorf("%s: %w", name, err)
		}
	}
	return total, nil
}

func rewriteFile(path string, removable bool, drop func(Line) bool) (int, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return 0, err
	}
	var out bytes.Buffer
	dropped, requests := 0, 0
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var head struct {
				Type string    `json:"type"`
				Run  string    `json:"run"`
				Time time.Time `json:"time"`
				To   time.Time `json:"to"`
			}
			if json.Unmarshal(line, &head) == nil {
				t := head.Time
				if head.Type == TypeCounts || head.Type == TypeGap {
					t = head.To
				}
				if drop(Line{Type: head.Type, Run: head.Run, Time: t}) {
					dropped++
					line = nil
				} else if head.Type == TypeRequest {
					requests++
				}
			}
			out.Write(line)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Close()
			return 0, err
		}
	}
	f.Close()
	if dropped == 0 {
		return 0, nil
	}
	if removable && requests == 0 {
		return dropped, os.Remove(path)
	}
	tmp := path + ".rewrite"
	if err := os.WriteFile(tmp, out.Bytes(), info.Mode().Perm()); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return dropped, os.Rename(tmp, path)
}
