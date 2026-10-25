package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/record"
)

// FuzzStoreReadsAnyFile: whatever a record file holds (broken lines, odd
// values, half a line at the end), the reader neither stops nor panics,
// every indexed record can be loaded, and every page can be built.
func FuzzStoreReadsAnyFile(f *testing.F) {
	var lines []string
	for _, v := range []any{
		startRecord("run1", t0, "sha256:one"),
		requestRecord("a", "run1", t0, "203.0.113.1", 10, at{930100, "ARGS:file"}),
		requestRecord("b", "run1", t0.AddDate(-30, 0, 0), "", 0),
		countsRecord("run1", t0, 10, 2, 1),
	} {
		data, _ := json.Marshal(v)
		lines = append(lines, string(data))
	}
	f.Add([]byte(strings.Join(lines, "\n") + "\n"))
	f.Add([]byte(lines[1] + "\nnot json\n{\"type\":\"request\",\"id\":\"c\",\"time\":\"0000-01-01T00:00:00Z\"}\n" + lines[2][:30]))
	f.Add([]byte("{\"type\":\"counts\",\"to\":\"9999-12-31T23:59:59Z\",\"analysed\":-5}\n{\"type\":\"start\",\"run\":\"\"}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, record.CurrentFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s := newStore(dir)
		if err := s.refresh(); err != nil {
			t.Fatal(err)
		}
		for _, e := range s.entries {
			if _, err := s.load(e.id); err != nil {
				t.Fatalf("load(%q): %v", e.id, err)
			}
		}
		for _, name := range []string{"1h", "all"} {
			r, _ := parseRange(name, t0)
			s.overview(r)
			s.list(filter{Range: r, Kind: "all", Page: 1})
			s.rulesPage(r, "")
			s.rulesPage(r, "none")
			s.list(filter{Range: r, Kind: "all", App: "none", Page: 1})
		}
		s.enginePage()
	})
}
