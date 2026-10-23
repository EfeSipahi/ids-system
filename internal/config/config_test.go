package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The product configuration loads, without a records section.
func TestProductConfig(t *testing.T) {
	p, err := Load("../../configs/crs-first-engine.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 19 || len(p.Exclude) != 4 || p.Level() != 1 {
		t.Errorf("files %d, exclusions %d, level %d", len(p.Files), len(p.Exclude), p.Level())
	}
	if !filepath.IsAbs(p.Files[0]) && !strings.HasPrefix(p.Files[0], "../../") {
		t.Errorf("rule file path %q does not start at the configuration's directory", p.Files[0])
	}
}

func TestRecordsSection(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog"`)
	path := write(t, dir, "ids.json", `{"files": ["rules.conf"], "records": {"dir": "out", "keep_files": 3}}`)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Records == nil || p.Records.Dir != filepath.Join(dir, "out") || p.Records.KeepFiles != 3 {
		t.Errorf("records = %+v", p.Records)
	}

	for text, want := range map[string]string{
		`{"files": ["rules.conf"], "records": {"keep_files": 3}}`:                 "dir is missing",
		`{"files": ["rules.conf"], "records": {"dir": "out", "max_file_mb": -1}}`: "max_file_mb",
		`{"files": ["rules.conf"], "records": {"dir": "out", "size": 1}}`:         "unknown field",
		`{"files": ["rules.conf"], "record": {}}`:                                 "unknown field",
		`{"files": [], "records": {"dir": "out"}}`:                                "no rule files",
		`{"files": ["rules.conf"]} {}`:                                            "unexpected content",
	} {
		path := write(t, dir, "bad.json", text)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", text, err, want)
		}
	}
}

// The fingerprint changes with the configuration, any rule file, and the
// level, and with nothing else.
func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	rules := write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog"`)
	path := write(t, dir, "ids.json", `{"files": ["rules.conf"]}`)
	fingerprint := func(level int) string {
		t.Helper()
		p, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := p.Fingerprint(level)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}

	first := fingerprint(1)
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("fingerprint = %q", first)
	}
	if fingerprint(1) != first {
		t.Error("the same files give another fingerprint")
	}
	if fingerprint(2) == first {
		t.Error("another level gives the same fingerprint")
	}
	write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog" `)
	if fingerprint(1) == first {
		t.Error("a changed rule file gives the same fingerprint")
	}
	write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog"`)
	write(t, dir, "ids.json", `{"files": ["rules.conf"], "paranoia_level": 1}`)
	if fingerprint(1) == first {
		t.Error("a changed configuration gives the same fingerprint")
	}

	os.Remove(rules)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Fingerprint(1); err == nil {
		t.Error("no error for a missing rule file")
	}
}
