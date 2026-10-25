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

// Applications name their profile relative to the configuration file, and
// Load reads each profile.
func TestApplications(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog"`)
	write(t, dir, "profiles/shop.json", `{"endpoints": [{"method": "GET", "path": "/"}]}`)
	path := write(t, dir, "ids.json", `{"files": ["rules.conf"], "require_profile": true,
		"applications": [{"name": "shop", "hosts": ["localhost:8080"], "profile": "profiles/shop.json"}]}`)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Applications) != 1 || !p.RequireProfile {
		t.Fatalf("applications %d, require_profile %v", len(p.Applications), p.RequireProfile)
	}
	app := p.Applications[0]
	if want := filepath.Join(dir, "profiles", "shop.json"); app.Profile != want {
		t.Errorf("profile path %q, want %q", app.Profile, want)
	}
	if app.Loaded == nil || app.Loaded.Path != app.Profile {
		t.Errorf("the profile is not loaded: %+v", app.Loaded)
	}

	write(t, dir, "profiles/bad.json", `{"endpoints": [{"method": "GET", "path": "/", "colour": "red"}]}`)
	for _, c := range []struct{ name, text, want string }{
		{"no profile", `{"files": ["rules.conf"], "applications": [{"name": "shop", "hosts": ["a"]}]}`,
			"applications[0]: profile is missing"},
		{"missing profile file", `{"files": ["rules.conf"], "applications": [{"name": "shop", "hosts": ["a"], "profile": "profiles/none.json"}]}`,
			"applications[0] (shop): "},
		{"broken profile", `{"files": ["rules.conf"], "applications": [{"name": "shop", "hosts": ["a"], "profile": "profiles/bad.json"}]}`,
			`applications[0] (shop): ` + filepath.Join(dir, "profiles", "bad.json") + `: invalid profile: json: unknown field "colour"`},
		{"require_profile without applications", `{"files": ["rules.conf"], "require_profile": true}`,
			"require_profile is on, but there are no applications"},
		{"unknown field in an application", `{"files": ["rules.conf"], "applications": [{"name": "shop", "hosts": ["a"], "profile": "profiles/shop.json", "path": "/"}]}`,
			`unknown field "path"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, dir, "case.json", c.text))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want it to contain %q", err, c.want)
			}
		})
	}
}

// Profile files take part in the fingerprint; without applications it is
// what it was before profiles existed.
func TestFingerprintOfProfiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "rules.conf", `SecAction "id:1,phase:1,pass,nolog"`)
	fingerprint := func(path string) string {
		t.Helper()
		p, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := p.Fingerprint(1)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}

	// Computed with the code of commit dbc6338, before profiles.
	plain := write(t, dir, "plain.json", `{"files": ["rules.conf"]}`)
	if got, want := fingerprint(plain), "sha256:c57afc08e4f4541b0d09a432d0309f284363422696f105156338a9d075c37de1"; got != want {
		t.Errorf("fingerprint without applications %s, want %s", got, want)
	}

	write(t, dir, "shop.json", `{"endpoints": [{"method": "GET", "path": "/"}]}`)
	path := write(t, dir, "ids.json", `{"files": ["rules.conf"],
		"applications": [{"name": "shop", "hosts": ["a"], "profile": "shop.json"}]}`)
	first := fingerprint(path)
	if fingerprint(path) != first {
		t.Error("the same files give another fingerprint")
	}
	write(t, dir, "shop.json", `{"endpoints": [{"method": "GET", "path": "/"}], "mode": "alert"}`)
	if fingerprint(path) == first {
		t.Error("a changed profile file gives the same fingerprint")
	}
}
