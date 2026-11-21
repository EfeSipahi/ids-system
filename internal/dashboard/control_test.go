package dashboard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/config"
)

// idsCopy copies the shop's configuration and profile into a new folder,
// beside a link to CRS, and returns the configuration's path.
func idsCopy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"configs", "profiles", "records"} {
		os.Mkdir(filepath.Join(dir, d), 0o755)
	}
	repo, _ := filepath.Abs("../..")
	if err := os.Symlink(filepath.Join(repo, "coreruleset-4.30.0"), filepath.Join(dir, "coreruleset-4.30.0")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"configs/csic-shop.json", "profiles/csic-shop.json"} {
		data, err := os.ReadFile(filepath.Join(repo, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, f), data, 0o644)
	}
	return filepath.Join(dir, "configs", "csic-shop.json")
}

func level(n int) *int { return &n }

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// W7, W11, W12: changes wait, are applied together as one version, write
// the IDS's own files in place, and can be undone byte for byte.
func TestControlAppliesAndUndoes(t *testing.T) {
	path := idsCopy(t)
	profilePath := filepath.Join(filepath.Dir(path), "..", "profiles", "csic-shop.json")
	origProfile, origConfig := read(t, profilePath), read(t, path)
	c := newControl(path, t.TempDir(), newClock().now)
	const app = "app:csic-shop"

	ch, err := c.add(app, pendingChange{Kind: kindRuleOff, Rule: 942100, Reason: "the search takes SQL words", User: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if ch.What != "Rule 942100 off for csic-shop" || ch.ID == "" {
		t.Errorf("change: %+v", ch)
	}
	if _, err := c.add(app, pendingChange{Kind: kindRuleSkip, Rule: 932235, Targets: []string{"ARGS:q"}, Reason: "words", User: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.add(app, pendingChange{Kind: kindLevel, Level: level(1), User: "admin"}); err != nil {
		t.Fatal(err)
	}
	list, _ := c.pending(app)
	if len(list) != 3 {
		t.Fatalf("pending: %+v", list)
	}
	// Nothing is written before the changes are applied.
	if read(t, profilePath) != origProfile {
		t.Fatal("the profile changed before apply")
	}

	a, err := c.apply(app, "admin", "fewer false alarms")
	if err != nil {
		t.Fatal(err)
	}
	v := a.Version
	if v.ID == "" || v.Seq != 1 || len(v.Files) != 1 || v.Files[0].Path != profilePath || v.Fingerprint == "" || len(v.Items) != 3 {
		t.Fatalf("version: %+v", v)
	}
	if read(t, path) != origConfig {
		t.Error("the configuration changed")
	}
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	prof := p.Applications[0].Loaded
	if prof.ParanoiaLevel != 1 {
		t.Errorf("level %d", prof.ParanoiaLevel)
	}
	var off, skip bool
	for _, ex := range prof.Exceptions {
		off = off || ex.Rule == 942100 && ex.Off && ex.Reason == "the search takes SQL words"
		skip = skip || ex.Rule == 932235 && len(ex.Skip) == 1 && ex.Skip[0] == "ARGS:q"
	}
	if !off || !skip {
		t.Errorf("exceptions: %+v", prof.Exceptions)
	}
	if fp, _ := p.Fingerprint(p.Level()); fp != v.Fingerprint {
		t.Errorf("fingerprint %s, version %s", fp, v.Fingerprint)
	}
	if list, _ := c.pending(app); len(list) != 0 {
		t.Errorf("still pending: %+v", list)
	}
	// The rest of the profile is as it was: the file differs only where
	// it changed.
	after := read(t, profilePath)
	if !strings.Contains(after, `"rule": 942100,`) || !strings.HasPrefix(after, origProfile[:200]) {
		t.Errorf("profile after:\n%s", after)
	}

	// Undo, as a new change.
	if _, err := c.add(app, pendingChange{Kind: kindRestore, Version: v.ID, User: "admin"}); err != nil {
		t.Fatal(err)
	}
	u, err := c.apply(app, "admin", "taken back")
	if err != nil {
		t.Fatal(err)
	}
	if read(t, profilePath) != origProfile {
		t.Errorf("undo did not restore the profile byte for byte")
	}
	if u.Version.Undoes != v.ID || u.Version.Seq != 2 {
		t.Errorf("undo version: %+v", u.Version)
	}
	vs, _ := c.versions(app)
	if len(vs) != 2 || vs[0].Seq != 2 {
		t.Errorf("versions: %+v", vs)
	}
	later, _ := c.laterChanges(v)
	if len(later) != 1 || later[0].ID != u.Version.ID {
		t.Errorf("later changes: %+v", later)
	}
}

// A change the IDS would not load is refused when it is added, and the
// files stay as they are.
func TestControlRefusesWhatWouldNotLoad(t *testing.T) {
	path := idsCopy(t)
	c := newControl(path, t.TempDir(), newClock().now)
	for _, tc := range []struct {
		object string
		ch     pendingChange
		want   string
	}{
		{"app:csic-shop", pendingChange{Kind: kindRuleOff, Rule: 949110, Reason: "x"}, "cannot be excepted"},
		{"app:csic-shop", pendingChange{Kind: kindRuleOff, Rule: 123, Reason: "x"}, "none of the loaded rule files"},
		{"app:csic-shop", pendingChange{Kind: kindRuleOff, Rule: 942100}, "give a reason"},
		{"app:csic-shop", pendingChange{Kind: kindRuleSkip, Rule: 942100, Targets: []string{"!ARGS"}, Reason: "x"}, "place"},
		{"app:csic-shop", pendingChange{Kind: kindRuleOn, Rule: 942100}, "has no exception"},
		{"app:other", pendingChange{Kind: kindMode, Mode: "alert"}, "no application other"},
		{"app:csic-shop", pendingChange{Kind: kindDefaultLevel, Level: level(2)}, "not a change for csic-shop"},
		{"global", pendingChange{Kind: kindInclude, Rule: 942100}, "not off for every application"},
		{"global", pendingChange{Kind: kindAddApp, Name: "csic-shop", Hosts: []string{"x"}}, "exists already"},
		{"global", pendingChange{Kind: kindRequireProfile, On: ptr(true)}, ""},
		{"app:csic-shop", pendingChange{Kind: kindProfile, Text: `{"mode": "loud"}`}, "mode"},
		{"app:csic-shop", pendingChange{Kind: kindHosts, Hosts: []string{"a b"}}, "host"},
		{"nothing", pendingChange{Kind: kindMode, Mode: "alert"}, "object"},
	} {
		_, err := c.add(tc.object, tc.ch)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s %s: %v", tc.object, tc.ch.Kind, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: %v, want %q", tc.object, tc.ch.Kind, err, tc.want)
		}
	}
	if list, _ := c.pending("app:csic-shop"); len(list) != 0 {
		t.Errorf("refused changes are pending: %+v", list)
	}
}

// The settings for every application: the default level, a rule off for
// every application, records, and a new application with its profile.
func TestControlGlobalChanges(t *testing.T) {
	path := idsCopy(t)
	c := newControl(path, t.TempDir(), newClock().now)
	for _, ch := range []pendingChange{
		{Kind: kindDefaultLevel, Level: level(2)},
		{Kind: kindExclude, Rule: 920350, Reason: "addresses as hosts are normal here"},
		{Kind: kindBodyLimit, Number: level(256 << 10)},
		{Kind: kindRecords, Records: &recordSettings{MaxFileMB: 20, KeepFiles: 5, SecretNames: []string{"pin"}}},
		{Kind: kindAddApp, Name: "blog", Hosts: []string{"blog.example.com"}},
		{Kind: kindRequireProfile, On: ptr(true)},
	} {
		if _, err := c.add(objectGlobal, ch); err != nil {
			t.Fatalf("%s: %v", ch.Kind, err)
		}
	}
	a, err := c.apply(objectGlobal, "admin", "a second site")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Version.Files) != 2 || !a.Version.Files[1].Created {
		t.Errorf("files: %+v", a.Version.Files)
	}
	p, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Level() != 2 || *p.RequestBodyLimit != 256<<10 || p.Records.MaxFileMB != 20 || p.Records.KeepFiles != 5 || !p.RequireProfile || len(p.Applications) != 2 {
		t.Errorf("configuration: %+v", p)
	}
	if ex := p.Exclude[len(p.Exclude)-1]; ex.ID != 920350 {
		t.Errorf("exclude: %+v", p.Exclude)
	}
	blog := p.Applications[1]
	if blog.Name != "blog" || filepath.Base(blog.Profile) != "blog.json" || blog.Loaded.Mode != "monitor" {
		t.Errorf("blog: %+v", blog)
	}
	if !strings.Contains(read(t, path), `"profile": "../profiles/blog.json"`) {
		t.Errorf("the new application's profile is not written relative to the configuration:\n%s", read(t, path))
	}

	// Taken out again: the application, then the rule back on.
	if _, err := c.add("app:blog", pendingChange{Kind: kindRemoveApp}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.apply("app:blog", "admin", "not yet"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.add(objectGlobal, pendingChange{Kind: kindInclude, Rule: 920350}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.apply(objectGlobal, "admin", "back"); err != nil {
		t.Fatal(err)
	}
	p, _ = config.Load(path)
	for _, ex := range p.Exclude {
		if ex.ID == 920350 {
			t.Error("920350 is still excluded")
		}
	}
}

// A file changed by hand between adding a change and applying it: the
// change is made on the file as it is now.
func TestControlWorksOnTheFilesAsTheyAre(t *testing.T) {
	path := idsCopy(t)
	c := newControl(path, t.TempDir(), newClock().now)
	if _, err := c.add("app:csic-shop", pendingChange{Kind: kindMode, Mode: "alert"}); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(filepath.Dir(path), "..", "profiles", "csic-shop.json")
	data := read(t, profilePath)
	os.WriteFile(profilePath, []byte(strings.Replace(data, `"paranoia_level": 2`, `"paranoia_level": 3`, 1)), 0o644)
	if _, err := c.apply("app:csic-shop", "admin", "alerts now"); err != nil {
		t.Fatal(err)
	}
	after := read(t, profilePath)
	if !strings.Contains(after, `"paranoia_level": 3`) || !strings.Contains(after, `"mode": "alert"`) {
		t.Errorf("profile:\n%s", after)
	}
	// A configuration broken by hand: nothing is applied, and the error
	// says why.
	os.WriteFile(path, bytes.Replace([]byte(read(t, path)), []byte(`"files"`), []byte(`"filez"`), 1), 0o644)
	if _, err := c.add("app:csic-shop", pendingChange{Kind: kindMode, Mode: "monitor"}); err == nil || !strings.Contains(err.Error(), "filez") {
		t.Errorf("broken configuration: %v", err)
	}
}
