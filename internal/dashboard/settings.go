package dashboard

// What the settings pages show (W3, W4 of
// docs/development-plan-dashboard-control.md): the settings as the
// configuration and the profiles write them, with the defaults of what
// they leave out, so that a form can show and change each one.

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/live"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// ruleFileRow is a rule file that the configuration loads, or one beside
// them that it could.
type ruleFileRow struct {
	Name string `json:"name"`
	// Path is the file as the configuration writes it, or would.
	Path string `json:"path"`
	On   bool   `json:"on"`
	// Rules counts its rules in the newest run.
	Rules int `json:"rules"`
	// Needed is true for a file without which CRS does not work: its
	// setup, its first rules and the score.
	Needed bool `json:"needed"`
}

// rawConfig is the product configuration as written, without the checks
// and the paths made absolute.
type rawConfig struct {
	Files            []string           `json:"files"`
	Exclude          []engine.Exclusion `json:"exclude"`
	ParanoiaLevel    int                `json:"paranoia_level"`
	RequestBodyLimit int                `json:"request_body_limit"`
	Records          *record.Config     `json:"records"`
	Applications     []struct {
		Name    string   `json:"name"`
		Hosts   []string `json:"hosts"`
		Paths   []string `json:"paths"`
		Profile string   `json:"profile"`
	} `json:"applications"`
	RequireProfile bool         `json:"require_profile"`
	Live           *live.Config `json:"live"`
}

// excludedRow is a rule off for every application.
type excludedRow struct {
	ID     int    `json:"id"`
	Reason string `json:"reason"`
	Msg    string `json:"msg,omitempty"`
}

// settingsPage is System › Settings: the settings for every application.
type settingsPage struct {
	Configured bool   `json:"configured"`
	File       string `json:"file,omitempty"`
	Error      string `json:"error,omitempty"`

	RuleFiles    []ruleFileRow `json:"rule_files"`
	DefaultLevel int           `json:"default_level"`
	// RulesAtLevel counts the newest run's rules of each paranoia level.
	RulesAtLevel map[int]int `json:"rules_at_level"`
	// OwnLevels are the applications with a level of their own.
	OwnLevels map[string]int `json:"own_levels"`
	Excluded  []excludedRow  `json:"excluded"`

	BodyLimit        int  `json:"body_limit"`
	BodyLimitDefault int  `json:"body_limit_default"`
	BodyLimitMax     int  `json:"body_limit_max"`
	RequireProfile   bool `json:"require_profile"`

	Records         *record.Config `json:"records,omitempty"`
	RecordsDefaults record.Config  `json:"records_defaults"`
	Live            live.Config    `json:"live"`
	LiveDefaults    live.Config    `json:"live_defaults"`
	Applications    []string       `json:"applications"`
}

// neededFiles are the CRS files without which the rules don't work.
var neededFiles = []string{"crs-setup.conf", "REQUEST-901-", "REQUEST-949-"}

func isNeeded(name string) bool {
	for _, n := range neededFiles {
		if strings.HasPrefix(name, n) {
			return true
		}
	}
	return false
}

// readRaw reads the configuration as written.
func (c *control) readRaw() (rawConfig, error) {
	var raw rawConfig
	w, err := c.newWork()
	if err != nil {
		return raw, err
	}
	return raw, w.config.value.Decode(&raw)
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	p := settingsPage{Configured: s.control.path != "", RuleFiles: []ruleFileRow{}, RulesAtLevel: map[int]int{}, OwnLevels: map[string]int{}, Excluded: []excludedRow{},
		BodyLimitDefault: httpmodel.DefaultBodyLimit, BodyLimitMax: httpmodel.MaxBodyLimit, Applications: []string{},
		RecordsDefaults: record.Config{}.WithDefaults(), LiveDefaults: live.Config{}.WithDefaults()}
	if !p.Configured {
		p.Error = errNoConfig.Error()
		writeJSON(w, http.StatusOK, p)
		return
	}
	p.File = filepath.Base(s.control.path)
	raw, err := s.control.readRaw()
	if err != nil {
		p.Error = err.Error()
		writeJSON(w, http.StatusOK, p)
		return
	}
	rules := s.store.newestRules()
	msgs, perFile := map[int]string{}, map[string]int{}
	for _, rule := range rules {
		msgs[rule.ID] = rule.Msg
		perFile[rule.File]++
		p.RulesAtLevel[rule.ParanoiaLevel]++
	}
	p.RuleFiles = ruleFiles(s.control.path, raw.Files, perFile)
	p.DefaultLevel = engine.Config{ParanoiaLevel: raw.ParanoiaLevel}.Level()
	for _, ex := range raw.Exclude {
		p.Excluded = append(p.Excluded, excludedRow{ID: ex.ID, Reason: ex.Reason, Msg: msgs[ex.ID]})
	}
	p.BodyLimit, p.RequireProfile, p.Records = raw.RequestBodyLimit, raw.RequireProfile, raw.Records
	if raw.Live != nil {
		p.Live = *raw.Live
	}
	if wk, err := s.control.newWork(); err == nil {
		for _, a := range raw.Applications {
			p.Applications = append(p.Applications, a.Name)
			if f, err := wk.profile(a.Name); err == nil {
				var prof struct {
					Level int `json:"paranoia_level"`
				}
				if f.value.Decode(&prof) == nil && prof.Level != 0 {
					p.OwnLevels[a.Name] = prof.Level
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, p)
}

// ruleFiles lists the rule files the configuration loads, in its order,
// with the .conf files beside them that it leaves out, each where it
// belongs by name.
func ruleFiles(configPath string, listed []string, perFile map[string]int) []ruleFileRow {
	dir := filepath.Dir(configPath)
	abs := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	rows := []ruleFileRow{}
	seen := map[string]bool{}
	folders := map[string]bool{}
	for _, f := range listed {
		a := abs(f)
		name := filepath.Base(a)
		seen[a] = true
		if strings.HasPrefix(name, "REQUEST-") || strings.HasPrefix(name, "RESPONSE-") {
			folders[filepath.Dir(a)] = true
		}
		rows = append(rows, ruleFileRow{Name: name, Path: f, On: true, Rules: perFile[name], Needed: isNeeded(name)})
	}
	for folder := range folders {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, e := range entries {
			// The request rules only: the IDS does not inspect responses
			// yet (K8).
			name := e.Name()
			if e.IsDir() || !strings.HasPrefix(name, "REQUEST-") || !strings.HasSuffix(name, ".conf") {
				continue
			}
			a := filepath.Join(folder, name)
			if seen[a] {
				continue
			}
			seen[a] = true
			rel, err := filepath.Rel(dir, a)
			if err != nil {
				rel = a
			}
			rows = append(rows, ruleFileRow{Name: name, Path: filepath.ToSlash(rel), Rules: perFile[name], Needed: isNeeded(name)})
		}
	}
	// The setup first, then the rule files by name, which is CRS's
	// order; the listed files keep theirs among themselves.
	key := func(r ruleFileRow) string {
		if strings.HasPrefix(r.Name, "crs-setup") {
			return ""
		}
		return r.Name
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].On && rows[j].On {
			return false
		}
		return key(rows[i]) < key(rows[j])
	})
	return rows
}

// newestRules returns the rules of the newest run.
func (s *store) newestRules() []record.Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.latestRun()
	if !ok {
		return nil
	}
	return s.rules[st.Run]
}

// appSettings is an application's Settings tab (W3): its entry of the
// configuration and its profile, as written.
type appSettings struct {
	Configured bool     `json:"configured"`
	Error      string   `json:"error,omitempty"`
	Name       string   `json:"name"`
	Hosts      []string `json:"hosts"`
	Paths      []string `json:"paths"`
	// Profile is the profile file as the configuration names it.
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
	// Level is the application's own level, 0 when it has none, and
	// DefaultLevel the configuration's.
	Level        int                 `json:"level"`
	DefaultLevel int                 `json:"default_level"`
	Exceptions   []profile.Exception `json:"exceptions"`
	// Settings are the CRS settings a profile may change, by kind.
	Settings []settingInfo `json:"settings"`
	// Socket is the live input's socket, for the ids_copy block (W18).
	Socket string `json:"socket,omitempty"`
}

type settingInfo struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func (s *Server) apiAppSettings(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	a := appSettings{Configured: s.control.path != "", Name: name, Hosts: []string{}, Paths: []string{}, Exceptions: []profile.Exception{}, Settings: []settingInfo{}}
	for _, n := range profile.SettingNames() {
		a.Settings = append(a.Settings, settingInfo{Name: n, Kind: profile.SettingKind(n)})
	}
	if !a.Configured {
		a.Error = errNoConfig.Error()
		writeJSON(w, http.StatusOK, a)
		return
	}
	wk, err := s.control.newWork()
	if err != nil {
		a.Error = err.Error()
		writeJSON(w, http.StatusOK, a)
		return
	}
	raw, _ := s.control.readRaw()
	a.DefaultLevel = engine.Config{ParanoiaLevel: raw.ParanoiaLevel}.Level()
	if raw.Live != nil {
		a.Socket = raw.Live.Socket
	}
	entry, err := wk.appEntry(name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	var e struct {
		Hosts   []string `json:"hosts"`
		Paths   []string `json:"paths"`
		Profile string   `json:"profile"`
	}
	entry.Decode(&e)
	a.Hosts, a.Profile = nonNil(e.Hosts), e.Profile
	a.Paths = nonNil(e.Paths)
	f, err := wk.profile(name)
	if err != nil {
		a.Error = err.Error()
		writeJSON(w, http.StatusOK, a)
		return
	}
	var prof struct {
		Mode       string              `json:"mode"`
		Level      int                 `json:"paranoia_level"`
		Exceptions []profile.Exception `json:"exceptions"`
	}
	if err := f.value.Decode(&prof); err != nil {
		a.Error = err.Error()
	}
	a.Mode, a.Level, a.Exceptions = prof.Mode, prof.Level, nonNil(prof.Exceptions)
	if a.Mode == "" {
		a.Mode = profile.ModeMonitor
	}
	writeJSON(w, http.StatusOK, a)
}
