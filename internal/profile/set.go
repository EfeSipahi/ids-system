package profile

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// AppConfig is one entry of the configuration's "applications" (F2, F3).
type AppConfig struct {
	// Name identifies the application in records and in the dashboard.
	Name string `json:"name"`
	// Hosts are the Host header values the application answers to, with
	// the port when the requests carry one, such as "localhost:8080".
	Hosts []string `json:"hosts"`
	// Paths are optional path prefixes, for applications that share a
	// host. The longest prefix that fits wins. Left out, every path of
	// the hosts belongs to the application.
	Paths []string `json:"paths,omitempty"`
	// Profile is the profile file, relative to the configuration file.
	Profile string `json:"profile"`

	// Loaded is the profile, read by the configuration loader.
	Loaded *Profile `json:"-"`
}

// App is one application, ready for requests.
type App struct {
	Name    string
	Hosts   []string
	Paths   []string
	Profile *Profile

	// Tuning holds the application's rule exceptions and level, for
	// engine.RuleSet.EvaluateWith.
	Tuning *engine.Tuning
	// Exceptions are the profile's exceptions with what they do, for the
	// startup report and the records.
	Exceptions []ExceptionStatus
	// Notes name exceptions that change nothing yet, such as
	// "exceptions[1]: rule 942200 belongs to paranoia level 2 ...".
	Notes []string
}

// ParanoiaLevel returns the level the application's requests run at.
func (a *App) ParanoiaLevel() int {
	return a.Tuning.ParanoiaLevel()
}

// ExceptionStatus is one exception and its effect on the rules.
type ExceptionStatus struct {
	Exception
	// NoEffect is set when the exception changes nothing at the moment,
	// and says why. (The exception's own note is the author's text.)
	NoEffect string `json:"no_effect,omitempty"`
}

// Set is the applications of one configuration.
type Set struct {
	apps    []*App
	require bool
}

// NewSet prepares the applications for the loaded rules: each profile's
// exceptions are checked against the rules (F5) and turned into a Tuning.
// With requireProfile, a request that belongs to no application gets a
// finding (F7). A Set with no applications checks nothing.
func NewSet(rs *engine.RuleSet, configs []AppConfig, requireProfile bool) (*Set, error) {
	s := &Set{require: requireProfile}
	names := map[string]bool{}
	routes := map[string]string{}
	for i, c := range configs {
		if !isAppName(c.Name) {
			return nil, fmt.Errorf("applications[%d]: name %q: use letters, digits, ., - and _", i, c.Name)
		}
		if c.Name == NoApplication {
			return nil, fmt.Errorf("applications[%d]: the name %s is kept for requests of no application", i, NoApplication)
		}
		if names[c.Name] {
			return nil, fmt.Errorf("applications[%d]: the name %s is already used", i, c.Name)
		}
		names[c.Name] = true
		if len(c.Hosts) == 0 {
			return nil, fmt.Errorf("application %s: hosts is empty; name the Host values of its requests, such as \"localhost:8080\"", c.Name)
		}
		if c.Loaded == nil {
			return nil, fmt.Errorf("application %s: its profile is not loaded", c.Name)
		}
		app := &App{Name: c.Name, Profile: c.Loaded}
		for _, h := range c.Hosts {
			if h == "" || strings.ContainsAny(h, " /\t") {
				return nil, fmt.Errorf("application %s: host %q is not a host name with an optional port", c.Name, h)
			}
			app.Hosts = append(app.Hosts, strings.ToLower(h))
		}
		app.Paths = c.Paths
		prefixes := c.Paths
		if len(prefixes) == 0 {
			prefixes = []string{"/"}
		}
		for _, p := range prefixes {
			if !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("application %s: path %q does not start with /", c.Name, p)
			}
			for _, h := range app.Hosts {
				key := h + p
				if other, dup := routes[key]; dup {
					return nil, fmt.Errorf("application %s: host %s with path %s already belongs to application %s", c.Name, h, p, other)
				}
				routes[key] = c.Name
			}
		}
		spec, statuses, notes, err := prepareExceptions(rs, c.Loaded)
		if err != nil {
			return nil, err
		}
		tuning, more, err := rs.NewTuning(spec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Loaded.Path, err)
		}
		notes = append(notes, more...)
		app.Tuning, app.Exceptions, app.Notes = tuning, statuses, notes
		s.apps = append(s.apps, app)
	}
	return s, nil
}

// Apps returns the applications in the order of the configuration.
func (s *Set) Apps() []*App {
	return s.apps
}

// RequireProfile reports whether a request of no application is a finding.
func (s *Set) RequireProfile() bool {
	return s.require
}

// ByName returns the application called name, or nil.
func (s *Set) ByName(name string) *App {
	for _, a := range s.apps {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// Match returns the application that receives the request, or nil (F3):
// the one whose host is the request's Host header and whose path prefix
// is the longest that fits the decoded path. No other header is read, so
// a client cannot pick another application's profile; a Host of another
// application also sends the request to that application.
func (s *Set) Match(req *httpmodel.Request) *App {
	hosts := req.HeaderValues("Host")
	if len(hosts) == 0 || len(s.apps) == 0 {
		return nil
	}
	host := strings.ToLower(hosts[0])
	var best *App
	bestLen := -1
	for _, a := range s.apps {
		if !slices.Contains(a.Hosts, host) {
			continue
		}
		prefixes := a.Paths
		if len(prefixes) == 0 {
			prefixes = []string{"/"}
		}
		for _, p := range prefixes {
			if strings.HasPrefix(req.Parsed.DecodedPath, p) && len(p) > bestLen {
				best, bestLen = a, len(p)
			}
		}
	}
	return best
}

// The CRS settings a profile may change (F5, kind 1): the per-application
// policy settings of crs-setup.conf.example. The paranoia level has its own
// field; thresholds and scores wait for the decision mechanism (A06);
// sampling and persistent collections are not supported; and
// enforce_bodyproc_urlencoded stays off by the user's decision of 16
// October 2026.
var settings = map[string]string{
	"allowed_methods":                      "text",
	"allowed_request_content_type":         "text",
	"allowed_request_content_type_charset": "text",
	"allowed_http_versions":                "text",
	"restricted_extensions":                "text",
	"restricted_headers_basic":             "text",
	"restricted_headers_extended":          "text",
	"crs_validate_utf8_encoding":           "flag",
	"allow_method_override_parameter":      "flag",
	"arg_name_length":                      "number",
	"arg_length":                           "number",
	"total_arg_length":                     "number",
	"max_num_args":                         "number",
	"max_file_size":                        "number",
	"combined_file_sizes":                  "number",
}

// SettingNames returns the CRS settings a profile may change, sorted.
func SettingNames() []string {
	return sortedKeys(settings)
}

// protected are the CRS files whose rules no exception may touch (5c), with
// what to tell the user.
var protected = map[string]string{
	"REQUEST-901-": "It is in %s, which sets up CRS: the alert threshold and the starting values. Without it the rules would not work as written for this application.",
	"REQUEST-949-": "It is in %s, which adds up the attack score; without it this application would never raise an alert.",
}

// prepareExceptions checks a profile's exceptions against the loaded rules
// and returns them as an engine.TuningSpec.
func prepareExceptions(rs *engine.RuleSet, p *Profile) (engine.TuningSpec, []ExceptionStatus, []string, error) {
	spec := engine.TuningSpec{ParanoiaLevel: p.ParanoiaLevel, Settings: map[string]string{}, Skips: map[int][]string{}}
	level := p.ParanoiaLevel
	if level == 0 {
		level = rs.ParanoiaLevel()
	}
	statusOf := map[int]engine.RuleStatus{}
	for _, st := range rs.Statuses() {
		statusOf[st.ID] = st
	}
	fail := func(i int, format string, args ...any) error {
		return fmt.Errorf("%s: exceptions[%d]: %s", p.Path, i, fmt.Sprintf(format, args...))
	}

	var statuses []ExceptionStatus
	var notes []string
	ruleUsed := map[int]int{}
	for i, ex := range p.Exceptions {
		status := ExceptionStatus{Exception: ex}
		if ex.Setting != "" {
			kind, ok := settings[ex.Setting]
			if !ok {
				return spec, nil, nil, fail(i, "the setting %s cannot be changed by a profile. These can: %s", ex.Setting, strings.Join(SettingNames(), ", "))
			}
			if _, dup := spec.Settings[ex.Setting]; dup {
				return spec, nil, nil, fail(i, "the setting %s is already given by another exception", ex.Setting)
			}
			if err := checkSettingValue(kind, *ex.Value); err != nil {
				return spec, nil, nil, fail(i, "setting %s: %v", ex.Setting, err)
			}
			spec.Settings[ex.Setting] = *ex.Value
			statuses = append(statuses, status)
			continue
		}

		st, ok := statusOf[ex.Rule]
		if !ok {
			return spec, nil, nil, fail(i, "rule %d is in none of the loaded rule files", ex.Rule)
		}
		file := filepath.Base(st.Pos.File)
		for prefix, why := range protected {
			if strings.HasPrefix(file, prefix) {
				return spec, nil, nil, fail(i, "rule %d cannot be excepted.\n"+why+"\nRemove this exception, or except the attack rule that causes the false alarm.", ex.Rule, file)
			}
		}
		if prev, dup := ruleUsed[ex.Rule]; dup {
			return spec, nil, nil, fail(i, "rule %d already has exceptions[%d]; write one exception per rule", ex.Rule, prev)
		}
		ruleUsed[ex.Rule] = i
		for j, s := range ex.Skip {
			if err := engine.CheckTarget(s); err != nil {
				return spec, nil, nil, fail(i, "skip[%d] %q: %v", j, s, err)
			}
		}
		switch {
		case !st.Active:
			status.NoEffect = fmt.Sprintf("rule %d is excluded by the configuration (%s), so this exception changes nothing", ex.Rule, st.Reason)
		case st.ParanoiaLevel > level:
			status.NoEffect = fmt.Sprintf("rule %d belongs to paranoia level %d and does not run at level %d; this exception takes effect when the level is raised", ex.Rule, st.ParanoiaLevel, level)
		}
		if status.NoEffect != "" {
			notes = append(notes, fmt.Sprintf("exceptions[%d]: %s", i, status.NoEffect))
		}
		if st.Active {
			if ex.Off {
				spec.Off = append(spec.Off, ex.Rule)
			} else {
				spec.Skips[ex.Rule] = ex.Skip
			}
		}
		statuses = append(statuses, status)
	}
	return spec, statuses, notes, nil
}

func checkSettingValue(kind, v string) error {
	for _, c := range v {
		if c < ' ' || c == 0x7f {
			return errors.New("the value has a control character")
		}
	}
	switch kind {
	case "flag":
		if v != "0" && v != "1" {
			return errors.New("the value must be 0 or 1")
		}
	case "number":
		if n, err := strconv.Atoi(v); err != nil || n < 1 {
			return errors.New("the value must be a whole number of at least 1")
		}
	}
	return nil
}

func isAppName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
