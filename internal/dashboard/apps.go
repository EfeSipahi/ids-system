package dashboard

// Applications and rules, each with a page of its own (decisions W1–W6 of
// docs/development-plan-dashboard-control.md). An application's page shows
// what concerns that application only; a rule's page shows where the rule
// runs, for every application.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// appRow is one application of the Applications list, with what its
// records hold in the period.
type appRow struct {
	result.AppStartup
	// Running is false for an application that only old records have:
	// the newest run's configuration does not have it any more.
	Running        bool      `json:"running"`
	Records        int       `json:"records"`
	Alerts         int       `json:"alerts"`
	NotReviewed    int       `json:"not_reviewed"`
	FalsePositives int       `json:"false_positives"`
	LastAlert      time.Time `json:"last_alert,omitzero"`
}

// appsPage is the Applications list.
type appsPage struct {
	Range timeRange `json:"range"`
	Run   string    `json:"run,omitempty"`
	// DefaultLevel is the level of the requests of no application, and of
	// applications without their own.
	DefaultLevel   int      `json:"default_level"`
	RequireProfile bool     `json:"require_profile"`
	Applications   []appRow `json:"applications"`
	// None is the requests of no application.
	None appRow `json:"none"`
}

// appKey is the application a record counts for on the Applications list:
// its name, or "none" for a request of no application and for a record of a
// run without applications.
func appKey(app string) string {
	if app == "" {
		return profile.NoApplication
	}
	return app
}

// applications lists the applications of the newest run, then those that
// only older records have, with the counts of the period.
func (s *store) applications(r timeRange) appsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := appsPage{Range: r, Applications: []appRow{}, None: appRow{AppStartup: result.AppStartup{Name: profile.NoApplication, Hosts: []string{}, Exceptions: []profile.ExceptionStatus{}}, Running: true}}
	rows := map[string]*appRow{profile.NoApplication: &p.None}
	st, ok := s.latestRun()
	if ok {
		p.Run, p.DefaultLevel, p.RequireProfile = st.Run, st.Engine.ParanoiaLevel, st.RequireProfile
		p.None.ParanoiaLevel = st.Engine.ParanoiaLevel
		for _, a := range st.Applications {
			p.Applications = append(p.Applications, appRow{AppStartup: a, Running: true})
		}
	}
	for i := range p.Applications {
		rows[p.Applications[i].Name] = &p.Applications[i]
	}
	var gone []appRow
	row := func(name string) *appRow {
		if r := rows[name]; r != nil {
			return r
		}
		gone = append(gone, appRow{AppStartup: result.AppStartup{Name: name, Hosts: []string{}, Exceptions: []profile.ExceptionStatus{}}})
		return nil
	}
	for _, e := range s.entries {
		name := appKey(e.app)
		if rows[name] == nil && !slices.ContainsFunc(gone, func(g appRow) bool { return g.Name == name }) {
			row(name)
		}
	}
	for i := range gone {
		rows[gone[i].Name] = &gone[i]
	}
	for _, e := range s.entries {
		if !r.contains(e.time) {
			continue
		}
		a := rows[appKey(e.app)]
		a.Records++
		if e.alert {
			a.Alerts++
			if s.marks.verdict(e.id) == verdictNotReviewed {
				a.NotReviewed++
			}
			if e.time.After(a.LastAlert) {
				a.LastAlert = e.time
			}
		}
	}
	s.marks.each(func(l markLine) {
		if l.Verdict == verdictFalsePositive && r.contains(l.Alert.Time) {
			if a := rows[appKey(l.Alert.Application)]; a != nil {
				a.FalsePositives++
			}
		}
	})
	slices.SortFunc(gone, func(a, b appRow) int { return strings.Compare(a.Name, b.Name) })
	p.Applications = append(p.Applications, gone...)
	return p
}

// appPage is one application's settings as the newest run has them, and
// the paths its records went to.
type appPage struct {
	Range       timeRange `json:"range"`
	Application appRow    `json:"application"`
	Run         string    `json:"run,omitempty"`
	RunTime     time.Time `json:"run_time,omitzero"`
	// DefaultLevel is the level of the configuration, which an
	// application without its own level runs at.
	DefaultLevel int `json:"default_level"`
	// Paths are the paths of its records in the period, most first.
	Paths []item `json:"top_paths"`
}

var errNoApp = errors.New("no such application")

// application returns one application's page. An application that only
// old records have is found too, with Running false.
func (s *store) application(name string, r timeRange) (appPage, error) {
	list := s.applications(r)
	var found *appRow
	for i := range list.Applications {
		if list.Applications[i].Name == name {
			found = &list.Applications[i]
		}
	}
	if found == nil {
		return appPage{}, errNoApp
	}
	p := appPage{Range: r, Application: *found, Run: list.Run, DefaultLevel: list.DefaultLevel}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, ok := s.latestRun(); ok {
		p.RunTime = st.Time
	}
	paths := map[string]int{}
	for _, e := range s.entries {
		if r.contains(e.time) && sameApp(e.app, name) {
			paths[e.method+" "+e.path]++
		}
	}
	p.Paths = top(paths)
	return p, nil
}

// ruleStatus is a rule's status for one application, or for the requests
// of no application.
type ruleStatus struct {
	Application string `json:"application"`
	// Running is false for an application that only old records have.
	Running bool `json:"running"`
	Level   int  `json:"level"`
	// Status is "runs", "above" (its level is above the application's),
	// "off" (the application's exception), or "excluded" (for every
	// application).
	Status   string   `json:"status"`
	Skips    []string `json:"skips,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	NoEffect string   `json:"no_effect,omitempty"`
	Fired    int      `json:"fired"`
	// FalsePositives counts its records marked false positive.
	FalsePositives int `json:"false_positives"`
}

// rulePage is one rule: what it is, where it runs, and what it found.
type rulePage struct {
	Range timeRange   `json:"range"`
	Rule  record.Rule `json:"rule"`
	Group string      `json:"group"`
	Run   string      `json:"run"`
	Time  time.Time   `json:"time"`
	CRS   string      `json:"crs"`
	// DefaultLevel is the configuration's level.
	DefaultLevel int `json:"default_level"`
	// Text is the rule as written in its file, with the rules chained to
	// it; TextError says why it is missing.
	Text      string `json:"text,omitempty"`
	TextError string `json:"text_error,omitempty"`
	// Statuses are its status for each application, then for the
	// requests of no application.
	Statuses       []ruleStatus `json:"statuses"`
	Fired          int          `json:"fired"`
	Alerts         int          `json:"alerts"`
	FalsePositives int          `json:"false_positives"`
	Series         []bucket     `json:"series"`
	BucketSecs     int          `json:"bucket_seconds"`
	Locations      []item       `json:"top_locations"`
	Paths          []item       `json:"top_paths"`
	IPs            []item       `json:"top_ips"`
	// TestFile is the file of CRS's tests for the rule in the test tab's
	// folder, and Tests how many it has.
	TestFile string `json:"test_file,omitempty"`
}

var errNoRule = errors.New("no such rule")

// statusFor is a rule's status at level with an application's exception.
func statusFor(rule record.Rule, level int, ex *profile.ExceptionStatus) ruleStatus {
	st := ruleStatus{Level: level, Status: "runs"}
	switch {
	case !rule.Active:
		st.Status, st.Reason = "excluded", rule.Reason
	case ex != nil && ex.Off:
		st.Status, st.Reason = "off", ex.Reason
	case rule.ParanoiaLevel > level:
		st.Status = "above"
	}
	if ex != nil {
		if len(ex.Skip) > 0 {
			st.Skips, st.Reason = ex.Skip, ex.Reason
		}
		st.NoEffect = ex.NoEffect
	}
	return st
}

// rule returns the page of one rule of the newest run.
func (s *store) rule(id int, r timeRange) (rulePage, error) {
	apps := s.applications(r)
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.latestRun()
	if !ok {
		return rulePage{}, errNoRule
	}
	i := slices.IndexFunc(s.rules[st.Run], func(x record.Rule) bool { return x.ID == id })
	if i < 0 {
		return rulePage{}, errNoRule
	}
	rule := s.rules[st.Run][i]
	p := rulePage{Range: r, Rule: rule, Group: fileGroup(rule.File), Run: st.Run, Time: st.Time, CRS: st.Engine.CRS, DefaultLevel: st.Engine.ParanoiaLevel, Statuses: []ruleStatus{}}

	byApp := map[string]*ruleStatus{}
	for _, a := range apps.Applications {
		var ex *profile.ExceptionStatus
		for j := range a.Exceptions {
			if a.Exceptions[j].Rule == id {
				ex = &a.Exceptions[j]
			}
		}
		level := a.ParanoiaLevel
		if !a.Running {
			level = st.Engine.ParanoiaLevel
		}
		rs := statusFor(rule, level, ex)
		rs.Application, rs.Running = a.Name, a.Running
		p.Statuses = append(p.Statuses, rs)
	}
	none := statusFor(rule, st.Engine.ParanoiaLevel, nil)
	none.Application, none.Running = profile.NoApplication, true
	p.Statuses = append(p.Statuses, none)
	for i := range p.Statuses {
		byApp[p.Statuses[i].Application] = &p.Statuses[i]
	}

	var times []time.Time
	locations, paths, ips := map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) || !slices.Contains(e.rules, id) {
			continue
		}
		times = append(times, e.time)
		p.Fired++
		if e.alert {
			p.Alerts++
		}
		if a := byApp[appKey(e.app)]; a != nil {
			a.Fired++
		}
		paths[e.method+" "+e.path]++
		if e.ip != "" {
			ips[e.ip]++
		}
		for _, l := range e.ruleLocations(id) {
			locations[l]++
		}
	}
	s.marks.each(func(l markLine) {
		if l.Verdict == verdictFalsePositive && r.contains(l.Alert.Time) && slices.Contains(l.Alert.Rules, id) {
			p.FalsePositives++
			if a := byApp[appKey(l.Alert.Application)]; a != nil {
				a.FalsePositives++
			}
		}
	})
	tl := newTimeline(r, s.earliest())
	for _, t := range times {
		if b := tl.slot(t); b != nil {
			b.Records++
		}
	}
	for _, e := range s.entries {
		if r.contains(e.time) && e.alert && slices.Contains(e.rules, id) {
			if b := tl.slot(e.time); b != nil {
				b.Alerts++
			}
		}
	}
	p.Series, p.BucketSecs = tl.series, int(tl.width/time.Second)
	p.Locations, p.Paths, p.IPs = top(locations), top(paths), top(ips)
	return p, nil
}

// ruleLocations returns the places rule id matched in the record, each
// once.
func (e *entry) ruleLocations(id int) []string {
	var out []string
	for _, f := range e.findings {
		if f.rule == id && f.location != "" && !slices.Contains(out, f.location) {
			out = append(out, f.location)
		}
	}
	return out
}

// maxRuleLines is the most lines of a rule's text that are shown.
const maxRuleLines = 120

// chainAction finds the chain action in a SecRule's actions.
var chainAction = regexp.MustCompile(`(?:^|[",\s])chain(?:[",\s]|$)`)

// ruleText reads the text of the rule at line of the rule file named file
// from the first of configs that loads such a file: the rule with its
// continuation lines, and the rules chained to it. configs are product
// configuration files; only their "files" are read.
func ruleText(configs []string, file string, line int) (string, error) {
	if line < 1 {
		return "", errors.New("the start record gives no line for this rule")
	}
	for _, c := range configs {
		path, err := ruleFile(c, file)
		if err != nil || path == "" {
			continue
		}
		return readRule(path, line)
	}
	if len(configs) == 0 {
		return "", errors.New("the dashboard knows no configuration of the IDS; name it as ids_config in the dashboard's configuration file")
	}
	return "", fmt.Errorf("no configuration the dashboard knows loads %s", file)
}

// ruleFile returns the path of the rule file named file that the
// configuration at config loads, or "" when it loads none of that name.
func ruleFile(config, file string) (string, error) {
	data, err := os.ReadFile(config)
	if err != nil {
		return "", err
	}
	var c struct {
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return "", err
	}
	for _, f := range c.Files {
		if !filepath.IsAbs(f) {
			f = filepath.Join(filepath.Dir(config), f)
		}
		if filepath.Base(f) == file {
			return f, nil
		}
	}
	return "", nil
}

// readRule reads the rule that starts at line of the file at path.
func readRule(path string, line int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var out []string
	n := 0
	statement := ""
	chained := false
	for sc.Scan() {
		n++
		if n < line {
			continue
		}
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		if statement == "" && n > line && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			// Between a rule and the rule chained to it.
			if !chained {
				break
			}
			continue
		}
		if statement == "" && n > line && !chained {
			break
		}
		out = append(out, text)
		statement += strings.TrimSuffix(trimmed, `\`) + " "
		if strings.HasSuffix(trimmed, `\`) {
			if len(out) >= maxRuleLines {
				break
			}
			continue
		}
		// The statement ends here; a chain action means the next rule
		// belongs to it.
		chained = chainAction.MatchString(actionsOf(statement))
		statement = ""
		if !chained || len(out) >= maxRuleLines {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", fmt.Errorf("%s has no line %d", filepath.Base(path), line)
	}
	return strings.Join(out, "\n"), nil
}

// actionsOf returns the last quoted part of a SecRule statement, which is
// its actions; a statement without quotes gives "".
func actionsOf(statement string) string {
	end := strings.LastIndex(statement, `"`)
	if end < 0 {
		return ""
	}
	start := strings.LastIndex(statement[:end], `"`)
	if start < 0 {
		return ""
	}
	return statement[start+1 : end]
}
