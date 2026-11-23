package dashboard

// The preview of pending changes (W8 of
// docs/development-plan-dashboard-control.md). Records keep what each rule
// matched and what it added to the score, not whole requests (R4). So a
// change that takes detection away, a rule off or skipping a place, a
// lower level, a rule file left out, can be worked out exactly from the
// records: their findings without the ones it removes, their score added
// up again. A change that adds detection can't: the requests themselves
// would be needed. The preview says which is which.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// preview is what an object's pending changes would do to the records
// kept.
type preview struct {
	Object  string `json:"object"`
	Reach   string `json:"reach"`
	Changes int    `json:"changes"`
	// Error says why the changes can't be applied as they are, such as a
	// file changed by hand since they were added.
	Error string `json:"error,omitempty"`
	// Records are those of the reach, every one kept, and Alerts those of
	// them that are alerts under the settings now; Since is the oldest.
	Records int       `json:"records"`
	Alerts  int       `json:"alerts"`
	Since   time.Time `json:"since,omitzero"`
	// AlertsRemoved would no longer be alerts, RecordsRemoved would no
	// longer be recorded at all, and AlertsAdded would become alerts.
	AlertsRemoved  int `json:"alerts_removed"`
	RecordsRemoved int `json:"records_removed"`
	AlertsAdded    int `json:"alerts_added"`
	// The alerts removed by their mark: RealAttacks is the warning (W8).
	RealAttacks    int `json:"real_attacks"`
	FalsePositives int `json:"false_positives"`
	NotReviewed    int `json:"not_reviewed"`
	// ByRule counts the alerts removed by the rule whose findings went.
	ByRule []item `json:"by_rule"`
	// Examples are alerts removed, those marked real attack first, then
	// the newest.
	Examples []row `json:"examples"`
	// Untested names what the records can't tell.
	Untested []string `json:"untested"`
}

// maxExamples is how many removed alerts the preview lists.
const maxExamples = 10

// tuning is what decides whether a rule runs for one application.
type tuning struct {
	level    int
	mode     string
	off      map[int]bool
	skips    map[int][]string
	settings string // its CRS settings, as text
}

// state is what decides whether a rule runs, for every application.
type state struct {
	files    map[string]bool // the rule files loaded, by name
	excluded map[int]bool
	level    int
	apps     map[string]*tuning // by name; "none" for no application
	hosts    map[string]string  // the hosts and paths of each application, as text
	require  bool
	limit    int
	// own are the own rules of the configuration, by id, with the
	// applications each is for (nil: every request), and ownText their
	// text without those; ownErr says why they can't be read.
	own     map[int][]string
	ownText map[int]string
	ownErr  error
}

func newState(p *config.Product) *state {
	st := &state{files: map[string]bool{}, excluded: map[int]bool{}, level: p.Level(), apps: map[string]*tuning{}, hosts: map[string]string{}, require: p.RequireProfile}
	for _, f := range p.Files {
		st.files[filepath.Base(f)] = true
	}
	if p.OwnRules != "" {
		st.files[filepath.Base(p.OwnRules)] = true
		st.own, st.ownText = map[int][]string{}, map[int]string{}
		rules, err := engine.ReadOwnRules(p.Config)
		st.ownErr = err
		for _, r := range rules {
			st.own[r.ID] = r.Applications
			st.ownText[r.ID] = withoutScope(r.Text)
		}
	}
	for _, ex := range p.Exclude {
		st.excluded[ex.ID] = true
	}
	if p.RequestBodyLimit != nil {
		st.limit = *p.RequestBodyLimit
	}
	st.apps[profile.NoApplication] = &tuning{level: st.level}
	for _, a := range p.Applications {
		t := &tuning{level: a.Loaded.ParanoiaLevel, mode: a.Loaded.Mode, off: map[int]bool{}, skips: map[int][]string{}}
		if t.level == 0 {
			t.level = st.level
		}
		var settings []string
		for _, ex := range a.Loaded.Exceptions {
			if ex.Setting != "" && ex.Value != nil {
				settings = append(settings, ex.Setting+"="+*ex.Value)
			}
			switch {
			case ex.Rule != 0 && ex.Off:
				t.off[ex.Rule] = true
			case ex.Rule != 0:
				t.skips[ex.Rule] = ex.Skip
			}
		}
		sort.Strings(settings)
		t.settings = strings.Join(settings, "\n")
		st.apps[a.Name] = t
		st.hosts[a.Name] = strings.Join(a.Hosts, ",") + " " + strings.Join(a.Paths, ",")
	}
	return st
}

// runs reports whether rule runs for an application. An own rule runs
// while the own-rules file has it, for the applications it names.
func (st *state) runs(rule record.Rule, app string) bool {
	t := st.apps[app]
	switch {
	case t == nil, !st.files[rule.File], st.excluded[rule.ID], t.off[rule.ID]:
		return false
	}
	if rule.Own {
		apps, ok := st.own[rule.ID]
		if !ok || apps != nil && !slices.Contains(apps, app) {
			return false
		}
	}
	return rule.ParanoiaLevel == 0 || rule.ParanoiaLevel <= t.level
}

// skips reports whether rule skips the place location for an application.
func (st *state) skips(rule int, app, location string) bool {
	t := st.apps[app]
	if t == nil {
		return false
	}
	for _, target := range t.skips[rule] {
		if skipMatches(target, location) {
			return true
		}
	}
	return false
}

// skipMatches reports whether a skipped variable, as an exception writes
// it ("ARGS:pwd", "ARGS", "ARGS:/^json\./"), covers the place a finding
// names ("ARGS:pwd"). A chained rule's place may be named through
// MATCHED_VARS.
func skipMatches(target, location string) bool {
	location = strings.TrimPrefix(location, "MATCHED_VARS:")
	tcol, tkey, hasKey := strings.Cut(target, ":")
	lcol, lkey, _ := strings.Cut(location, ":")
	if !strings.EqualFold(tcol, lcol) {
		return false
	}
	if !hasKey {
		return true
	}
	if len(tkey) >= 2 && strings.HasPrefix(tkey, "/") && strings.HasSuffix(tkey, "/") {
		re, err := regexp.Compile("(?i)" + tkey[1:len(tkey)-1])
		return err == nil && re.MatchString(lkey)
	}
	return strings.EqualFold(tkey, lkey)
}

// previewChanges works out what the changes from before to after would do
// to the records of the reach: an application's records, or every record.
func (s *store) previewChanges(object string, before, after *config.Product) preview {
	p := preview{Object: object, Reach: reach(object), ByRule: []item{}, Examples: []row{}, Untested: []string{}}
	old, now := newState(before), newState(after)
	for _, st := range []*state{old, now} {
		if st.ownErr != nil && p.Error == "" {
			p.Error = "the own rules can't be read: " + st.ownErr.Error()
		}
	}
	app := objectApp(object)

	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.latestRun()
	rules := map[int]record.Rule{}
	if ok {
		for _, r := range s.rules[run.Run] {
			rules[r.ID] = r
		}
	}
	p.Untested = nonNil(untested(old, now, rules))

	byRule := map[int]int{}
	type removed struct {
		e       *entry
		verdict string
	}
	var gone []removed
	for _, e := range s.entries {
		name := appKey(e.app)
		if object != objectGlobal && !sameApp(e.app, app) {
			continue
		}
		if old.apps[name] == nil {
			// A record of an application the configuration no longer
			// has: the changes don't concern it.
			continue
		}
		p.Records++
		if p.Since.IsZero() || e.time.Before(p.Since) {
			p.Since = e.time
		}
		// Each finding counts under a state when its rule runs there and
		// does not skip its place. A record made before a rule was
		// switched off still has the rule's findings, so switching it
		// back on can be worked out too.
		oldScore, newScore, oldLeft, newLeft := e.score, e.score, 0, 0
		var lost []int
		for _, f := range e.findings {
			r, known := rules[f.rule]
			if !known {
				if groupOf(f.rule).counts {
					oldLeft++
					newLeft++
				}
				continue
			}
			inOld := old.runs(r, name) && !(f.location != "" && old.skips(f.rule, name, f.location))
			inNew := now.runs(r, name) && !(f.location != "" && now.skips(f.rule, name, f.location))
			if !inOld {
				oldScore -= f.weight
			} else if groupOf(f.rule).counts {
				oldLeft++
			}
			if !inNew {
				newScore -= f.weight
			} else if groupOf(f.rule).counts {
				newLeft++
			}
			if inOld && !inNew && !slices.Contains(lost, f.rule) {
				lost = append(lost, f.rule)
			}
		}
		// The record's alert decision under the settings of now and of
		// after, so that a record of an older run, made with other
		// settings, counts only for what these changes do.
		wasAlert := e.threshold > 0 && oldScore >= e.threshold || e.profiled && old.apps[name].mode == profile.ModeAlert
		alert := e.threshold > 0 && newScore >= e.threshold || e.profiled && now.apps[name] != nil && now.apps[name].mode == profile.ModeAlert
		if wasAlert {
			p.Alerts++
		}
		switch {
		case wasAlert && !alert:
			p.AlertsRemoved++
			v := s.marks.verdict(e.id)
			switch v {
			case verdictRealAttack:
				p.RealAttacks++
			case verdictFalsePositive:
				p.FalsePositives++
			case verdictNotReviewed:
				p.NotReviewed++
			}
			for _, id := range lost {
				if groupOf(id).counts {
					byRule[id]++
				}
			}
			gone = append(gone, removed{e, v})
		case !wasAlert && alert:
			p.AlertsAdded++
		}
		if oldLeft > 0 && newLeft == 0 && !e.profiled && !e.incomplete {
			p.RecordsRemoved++
		}
	}
	p.ByRule = topInts(byRule)
	for i := range p.ByRule {
		if r, ok := rules[atoi(p.ByRule[i].Key)]; ok {
			p.ByRule[i].Msg = r.Msg
		}
	}
	sort.SliceStable(gone, func(i, j int) bool {
		ri, rj := gone[i].verdict == verdictRealAttack, gone[j].verdict == verdictRealAttack
		if ri != rj {
			return ri
		}
		return gone[i].e.time.After(gone[j].e.time)
	})
	for _, g := range gone[:min(len(gone), maxExamples)] {
		e := g.e
		p.Examples = append(p.Examples, row{
			ID: e.id, Time: e.time, Alert: e.alert, Score: e.score, IP: e.ip, Method: e.method, Host: e.host,
			Path: e.path, Rules: nonNil(e.rules), Groups: nonNil(e.groups), Locations: nonNil(e.locations),
			Application: e.app, Verdict: g.verdict,
		})
	}
	return p
}

func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// appTag is an own rule's tag that names an application (N5).
var appTag = regexp.MustCompile(`tag:'?` + regexp.QuoteMeta(engine.ApplicationTag) + `[^',"]*'?,?`)

// withoutScope is an own rule's text without the tags that say which
// requests it is for, its spaces and line breaks made one space: two
// rules with the same text so are the same but for whom they are for,
// which the preview can work out.
func withoutScope(text string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(appTag.ReplaceAllString(text, ""), "\\\n", " ")), " ")
}

// untested names what the changes do that the records can't tell.
func untested(old, now *state, rules map[int]record.Rule) []string {
	var out, own []string
	// Own rules: a new one, or one whose conditions, message or severity
	// change, finds what the records can't show.
	var ownNew, ownChanged []int
	for id, text := range now.ownText {
		before, ok := old.ownText[id]
		switch {
		case !ok:
			ownNew = append(ownNew, id)
		case before != text:
			ownChanged = append(ownChanged, id)
		}
	}
	slices.Sort(ownNew)
	slices.Sort(ownChanged)
	for _, id := range ownNew {
		own = append(own, fmt.Sprintf("Own rule %d is new: the records keep only what rules found, so what it would find can't be told from them. Try it in the Test tab, with the pending changes, or on request files with Analyse files.", id))
	}
	for _, id := range ownChanged {
		own = append(own, fmt.Sprintf("Own rule %d changes: what it would find as it is written now can't be told from the records; they count its old findings above as they are. Try it in the Test tab, with the pending changes.", id))
	}
	more := map[string]int{} // rules that would run where they did not, by application
	for name, t := range now.apps {
		if old.apps[name] == nil {
			continue
		}
		for _, r := range rules {
			if now.runs(r, name) && !old.runs(r, name) {
				more[name]++
			}
		}
		for id, targets := range old.apps[name].skips {
			for _, target := range targets {
				if !slices.Contains(t.skips[id], target) && now.runs(rules[id], name) {
					more[name]++
				}
			}
		}
	}
	// A higher level is said even when the start record lists none of the
	// rules it adds.
	raised := map[string][2]int{}
	for name, t := range now.apps {
		if o := old.apps[name]; o != nil && t.level > o.level {
			raised[name] = [2]int{o.level, t.level}
			if more[name] == 0 {
				more[name] = -1
			}
		}
	}
	names := make([]string, 0, len(more))
	for n := range more {
		names = append(names, n)
	}
	sort.Strings(names)
	const tell = "The records keep only what the rules found, so what more rules would find can't be told from them; try request files with Analyse files."
	for _, n := range names {
		who := "requests of no application"
		if n != profile.NoApplication {
			who = n
		}
		count := "more rules"
		if more[n] > 0 {
			count = fmt.Sprintf("%d more %s", more[n], plural(more[n], "rule", "rules"))
		}
		if r, ok := raised[n]; ok {
			out = append(out, fmt.Sprintf("The paranoia level for %s goes from %d to %d, so %s would run. %s", who, r[0], r[1], count, tell))
		} else {
			out = append(out, fmt.Sprintf("%s would look at more for %s: a rule or a place back on. Records made before it was switched off are counted above; records made while it was off can't show what it would have found. Try request files with Analyse files.", capitalise(count), who))
		}
	}
	for name := range now.apps {
		if name == profile.NoApplication {
			continue
		}
		if old.apps[name] == nil {
			out = append(out, fmt.Sprintf("%s is a new application: its requests are recorded as no application until it runs, so the records can't tell what its profile will find.", name))
		} else if old.apps[name].settings != now.apps[name].settings {
			out = append(out, fmt.Sprintf("The CRS settings of %s change; the records can't tell what the rules would find with them. Try request files with Analyse files.", name))
		}
		if old.apps[name] != nil && old.hosts[name] != now.hosts[name] {
			out = append(out, fmt.Sprintf("The hosts or paths of %s change, and with them which requests are its own; the records can't tell which requests would move.", name))
		}
	}
	for name := range old.apps {
		if now.apps[name] == nil {
			out = append(out, fmt.Sprintf("Without the application %s, its requests would run as requests of no application, at the default level and without a profile; the records can't tell what that finds.", name))
		}
	}
	if old.limit != now.limit {
		out = append(out, "A new body limit changes how much of each body is read; the records can't tell what a longer or shorter part would show.")
	}
	if now.require && !old.require {
		out = append(out, "Requests of no application would get a no_profile finding, so each of them would be recorded.")
	}
	sort.Strings(out[min(len(out), len(names)):])
	return append(out, own...)
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
