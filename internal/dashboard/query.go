package dashboard

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// timeRange is the period a page shows.
type timeRange struct {
	Name string    `json:"name"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// endOpen leaves To itself out, as a bar of the chart does: a record
	// at the end of one bar belongs to the next.
	endOpen bool
}

// ranges are the periods a user can choose. "all" starts at the zero time.
var ranges = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "all": 0}

const defaultRange = "24h"

func parseRange(v string, now time.Time) (timeRange, error) {
	if v == "" {
		v = defaultRange
	}
	d, ok := ranges[v]
	if !ok {
		return timeRange{}, fmt.Errorf("range %q is not one of 1h, 24h, 7d, all", v)
	}
	r := timeRange{Name: v, To: now.UTC()}
	if d > 0 {
		r.From = r.To.Add(-d)
	}
	return r, nil
}

func (r timeRange) contains(t time.Time) bool {
	if r.endOpen && !t.Before(r.To) {
		return false
	}
	return !t.Before(r.From) && !t.After(r.To)
}

// parsePeriod reads the period of the alerts list: a range name, or from
// and to (RFC 3339) for a bar picked on the chart. Such a period is named
// "custom" and leaves its end out.
func parsePeriod(q url.Values, now time.Time) (timeRange, error) {
	from, to := q.Get("from"), q.Get("to")
	if from == "" && to == "" {
		return parseRange(q.Get("range"), now)
	}
	f, errFrom := time.Parse(time.RFC3339Nano, from)
	t, errTo := time.Parse(time.RFC3339Nano, to)
	if errFrom != nil || errTo != nil || !f.Before(t) {
		return timeRange{}, fmt.Errorf("from %q and to %q are not two RFC 3339 times, the first before the second", from, to)
	}
	return timeRange{Name: "custom", From: f.UTC(), To: t.UTC(), endOpen: true}, nil
}

// item is one line of a "top" list.
type item struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	// Msg is a rule's msg text, from the newest start record.
	Msg   string `json:"msg,omitempty"`
	Count int    `json:"count"`
}

// bucket is one bar of the chart over time.
type bucket struct {
	Start    time.Time `json:"start"`
	Analysed int       `json:"analysed"`
	Records  int       `json:"records"`
	Alerts   int       `json:"alerts"`
}

type overview struct {
	Range      timeRange `json:"range"`
	Analysed   int       `json:"analysed"`
	Recorded   int       `json:"recorded"`
	Alerts     int       `json:"alerts"`
	Incomplete int       `json:"incomplete"`
	// Profiled is true when the newest run has applications, and
	// NoProfile counts the requests analysed in the period that belonged
	// to no application, so only the rules checked them (F9).
	Profiled   bool      `json:"profiled"`
	NoProfile  int       `json:"no_profile"`
	Series     []bucket  `json:"series"`
	BucketSecs int       `json:"bucket_seconds"`
	Rules      []item    `json:"top_rules"`
	Groups     []item    `json:"top_groups"`
	Locations  []item    `json:"top_locations"`
	IPs        []item    `json:"top_ips"`
	LastRecord time.Time `json:"last_record,omitzero"`
	LastAlert  time.Time `json:"last_alert,omitzero"`

	// NotAnalysed counts the requests of the live input that were not
	// analysed in the period, from the gap records (T7, T8); NotAnalysedBy
	// splits it by source and reason, and Gaps are the newest gaps.
	NotAnalysed   int64         `json:"not_analysed"`
	NotAnalysedBy []missedCount `json:"not_analysed_by"`
	Gaps          []gapRow      `json:"gaps"`
	GapCount      int           `json:"gap_count"`
	// UnknownApps are the application names the proxy gave that the
	// configuration does not have, with their requests in the period (T6).
	UnknownApps []item `json:"unknown_applications"`
	// Live is the state of the newest run when its input is live.
	Live *liveStatus `json:"live,omitempty"`
	// NotReviewed counts the alerts of the period that nobody marked yet
	// (G1).
	NotReviewed int `json:"not_reviewed"`

	// Application is the application the overview is for (W1), or
	// "none" for the requests of no application; empty for every
	// request. The counts of the IDS, the gaps and the unknown
	// application names are not kept per application, so with one they
	// are left out.
	Application string `json:"application,omitempty"`
	// FalsePositives counts the records of the period marked false
	// positive.
	FalsePositives int `json:"false_positives"`
}

// missedCount is the not-analysed total of one source and reason.
type missedCount struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
	Missed int64  `json:"missed"`
}

// gapRow is one gap record.
type gapRow struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Missed int64     `json:"missed"`
	Reason string    `json:"reason"`
	Source string    `json:"source"`
}

// liveStatus says whether a live run is writing, and whether a proxy is
// sending to it.
type liveStatus struct {
	Socket string    `json:"socket,omitempty"`
	Start  time.Time `json:"start"`
	// LastCounts is the end of the run's newest counts record, and Copiers
	// the copiers that record saw (most at once in its period). Both are
	// left out before the first counts record.
	LastCounts time.Time `json:"last_counts,omitzero"`
	Copiers    *int      `json:"copiers,omitempty"`
	// Stale is true when nothing has been written for longer than
	// staleAfter: ids-live writes a counts record every minute, so it has
	// stopped, crashed or hangs (decided by the user, 18 November 2026).
	Stale bool `json:"stale"`
}

// staleAfter is how old a live run's newest counts record may be. ids-live
// writes one every minute.
const staleAfter = 2 * time.Minute

// maxGaps is how many of the newest gaps the overview lists.
const maxGaps = 10

const (
	topSize = 10
	buckets = 48
)

func (s *store) overview(r timeRange) overview {
	return s.overviewFor(r, "")
}

// timeline is the bars of a chart over a period.
type timeline struct {
	series []bucket
	width  time.Duration
	from   time.Time
}

// newTimeline makes the bars of r. With "all", the chart starts at
// earliest, the first thing recorded.
func newTimeline(r timeRange, earliest time.Time) timeline {
	from := r.From
	if from.IsZero() {
		from = r.To
		if !earliest.IsZero() && earliest.Before(from) {
			from = earliest
		}
	}
	width := bucketWidth(r.To.Sub(from))
	from = from.Truncate(width)
	n := int(r.To.Sub(from)/width) + 1
	tl := timeline{series: make([]bucket, n), width: width, from: from}
	for i := range tl.series {
		tl.series[i].Start = from.Add(time.Duration(i) * width)
	}
	return tl
}

// slot returns the bar of t, or nil when t is outside the chart.
func (tl timeline) slot(t time.Time) *bucket {
	i := int(t.Sub(tl.from) / tl.width)
	if i < 0 || i >= len(tl.series) {
		return nil
	}
	return &tl.series[i]
}

// earliest returns the time of the first record or counts record.
func (s *store) earliest() time.Time {
	var first time.Time
	for _, e := range s.entries {
		if first.IsZero() || e.time.Before(first) {
			first = e.time
		}
	}
	for _, c := range s.counts {
		if first.IsZero() || c.From.Before(first) {
			first = c.From
		}
	}
	return first
}

// overviewFor is the overview of one application's records (W1), or of
// every record when app is "".
func (s *store) overviewFor(r timeRange, app string) overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := overview{Range: r, Application: app}

	tl := newTimeline(r, s.earliest())
	o.Series, o.BucketSecs = tl.series, int(tl.width/time.Second)
	slot := tl.slot

	// A counts record belongs to the period when its end is in it. The
	// counts are not kept per application.
	for _, c := range s.counts {
		if app == "" && r.contains(c.To) && c.To.After(r.From) {
			o.Analysed += c.Analysed
			o.NoProfile += c.NoProfile
			if b := slot(c.To); b != nil {
				b.Analysed += c.Analysed
			}
		}
	}
	rules, groupCounts, locations, ips := map[int]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) || app != "" && !sameApp(e.app, app) {
			continue
		}
		o.Recorded++
		b := slot(e.time)
		if b != nil {
			b.Records++
		}
		if e.alert {
			o.Alerts++
			if b != nil {
				b.Alerts++
			}
			if s.marks.verdict(e.id) == verdictNotReviewed {
				o.NotReviewed++
			}
			if e.time.After(o.LastAlert) {
				o.LastAlert = e.time
			}
		}
		if e.incomplete {
			o.Incomplete++
		}
		if e.time.After(o.LastRecord) {
			o.LastRecord = e.time
		}
		for _, id := range e.rules {
			if groupOf(id).counts {
				rules[id]++
			}
		}
		for _, g := range e.groups {
			groupCounts[g]++
		}
		for _, l := range e.locations {
			locations[l]++
		}
		if e.ip != "" {
			ips[e.ip]++
		}
	}
	o.Rules = topInts(rules)
	if st, ok := s.latestRun(); ok {
		o.Profiled = len(st.Applications) > 0
		msgs := map[string]string{}
		for _, rule := range s.rules[st.Run] {
			msgs[strconv.Itoa(rule.ID)] = rule.Msg
		}
		for i := range o.Rules {
			o.Rules[i].Msg = msgs[o.Rules[i].Key]
		}
	}
	o.Groups = top(groupCounts)
	o.Locations = top(locations)
	o.IPs = top(ips)
	s.marks.each(func(l markLine) {
		if l.Verdict == verdictFalsePositive && r.contains(l.Alert.Time) && (app == "" || sameApp(l.Alert.Application, app)) {
			o.FalsePositives++
		}
	})
	s.liveParts(&o, r)
	if app != "" {
		o.NotAnalysed, o.NotAnalysedBy, o.Gaps, o.GapCount, o.UnknownApps = 0, []missedCount{}, []gapRow{}, 0, []item{}
	}
	return o
}

// liveParts adds what the live input wrote: gaps, unknown application
// names, and the state of the newest run. A gap belongs to the period when
// its end is in it, as a counts record does. The caller holds s.mu.
func (s *store) liveParts(o *overview, r timeRange) {
	o.NotAnalysedBy, o.Gaps, o.UnknownApps = []missedCount{}, []gapRow{}, []item{}
	by := map[[2]string]int64{}
	for _, g := range s.gaps {
		if !r.contains(g.To) {
			continue
		}
		o.NotAnalysed += g.Missed
		by[[2]string{g.Source, g.Reason}] += g.Missed
		o.Gaps = append(o.Gaps, gapRow{From: g.From, To: g.To, Missed: g.Missed, Reason: g.Reason, Source: g.Source})
	}
	for k, n := range by {
		o.NotAnalysedBy = append(o.NotAnalysedBy, missedCount{Source: k[0], Reason: k[1], Missed: n})
	}
	sort.Slice(o.NotAnalysedBy, func(i, j int) bool {
		a, b := o.NotAnalysedBy[i], o.NotAnalysedBy[j]
		if a.Missed != b.Missed {
			return a.Missed > b.Missed
		}
		return a.Source+a.Reason < b.Source+b.Reason
	})
	sort.SliceStable(o.Gaps, func(i, j int) bool { return o.Gaps[i].To.After(o.Gaps[j].To) })
	o.GapCount = len(o.Gaps)
	if len(o.Gaps) > maxGaps {
		o.Gaps = o.Gaps[:maxGaps]
	}

	unknown := map[string]int{}
	for _, c := range s.counts {
		if r.contains(c.To) && c.To.After(r.From) {
			for name, n := range c.UnknownApplications {
				unknown[name] += n
			}
		}
	}
	o.UnknownApps = top(unknown)

	st, ok := s.latestRun()
	if !ok || st.Input == nil || st.Input.Kind != record.InputLive {
		return
	}
	live := &liveStatus{Socket: st.Input.Socket, Start: st.Time}
	for _, c := range s.counts {
		if c.Run == st.Run && c.To.After(live.LastCounts) {
			live.LastCounts, live.Copiers = c.To, c.Copiers
		}
	}
	since := live.LastCounts
	if since.IsZero() {
		since = st.Time
	}
	live.Stale = r.To.Sub(since) > staleAfter
	o.Live = live
}

// bucketWidths are the widths a bar of the chart may have. Round widths
// put the bars on round times, such as every 30 minutes.
var bucketWidths = []time.Duration{
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour,
	24 * time.Hour, 2 * 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour,
}

// bucketWidth is the smallest round width that shows span in at most
// buckets bars.
func bucketWidth(span time.Duration) time.Duration {
	for _, w := range bucketWidths {
		if span/w <= buckets {
			return w
		}
	}
	return span/buckets + 1
}

func top(counts map[string]int) []item {
	items := make([]item, 0, len(counts))
	for k, n := range counts {
		items = append(items, item{Key: k, Count: n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if len(items) > topSize {
		items = items[:topSize]
	}
	return items
}

func topInts(counts map[int]int) []item {
	byKey := map[string]int{}
	for id, n := range counts {
		byKey[strconv.Itoa(id)] = n
	}
	items := top(byKey)
	for i := range items {
		id, _ := strconv.Atoi(items[i].Key)
		items[i].Label = groupName(id)
	}
	return items
}

// filter is what the alerts page asks for.
type filter struct {
	Range    timeRange
	Kind     string // "alerts", "all" or "incomplete"
	Rule     int
	Group    string
	IP       string
	Location string
	// App is an application's name, or profile.NoApplication for the
	// requests of none; empty for every request.
	App      string
	MinScore int
	Sort     string // "time" (newest first) or "score" (highest first)
	Page     int
	// Review is a verdict (G1), "not_reviewed" included; empty for all.
	Review string
}

func parseFilter(q url.Values, now time.Time) (filter, error) {
	r, err := parsePeriod(q, now)
	if err != nil {
		return filter{}, err
	}
	f := filter{Range: r, Kind: q.Get("kind"), Group: q.Get("group"), IP: strings.TrimSpace(q.Get("ip")), Location: strings.TrimSpace(q.Get("location")), App: strings.TrimSpace(q.Get("app")), Sort: q.Get("sort"), Page: 1, Review: q.Get("review")}
	if f.Review != "" && !slices.Contains(verdicts, f.Review) {
		return filter{}, fmt.Errorf("review %q is not one of %s", f.Review, strings.Join(verdicts, ", "))
	}
	if len(f.App) > maxAppName {
		return filter{}, fmt.Errorf("app is longer than %d characters", maxAppName)
	}
	switch f.Sort {
	case "":
		f.Sort = "time"
	case "time", "score":
	default:
		return filter{}, fmt.Errorf("sort %q is not one of time, score", f.Sort)
	}
	switch f.Kind {
	case "":
		f.Kind = "alerts"
	case "alerts", "all", "incomplete":
	default:
		return filter{}, fmt.Errorf("kind %q is not one of alerts, all, incomplete", f.Kind)
	}
	for _, p := range []struct {
		name string
		to   *int
		min  int
	}{{"rule", &f.Rule, 0}, {"min_score", &f.MinScore, 0}, {"page", &f.Page, 1}} {
		if v := q.Get(p.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < p.min {
				return filter{}, fmt.Errorf("%s %q is not a number of at least %d", p.name, v, p.min)
			}
			*p.to = n
		}
	}
	return f, nil
}

// maxAppName is the longest application name (see profile.NewSet).
const maxAppName = 64

// sameApp reports whether a record's application is app. A record of a run
// without applications belongs to none, as a request of no application.
func sameApp(recordApp, app string) bool {
	if app == profile.NoApplication {
		return recordApp == "" || recordApp == profile.NoApplication
	}
	return recordApp == app
}

func (f filter) match(e *entry) bool {
	switch {
	case !f.Range.contains(e.time):
	case f.App != "" && !sameApp(e.app, f.App):
	case f.Kind == "alerts" && !e.alert:
	case f.Kind == "incomplete" && !e.incomplete:
	case f.Rule != 0 && !slices.Contains(e.rules, f.Rule):
	case f.Group != "" && !slices.Contains(e.groups, f.Group):
	case f.IP != "" && e.ip != f.IP:
	case f.Location != "" && !slices.Contains(e.locations, f.Location):
	case e.score < f.MinScore:
	default:
		return true
	}
	return false
}

// row is one line of the alerts list.
type row struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Alert      bool      `json:"alert"`
	Score      int       `json:"score"`
	IP         string    `json:"ip,omitempty"`
	Method     string    `json:"method"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Rules      []int     `json:"rules"`
	Groups     []string  `json:"groups"`
	Locations  []string  `json:"locations"`
	Incomplete bool      `json:"incomplete"`
	// Application, ProfileKinds and AlertBy are left out for a record of
	// a run without applications.
	Application  string   `json:"application,omitempty"`
	ProfileKinds []string `json:"profile_kinds,omitempty"`
	AlertBy      []string `json:"alert_by,omitempty"`
	// Verdict is the record's mark (G1), "not_reviewed" without one.
	Verdict string `json:"verdict"`
}

type list struct {
	Total int   `json:"total"`
	Page  int   `json:"page"`
	Pages int   `json:"pages"`
	Rows  []row `json:"rows"`
	// Applications are the names the filter can choose: those of the
	// records and of the newest run, sorted, and "none" last when some
	// request belonged to no application. Empty without applications.
	Applications []string `json:"applications"`
}

const pageSize = 50

func (s *store) list(f filter) list {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []*entry
	for _, e := range s.entries {
		if f.match(e) && s.reviewMatches(f, e) {
			matched = append(matched, e)
		}
	}
	// Newest first, or the highest score first and then the newest;
	// records of the same moment in the order written.
	sort.SliceStable(matched, func(i, j int) bool {
		if f.Sort == "score" && matched[i].score != matched[j].score {
			return matched[i].score > matched[j].score
		}
		return matched[i].time.After(matched[j].time)
	})
	l := list{Total: len(matched), Page: f.Page, Pages: max(1, (len(matched)+pageSize-1)/pageSize), Rows: []row{}}
	start := (f.Page - 1) * pageSize
	for i := start; i < len(matched) && i < start+pageSize; i++ {
		e := matched[i]
		l.Rows = append(l.Rows, row{
			ID: e.id, Time: e.time, Alert: e.alert, Score: e.score, IP: e.ip, Method: e.method, Host: e.host,
			Path: e.path, UserAgent: e.userAgent, Rules: nonNil(e.rules), Groups: nonNil(e.groups),
			Locations: nonNil(e.locations), Incomplete: e.incomplete,
			Application: e.app, ProfileKinds: e.profileKinds, AlertBy: e.alertBy,
			Verdict: s.marks.verdict(e.id),
		})
	}
	l.Applications = s.appNames()
	return l
}

// appNames returns the application names of the records and of the newest
// run, sorted, with "none" last when some request belonged to none. It is
// empty when nothing has an application. The caller holds s.mu.
func (s *store) appNames() []string {
	seen := map[string]bool{}
	none := false
	for _, e := range s.entries {
		switch e.app {
		case "", profile.NoApplication:
			none = true
		default:
			seen[e.app] = true
		}
	}
	if st, ok := s.latestRun(); ok {
		for _, a := range st.Applications {
			seen[a.Name] = true
		}
	}
	names := []string{}
	if len(seen) == 0 {
		return names
	}
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	if none {
		names = append(names, profile.NoApplication)
	}
	return names
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ruleRow is one rule of the rules page.
type ruleRow struct {
	record.Rule
	Group string `json:"group"`
	Fired int    `json:"fired"`
	// FalsePositives counts the records of the period with this rule that
	// are marked false positive, also those that rotated away (G6).
	FalsePositives int `json:"false_positives"`

	// NotFor is true when the rule is an own rule for other applications
	// than the chosen one, so it does not run for it.
	NotFor bool `json:"not_for,omitempty"`

	// Off and Skips are the chosen application's exception for the rule:
	// the rule does not run for it, or does not look at these variables.
	// ExceptionReason is the exception's reason, and NoEffect says why it
	// changes nothing at the moment, when it does not.
	Off             bool     `json:"off,omitempty"`
	Skips           []string `json:"skips,omitempty"`
	ExceptionReason string   `json:"exception_reason,omitempty"`
	NoEffect        string   `json:"no_effect,omitempty"`
}

type rulesPage struct {
	Range  timeRange     `json:"range"`
	Run    string        `json:"run,omitempty"`
	Time   time.Time     `json:"time,omitzero"`
	Engine record.Engine `json:"engine"`
	Rules  []ruleRow     `json:"rules"`

	// Applications are those of the run. App is the chosen one, or "none"
	// for requests of no application; empty when none was chosen. Level
	// is the paranoia level the statuses are for: the application's, or
	// the run's.
	Applications []result.AppStartup `json:"applications,omitempty"`
	App          string              `json:"app,omitempty"`
	Level        int                 `json:"level"`
}

// newestConfig returns the configuration fingerprint of the newest run,
// or "" when there is no run: the test tab says whether it tests the same
// rules (S2).
func (s *store) newestConfig() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.latestRun()
	if !ok {
		return ""
	}
	return st.Engine.Config
}

// latestRun returns the run that started last. A replay's start record
// carries the time of its first request; it started when it was replayed.
func (s *store) latestRun() (record.Start, bool) {
	var latest record.Start
	found := false
	for _, run := range s.runs {
		st := s.starts[run]
		if !found || started(st).After(started(latest)) {
			latest, found = st, true
		}
	}
	return latest, found
}

// started is when a run started: when it was replayed, for a replay.
func started(st record.Start) time.Time {
	if st.Input != nil && st.Input.Kind == record.InputReplay && !st.Input.Replayed.IsZero() {
		return st.Input.Replayed
	}
	return st.Time
}

// rulesPage lists the rules of the newest run with how often each fired in
// r. With app, the statuses are those of that application (F9, F11): its
// level, and its exceptions; and only its records are counted.
func (s *store) rulesPage(r timeRange, app string) (rulesPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := rulesPage{Range: r, Rules: []ruleRow{}, App: app}
	st, ok := s.latestRun()
	var chosen *result.AppStartup
	if ok {
		p.Applications, p.Level = st.Applications, st.Engine.ParanoiaLevel
		for i := range st.Applications {
			if st.Applications[i].Name == app {
				chosen = &st.Applications[i]
				p.Level = chosen.ParanoiaLevel
			}
		}
	}
	if app != "" && app != profile.NoApplication && chosen == nil {
		return p, fmt.Errorf("app %q is not an application of the newest run", app)
	}
	fired := map[int]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) || app != "" && !sameApp(e.app, app) {
			continue
		}
		for _, id := range e.rules {
			fired[id]++
		}
	}
	falsePositives := map[int]int{}
	s.marks.each(func(l markLine) {
		if l.Verdict != verdictFalsePositive || !r.contains(l.Alert.Time) || app != "" && !sameApp(l.Alert.Application, app) {
			return
		}
		for _, id := range l.Alert.Rules {
			falsePositives[id]++
		}
	})
	if !ok {
		return p, nil
	}
	p.Run, p.Time, p.Engine = st.Run, st.Time, st.Engine
	exceptions := map[int]profile.ExceptionStatus{}
	if chosen != nil {
		for _, ex := range chosen.Exceptions {
			if ex.Rule != 0 {
				exceptions[ex.Rule] = ex
			}
		}
	}
	for _, rule := range s.rules[st.Run] {
		row := ruleRow{Rule: rule, Group: ruleGroup(rule), Fired: fired[rule.ID], FalsePositives: falsePositives[rule.ID]}
		row.NotFor = app != "" && !forApp(rule, app)
		if ex, ok := exceptions[rule.ID]; ok {
			row.Off, row.Skips, row.ExceptionReason, row.NoEffect = ex.Off, ex.Skip, ex.Reason, ex.NoEffect
		}
		p.Rules = append(p.Rules, row)
	}
	return p, nil
}

type runRow struct {
	Run    string        `json:"run"`
	Time   time.Time     `json:"time"`
	Engine record.Engine `json:"engine"`
	// Input is where the run's requests came from; nil for request files.
	Input *record.Input `json:"input,omitempty"`
	// What the run did: requests analysed (from its counts records), and
	// the request records and alerts that are still kept.
	Analysed int `json:"analysed"`
	Records  int `json:"records"`
	Alerts   int `json:"alerts"`
}

type fileRow struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

type enginePage struct {
	Latest   *runRow `json:"latest,omitempty"`
	Active   int     `json:"active_rules"`
	Excluded int     `json:"excluded_rules"`
	// AboveLevel counts the active rules of a paranoia level above the
	// run's: they are loaded, and the CRS gate rules skip them.
	AboveLevel int       `json:"above_level_rules"`
	Runs       []runRow  `json:"runs"`
	Files      []fileRow `json:"files"`
	// Applications and RequireProfile are those of the newest run.
	Applications   []result.AppStartup `json:"applications"`
	RequireProfile bool                `json:"require_profile"`
	Records        int                 `json:"records"`
	Oldest         time.Time           `json:"oldest_record,omitzero"`
	Newest         time.Time           `json:"newest_record,omitzero"`
	Unreadable     int                 `json:"unreadable_lines"`
	// Skipped counts lines of record types this dashboard does not know.
	Skipped int `json:"skipped_lines"`
	// Marks counts the marked records, also those that rotated away, whose
	// marks keep a client address (C6); MarksUnreadable the lines of the
	// marks file that could not be read.
	Marks           int `json:"marks"`
	MarksUnreadable int `json:"marks_unreadable"`

	// Live is the state of the newest run when its input is live (W17),
	// and NotAnalysed, by source and reason, what the live input did not
	// analyse in the last hour.
	Live          *liveStatus   `json:"live,omitempty"`
	NotAnalysed   int64         `json:"not_analysed_last_hour"`
	NotAnalysedBy []missedCount `json:"not_analysed_by"`
}

func (s *store) enginePage() enginePage {
	return s.enginePageAt(time.Now())
}

// enginePageAt is the Engine page at now, which decides whether ids-live
// still writes.
func (s *store) enginePageAt(now time.Time) enginePage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := enginePage{Runs: []runRow{}, Files: []fileRow{}, Applications: []result.AppStartup{}, Records: len(s.entries), Unreadable: s.broken, Skipped: s.skipped}
	if s.marks != nil {
		p.Marks, p.MarksUnreadable = s.marks.count()
	}
	type done struct{ analysed, records, alerts int }
	byRun := map[string]*done{}
	for _, run := range s.runs {
		byRun[run] = &done{}
	}
	for _, c := range s.counts {
		if d := byRun[c.Run]; d != nil {
			d.analysed += c.Analysed
		}
	}
	for _, e := range s.entries {
		if d := byRun[e.run]; d != nil {
			d.records++
			if e.alert {
				d.alerts++
			}
		}
	}
	for i := len(s.runs) - 1; i >= 0; i-- {
		st := s.starts[s.runs[i]]
		d := byRun[st.Run]
		p.Runs = append(p.Runs, runRow{Run: st.Run, Time: st.Time, Engine: st.Engine, Input: st.Input, Analysed: d.analysed, Records: d.records, Alerts: d.alerts})
	}
	sort.SliceStable(p.Runs, func(i, j int) bool { return started(s.starts[p.Runs[i].Run]).After(started(s.starts[p.Runs[j].Run])) })
	if st, ok := s.latestRun(); ok {
		p.Latest = &runRow{Run: st.Run, Time: st.Time, Engine: st.Engine, Input: st.Input}
		if st.Applications != nil {
			p.Applications = st.Applications
		}
		p.RequireProfile = st.RequireProfile
		for _, rule := range s.rules[st.Run] {
			switch {
			case !rule.Active:
				p.Excluded++
			case rule.ParanoiaLevel > st.Engine.ParanoiaLevel:
				p.Active++
				p.AboveLevel++
			default:
				p.Active++
			}
		}
	}
	for _, f := range s.files {
		if info, err := os.Stat(filepath.Join(s.dir, f.name)); err == nil {
			p.Files = append(p.Files, fileRow{Name: f.name, Size: info.Size(), Modified: info.ModTime().UTC()})
		}
	}
	for _, e := range s.entries {
		if p.Oldest.IsZero() || e.time.Before(p.Oldest) {
			p.Oldest = e.time
		}
		if e.time.After(p.Newest) {
			p.Newest = e.time
		}
	}
	var o overview
	s.liveParts(&o, timeRange{Name: "1h", From: now.UTC().Add(-time.Hour), To: now.UTC()})
	p.Live, p.NotAnalysed, p.NotAnalysedBy = o.Live, o.NotAnalysed, o.NotAnalysedBy
	return p
}
