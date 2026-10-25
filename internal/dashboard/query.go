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

	"github.com/EfeSipahi/ids-system/internal/record"
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
	Series     []bucket  `json:"series"`
	BucketSecs int       `json:"bucket_seconds"`
	Rules      []item    `json:"top_rules"`
	Groups     []item    `json:"top_groups"`
	Locations  []item    `json:"top_locations"`
	IPs        []item    `json:"top_ips"`
	LastRecord time.Time `json:"last_record,omitzero"`
	LastAlert  time.Time `json:"last_alert,omitzero"`
}

const (
	topSize = 10
	buckets = 48
)

func (s *store) overview(r timeRange) overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := overview{Range: r}

	// With "all", the chart starts at the first thing recorded.
	from := r.From
	if from.IsZero() {
		from = r.To
		for _, e := range s.entries {
			if e.time.Before(from) {
				from = e.time
			}
		}
		for _, c := range s.counts {
			if c.From.Before(from) {
				from = c.From
			}
		}
	}
	width := bucketWidth(r.To.Sub(from))
	from = from.Truncate(width)
	o.BucketSecs = int(width / time.Second)
	n := int(r.To.Sub(from)/width) + 1
	o.Series = make([]bucket, n)
	for i := range o.Series {
		o.Series[i].Start = from.Add(time.Duration(i) * width)
	}
	slot := func(t time.Time) *bucket {
		i := int(t.Sub(from) / width)
		if i < 0 || i >= n {
			return nil
		}
		return &o.Series[i]
	}

	// A counts record belongs to the period when its end is in it.
	for _, c := range s.counts {
		if r.contains(c.To) && c.To.After(r.From) {
			o.Analysed += c.Analysed
			if b := slot(c.To); b != nil {
				b.Analysed += c.Analysed
			}
		}
	}
	rules, groupCounts, locations, ips := map[int]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) {
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
	return o
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
	MinScore int
	Sort     string // "time" (newest first) or "score" (highest first)
	Page     int
}

func parseFilter(q url.Values, now time.Time) (filter, error) {
	r, err := parsePeriod(q, now)
	if err != nil {
		return filter{}, err
	}
	f := filter{Range: r, Kind: q.Get("kind"), Group: q.Get("group"), IP: strings.TrimSpace(q.Get("ip")), Location: strings.TrimSpace(q.Get("location")), Sort: q.Get("sort"), Page: 1}
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

func (f filter) match(e *entry) bool {
	switch {
	case !f.Range.contains(e.time):
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
}

type list struct {
	Total int   `json:"total"`
	Page  int   `json:"page"`
	Pages int   `json:"pages"`
	Rows  []row `json:"rows"`
}

const pageSize = 50

func (s *store) list(f filter) list {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []*entry
	for _, e := range s.entries {
		if f.match(e) {
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
		})
	}
	return l
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
}

type rulesPage struct {
	Range  timeRange     `json:"range"`
	Run    string        `json:"run,omitempty"`
	Time   time.Time     `json:"time,omitzero"`
	Engine record.Engine `json:"engine"`
	Rules  []ruleRow     `json:"rules"`
}

// latestRun returns the run whose start record is the newest.
func (s *store) latestRun() (record.Start, bool) {
	var latest record.Start
	found := false
	for _, run := range s.runs {
		st := s.starts[run]
		if !found || st.Time.After(latest.Time) {
			latest, found = st, true
		}
	}
	return latest, found
}

func (s *store) rulesPage(r timeRange) rulesPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := rulesPage{Range: r, Rules: []ruleRow{}}
	fired := map[int]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) {
			continue
		}
		for _, id := range e.rules {
			fired[id]++
		}
	}
	st, ok := s.latestRun()
	if !ok {
		return p
	}
	p.Run, p.Time, p.Engine = st.Run, st.Time, st.Engine
	for _, rule := range s.rules[st.Run] {
		p.Rules = append(p.Rules, ruleRow{Rule: rule, Group: fileGroup(rule.File), Fired: fired[rule.ID]})
	}
	return p
}

type runRow struct {
	Run    string        `json:"run"`
	Time   time.Time     `json:"time"`
	Engine record.Engine `json:"engine"`
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
	Records    int       `json:"records"`
	Oldest     time.Time `json:"oldest_record,omitzero"`
	Newest     time.Time `json:"newest_record,omitzero"`
	Unreadable int       `json:"unreadable_lines"`
}

func (s *store) enginePage() enginePage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := enginePage{Runs: []runRow{}, Files: []fileRow{}, Records: len(s.entries), Unreadable: s.broken}
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
		p.Runs = append(p.Runs, runRow{Run: st.Run, Time: st.Time, Engine: st.Engine, Analysed: d.analysed, Records: d.records, Alerts: d.alerts})
	}
	sort.SliceStable(p.Runs, func(i, j int) bool { return p.Runs[i].Time.After(p.Runs[j].Time) })
	if st, ok := s.latestRun(); ok {
		p.Latest = &runRow{Run: st.Run, Time: st.Time, Engine: st.Engine}
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
	return p
}
