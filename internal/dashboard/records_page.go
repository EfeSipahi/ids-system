package dashboard

// System › Records (W19 of docs/development-plan-dashboard-control.md): the
// record files and runs, the filtered records exported, a run or the
// records older than a date deleted, and how long records and marks are
// kept.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
)

// Actions of the change log for records and marks.
const (
	actionRecordsDeleted = "records_deleted"
	actionMarksPruned    = "marks_pruned"
)

// recordsPageRun is a run of the Records page.
type recordsPageRun struct {
	Run     string    `json:"run"`
	Started time.Time `json:"started"`
	Kind    string    `json:"kind"`
	Records int       `json:"records"`
	Alerts  int       `json:"alerts"`
	Oldest  time.Time `json:"oldest,omitzero"`
	Newest  time.Time `json:"newest,omitzero"`
}

// recordsPage is the Records page.
type recordsPage struct {
	Dir   string           `json:"dir"`
	Files []fileRow        `json:"files"`
	Runs  []recordsPageRun `json:"runs"`
	// Busy is true while ids-live seems to run, from its counts: nothing
	// can be deleted then. The page does not take the folder's lock to
	// find out, as a program starting at that moment would fail.
	Busy bool `json:"busy"`
	// Settings are the records settings of the IDS's configuration, when
	// the dashboard knows it.
	Settings        *record.Config `json:"settings,omitempty"`
	MarksMaxAgeDays int            `json:"marks_max_age_days"`
	Marks           int            `json:"marks"`
}

func (s *Server) apiRecordsPage(w http.ResponseWriter, r *http.Request) {
	p := recordsPage{Dir: s.cfg.RecordsDir, Files: []fileRow{}, Runs: []recordsPageRun{}, MarksMaxAgeDays: s.cfg.MarksMaxAgeDays}
	e := s.store.enginePageAt(s.now())
	p.Files = e.Files
	p.Busy = e.Live != nil && !e.Live.Stale
	p.Marks, _ = s.marks.count()
	byRun := map[string]*recordsPageRun{}
	for _, run := range e.Runs {
		kind := "files"
		if run.Input != nil {
			kind = run.Input.Kind
		}
		rr := recordsPageRun{Run: run.Run, Started: run.Time, Kind: kind, Records: run.Records, Alerts: run.Alerts}
		if run.Input != nil && run.Input.Kind == record.InputReplay {
			rr.Started = run.Input.Replayed
		}
		p.Runs = append(p.Runs, rr)
	}
	for i := range p.Runs {
		byRun[p.Runs[i].Run] = &p.Runs[i]
	}
	s.store.mu.RLock()
	for _, en := range s.store.entries {
		if rr := byRun[en.run]; rr != nil {
			if rr.Oldest.IsZero() || en.time.Before(rr.Oldest) {
				rr.Oldest = en.time
			}
			if en.time.After(rr.Newest) {
				rr.Newest = en.time
			}
		}
	}
	s.store.mu.RUnlock()
	if s.control.path != "" {
		if raw, err := s.control.readRaw(); err == nil && raw.Records != nil {
			rc := raw.Records.WithDefaults()
			p.Settings = &rc
		}
	}
	writeJSON(w, http.StatusOK, p)
}

// deleteRequest is a deletion of records.
type deleteRequest struct {
	// Run is a run to delete; Before deletes every record, counts and gap
	// record older than the time.
	Run      string    `json:"run,omitempty"`
	Before   time.Time `json:"before,omitzero"`
	Reason   string    `json:"reason"`
	Password string    `json:"password"`
}

func (s *Server) apiRecordsDelete(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	var dr deleteRequest
	if err := readJSON(w, r, 8<<10, &dr); err != nil {
		badRequest(w, err)
		return
	}
	dr.Reason = strings.TrimSpace(dr.Reason)
	switch {
	case (dr.Run == "") == dr.Before.IsZero():
		badRequest(w, errors.New("give either the run or the date"))
		return
	case dr.Reason == "":
		badRequest(w, errors.New("give a reason: the change log keeps it"))
		return
	}
	if !s.confirm(w, r, user, dr.Password) {
		return
	}
	drop := func(l record.Line) bool {
		if dr.Run != "" {
			return l.Run == dr.Run
		}
		return l.Type != record.TypeStart && l.Time.Before(dr.Before)
	}
	n, err := record.Rewrite(s.cfg.RecordsDir, drop)
	if errors.Is(err, record.ErrInUse) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a program writes the records folder now, such as ids-live; stop it first (scripts/ids-live-ctl stop), then delete"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	what := "the run " + dr.Run
	if dr.Run == "" {
		what = "everything older than " + dr.Before.UTC().Format(time.RFC3339)
	}
	s.logChange(change{User: user, Action: actionRecordsDeleted, What: []string{what}, Records: n, Reason: dr.Reason})
	if err := s.store.refresh(); err != nil {
		s.log.Printf("reading records: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]int{"lines": n})
}

// apiExport writes the records the alerts list's filters choose, as CSV
// or as JSON Lines (W19).
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format != "csv" && format != "jsonl" {
		badRequest(w, errors.New("format is csv or jsonl"))
		return
	}
	f, err := parseFilter(q, s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	f.Page = 1
	ids := s.store.matchingIDs(f)
	name := "records-" + s.now().UTC().Format("20060102T150405Z")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "time", "alert", "score", "client", "method", "host", "path", "application", "rules", "groups", "locations", "incomplete", "review"})
		for _, row := range s.store.rows(ids) {
			cw.Write([]string{row.ID, row.Time.UTC().Format(time.RFC3339Nano), strconv.FormatBool(row.Alert), strconv.Itoa(row.Score), row.IP, row.Method, row.Host, row.Path,
				row.Application, joinInts(row.Rules), strings.Join(row.Groups, " "), strings.Join(row.Locations, " "), strconv.FormatBool(row.Incomplete), s.marks.verdict(row.ID)})
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.jsonl"`)
	for _, id := range ids {
		line, err := s.store.load(id)
		if err != nil {
			continue
		}
		var rec any
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		var b bytes.Buffer
		json.NewEncoder(&b).Encode(rec)
		w.Write(b.Bytes())
	}
}

func joinInts(list []int) string {
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, " ")
}

// matchingIDs returns the IDs of every record the filter chooses, newest
// first, as the alerts list orders them.
func (s *store) matchingIDs(f filter) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []*entry
	for _, e := range s.entries {
		if f.match(e) && s.reviewMatches(f, e) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if f.Sort == "score" && matched[i].score != matched[j].score {
			return matched[i].score > matched[j].score
		}
		return matched[i].time.After(matched[j].time)
	})
	ids := make([]string, len(matched))
	for i, e := range matched {
		ids[i] = e.id
	}
	return ids
}

// rows returns the list rows of the given records.
func (s *store) rows(ids []string) []row {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]row, 0, len(ids))
	for _, id := range ids {
		e := s.byID[id]
		if e == nil {
			continue
		}
		out = append(out, row{ID: e.id, Time: e.time, Alert: e.alert, Score: e.score, IP: e.ip, Method: e.method, Host: e.host, Path: e.path,
			Rules: nonNil(e.rules), Groups: nonNil(e.groups), Locations: nonNil(e.locations), Incomplete: e.incomplete, Application: e.app})
	}
	return out
}

// prune drops the marks of alerts older than maxAge, by writing the file
// again with the others (W19, C6 of the marks plan). It returns how many
// lines went.
func (m *marks) prune(before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep bytes.Buffer
	dropped := 0
	kept := map[string][]markLine{}
	lines := 0
	ids := make([]string, 0, len(m.byRecord))
	for id := range m.byRecord {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var all []markLine
	for _, id := range ids {
		for _, l := range m.byRecord[id] {
			if l.Alert.Time.Before(before) {
				dropped++
				continue
			}
			all = append(all, l)
		}
	}
	if dropped == 0 {
		return 0, nil
	}
	// The file keeps the order the marks were made in.
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	for _, l := range all {
		data, err := json.Marshal(l)
		if err != nil {
			return 0, err
		}
		keep.Write(data)
		keep.WriteByte('\n')
		kept[l.Record] = append(kept[l.Record], l)
		lines++
	}
	if err := writeFileAtomic(m.path, keep.Bytes(), 0o600); err != nil {
		return 0, err
	}
	m.byRecord, m.lines = kept, lines
	return dropped, nil
}

// pruneMarks applies the marks' maximum age, once a day (W19).
func (s *Server) pruneMarks() {
	if s.cfg.MarksMaxAgeDays <= 0 {
		return
	}
	if s.now().Sub(s.marksPruned) < 24*time.Hour {
		return
	}
	s.marksPruned = s.now()
	n, err := s.marks.prune(s.now().Add(-time.Duration(s.cfg.MarksMaxAgeDays) * 24 * time.Hour))
	if err != nil {
		s.log.Printf("marks: %v", err)
		return
	}
	if n > 0 {
		s.logChange(change{User: "dashboard", Action: actionMarksPruned, Records: n, Reason: fmt.Sprintf("marks of alerts older than %d days", s.cfg.MarksMaxAgeDays)})
	}
}
