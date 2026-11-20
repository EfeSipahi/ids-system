package dashboard

// Marks: a person's verdict on an alert (G1, G2, G6 of
// docs/development-plan-marks-users.md). They live in the dashboard's
// state folder, never in the record files, which stay as the IDS wrote
// them (C1).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"
	"unicode/utf8"
)

// MarksFile holds the marks: one JSON line per marked record per action.
// A record's newest line is its mark; the older ones are its history.
const MarksFile = "marks.jsonl"

// The verdicts (G1). A record without a mark is not reviewed; marking it
// "not_reviewed" takes a mistaken verdict back.
const (
	verdictNotReviewed   = "not_reviewed"
	verdictRealAttack    = "real_attack"
	verdictExpected      = "expected"
	verdictFalsePositive = "false_positive"
	verdictUndetermined  = "undetermined"
)

var verdicts = []string{verdictNotReviewed, verdictRealAttack, verdictExpected, verdictFalsePositive, verdictUndetermined}

const (
	// maxMarkRecords is the most records one action marks (C7).
	maxMarkRecords = 10_000
	// maxNote is the longest note, in characters.
	maxNote = 1000
	// maxMarkBody is the largest body of a mark: 10,000 record IDs fit.
	maxMarkBody = 1 << 20
)

// markAlert is the short summary of an alert that a mark keeps, so that
// counts per rule survive the records' rotation (G6, C6).
type markAlert struct {
	Time        time.Time `json:"time"`
	Alert       bool      `json:"alert"`
	Score       int       `json:"score"`
	Rules       []int     `json:"rules"`
	Path        string    `json:"path"`
	Application string    `json:"application,omitempty"`
	Client      string    `json:"client,omitempty"`
}

// markLine is one line of the marks file.
type markLine struct {
	Record  string    `json:"record"`
	Verdict string    `json:"verdict"`
	Note    string    `json:"note,omitempty"`
	User    string    `json:"user"`
	Time    time.Time `json:"time"`
	// Change is the change log entry of the action (G5).
	Change string    `json:"change"`
	Alert  markAlert `json:"alert"`
}

// marks keeps every mark in memory; the dashboard is the only writer of
// the file (C4), so it reads the file once, at the start.
type marks struct {
	path string

	mu       sync.RWMutex
	byRecord map[string][]markLine // oldest first
	lines    int
	broken   int // lines that could not be read
}

func openMarks(path string) (*marks, error) {
	m := &marks{path: path, byRecord: map[string][]markLine{}}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var l markLine
		if json.Unmarshal(sc.Bytes(), &l) != nil || l.Record == "" || !slices.Contains(verdicts, l.Verdict) {
			m.broken++
			continue
		}
		m.byRecord[l.Record] = append(m.byRecord[l.Record], l)
		m.lines++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// verdict returns a record's verdict: not reviewed when it has no mark.
func (m *marks) verdict(id string) string {
	if m == nil {
		return verdictNotReviewed
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := m.byRecord[id]
	if len(list) == 0 {
		return verdictNotReviewed
	}
	return list[len(list)-1].Verdict
}

// history returns a record's marks, oldest first.
func (m *marks) history(id string) []markLine {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.byRecord[id])
}

// each calls f with the newest mark of every marked record, also of
// records that rotated away.
func (m *marks) each(f func(markLine)) {
	if m == nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, list := range m.byRecord {
		f(list[len(list)-1])
	}
}

// count returns how many records have a mark, and how many lines of the
// file could not be read.
func (m *marks) count() (records, broken int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byRecord), m.broken
}

// add appends lines to the file with one write, and keeps them.
func (m *marks) add(lines []markLine) error {
	var buf bytes.Buffer
	for _, l := range lines {
		data, err := json.Marshal(l)
		if err != nil {
			return err
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.OpenFile(m.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(buf.Bytes())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for _, l := range lines {
		m.byRecord[l.Record] = append(m.byRecord[l.Record], l)
		m.lines++
	}
	return nil
}

// markRequest is what the alerts list and the detail page post (G2):
// record IDs, or the list's filter as an address query.
type markRequest struct {
	Verdict string   `json:"verdict"`
	Note    string   `json:"note"`
	IDs     []string `json:"ids,omitempty"`
	Filter  *string  `json:"filter,omitempty"`
}

// toMark returns the summaries of the records a mark request names. The
// caller must not hold s.mu.
func (s *store) toMark(mr markRequest, now time.Time) (map[string]markAlert, string, error) {
	targets := map[string]markAlert{}
	summary := func(e *entry) markAlert {
		return markAlert{Time: e.time, Alert: e.alert, Score: e.score, Rules: slices.Clone(e.rules), Path: e.path, Application: e.app, Client: e.ip}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if mr.Filter != nil {
		q, err := url.ParseQuery(*mr.Filter)
		if err != nil {
			return nil, "", fmt.Errorf("filter: %v", err)
		}
		q.Del("page")
		q.Del("sort")
		f, err := parseFilter(q, now)
		if err != nil {
			return nil, "", fmt.Errorf("filter: %v", err)
		}
		for _, e := range s.entries {
			if f.match(e) && s.reviewMatches(f, e) {
				targets[e.id] = summary(e)
			}
		}
		if len(targets) > maxMarkRecords {
			return nil, "", fmt.Errorf("%d records match; at most %d can be marked at once: narrow the filter", len(targets), maxMarkRecords)
		}
		return targets, q.Encode(), nil
	}
	if len(mr.IDs) > maxMarkRecords {
		return nil, "", fmt.Errorf("%d records; at most %d can be marked at once", len(mr.IDs), maxMarkRecords)
	}
	for _, id := range mr.IDs {
		e := s.byID[id]
		if e == nil {
			return nil, "", fmt.Errorf("there is no record %q: it may have rotated away", id)
		}
		targets[id] = summary(e)
	}
	return targets, "", nil
}

// reviewMatches applies the filter's review choice to a record. The
// caller holds s.mu.
func (s *store) reviewMatches(f filter, e *entry) bool {
	return f.Review == "" || s.marks.verdict(e.id) == f.Review
}

// apiMark marks records (G1, G2), as one action of the change log (G5).
func (s *Server) apiMark(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	var mr markRequest
	if err := readJSON(w, r, maxMarkBody, &mr); err != nil {
		badRequest(w, err)
		return
	}
	switch {
	case !slices.Contains(verdicts, mr.Verdict):
		badRequest(w, fmt.Errorf("verdict %q: give not_reviewed, real_attack, expected, false_positive or undetermined", mr.Verdict))
		return
	case utf8.RuneCountInString(mr.Note) > maxNote || !utf8.ValidString(mr.Note):
		badRequest(w, fmt.Errorf("the note is not text of at most %d characters", maxNote))
		return
	case (mr.Filter == nil) == (len(mr.IDs) == 0):
		badRequest(w, errors.New("give either the records or the list's filter"))
		return
	}
	targets, filter, err := s.store.toMark(mr, s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	if len(targets) == 0 {
		badRequest(w, errors.New("no record matches"))
		return
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	c := change{Time: s.now(), User: user, Action: actionMark, Verdict: mr.Verdict, Note: mr.Note, Records: len(ids), Filter: filter, Before: map[string]int{}}
	if mr.Filter == nil {
		c.IDs = ids
	}
	for _, id := range ids {
		c.Before[s.marks.verdict(id)]++
	}
	// The log first: a mark is never without its entry (G5).
	c, err = s.changes.add(c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the change log can't be written, so nothing was marked: " + err.Error()})
		return
	}
	lines := make([]markLine, 0, len(ids))
	for _, id := range ids {
		lines = append(lines, markLine{Record: id, Verdict: mr.Verdict, Note: mr.Note, User: user, Time: c.Time, Change: c.ID, Alert: targets[id]})
	}
	if err := s.marks.add(lines); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the marks can't be written: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"marked": len(ids), "change": c.ID})
}

// apiMarkHistory gives a record's marks, oldest first, to every role (G5).
func (s *Server) apiMarkHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	history := s.marks.history(id)
	answer := map[string]any{"verdict": verdictNotReviewed, "history": []markLine{}}
	if len(history) > 0 {
		answer["verdict"] = history[len(history)-1].Verdict
		answer["history"] = history
	}
	writeJSON(w, http.StatusOK, answer)
}
