package dashboard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// store keeps a small index of the record files in memory and reads whole
// records from disk when one is asked for. The dashboard only reads: it
// never changes a record file (V2).
type store struct {
	dir string

	mu      sync.RWMutex
	files   []*recordFile // oldest first; the current file is last
	entries []*entry      // in the order read
	byID    map[string]*entry
	starts  map[string]record.Start // by run, without the rule list
	runs    []string                // runs in the order first seen
	rules   map[string][]record.Rule
	counts  []countsEntry
	gaps    []gapEntry
	broken  int // lines that could not be read
	// skipped counts lines of a record type this dashboard does not know,
	// which readers skip (docs/records-format.md, section 2).
	skipped int

	// marks are the verdicts people gave (G1); they live in the state
	// folder, not in the records. Lock order: s.mu before the marks' own.
	marks *marks
}

// recordFile is one file and how far it has been read.
type recordFile struct {
	name   string
	info   os.FileInfo
	offset int64 // the first byte not read yet
}

// entry is what the lists, filters and counts need of one request record.
type entry struct {
	id         string
	run        string
	time       time.Time
	alert      bool
	score      int
	ip         string
	method     string
	path       string
	host       string
	userAgent  string
	rules      []int
	groups     []string
	locations  []string
	incomplete bool
	// app is the record's application, "none" for a request of no
	// application, or "" for a record of a run without applications.
	// profileKinds are the kinds of its profile findings, each once, and
	// alertBy what made it an alert.
	app          string
	profileKinds []string
	alertBy      []string
	// findings are the record's findings, for a rule's page and for the
	// preview of a change (W8), which works the score out again from
	// them. threshold is the score at which the rules make an alert, and
	// profiled is true when the profile found something.
	findings  []entryFinding
	threshold int
	profiled  bool
	// profFindings are the profile's findings, for the suggestions of an
	// application's Profile tab (W15).
	profFindings []profFinding

	file   *recordFile
	offset int64
	length int
}

// profFinding is a finding of the profile: its kind and where.
type profFinding struct {
	kind     string
	location string
}

// entryFinding is one finding of a record: a rule, where it matched, and
// what it added to the score.
type entryFinding struct {
	rule     int
	location string
	weight   int
}

// severityWeights are what a finding of each severity adds to the anomaly
// score, at CRS's defaults (crs-setup.conf: critical 5, error 4, warning 3,
// notice 2). The score of every record kept on 21 November 2026 was the
// sum of its findings' weights.
var severityWeights = map[string]int{"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}

type countsEntry struct {
	record.Counts
	file *recordFile
}

// gapEntry is a gap record: requests of the live input that were not
// analysed (T7, T8).
type gapEntry struct {
	record.Gap
	file *recordFile
}

func newStore(dir string) *store {
	return &store{dir: dir, byID: map[string]*entry{}, starts: map[string]record.Start{}, rules: map[string][]record.Rule{}}
}

// refresh reads what was added to the files since the last call. It
// notices when the current file was renamed by rotation, and forgets the
// records of files that were deleted.
func (s *store) refresh() error {
	rotated, err := record.RotatedFiles(s.dir)
	if err != nil {
		return err
	}
	names := append(rotated, record.CurrentFile)
	infos := map[string]os.FileInfo{}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(s.dir, name))
		if err == nil {
			infos[name] = info
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A known file may now have another name: the current file becomes a
	// rotated one. The same file on disk keeps its read position.
	var kept []*recordFile
	for _, f := range s.files {
		found := ""
		for name, info := range infos {
			if os.SameFile(f.info, info) {
				found = name
				break
			}
		}
		if found == "" {
			s.forget(f)
			continue
		}
		f.name = found
		f.info = infos[found]
		kept = append(kept, f)
	}
	s.files = kept

	for _, name := range names {
		info, ok := infos[name]
		if !ok {
			continue
		}
		f := s.file(name)
		if f == nil {
			f = &recordFile{name: name, info: info}
			s.files = append(s.files, f)
		}
		if err := s.read(f); err != nil {
			return err
		}
	}
	sort.SliceStable(s.files, func(i, j int) bool { return fileOrder(s.files[i].name) < fileOrder(s.files[j].name) })
	return nil
}

// fileOrder sorts rotated files by name, which holds their time, and the
// current file last.
func fileOrder(name string) string {
	if name == record.CurrentFile {
		return "\xff"
	}
	return name
}

func (s *store) file(name string) *recordFile {
	for _, f := range s.files {
		if f.name == name {
			return f
		}
	}
	return nil
}

// forget drops the records of a file that no longer exists.
func (s *store) forget(f *recordFile) {
	entries := s.entries[:0]
	for _, e := range s.entries {
		if e.file == f {
			delete(s.byID, e.id)
			continue
		}
		entries = append(entries, e)
	}
	s.entries = entries
	counts := s.counts[:0]
	for _, c := range s.counts {
		if c.file != f {
			counts = append(counts, c)
		}
	}
	s.counts = counts
	gaps := s.gaps[:0]
	for _, g := range s.gaps {
		if g.file != f {
			gaps = append(gaps, g)
		}
	}
	s.gaps = gaps
}

// maxLine is the longest line that is read. The writer's limits keep a
// record far below it, even with full_requests.
const maxLine = 4 << 20

// read reads the complete lines after f.offset. A last line without its
// newline is still being written; it is read on a later call.
func (s *store) read(f *recordFile) error {
	file, err := os.Open(filepath.Join(s.dir, f.name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()
	if info, err := file.Stat(); err == nil && info.Size() < f.offset {
		// The file is shorter than what was read: it is not the same
		// file any more. Read it again from the start.
		s.forget(f)
		f.offset = 0
	}
	if _, err := file.Seek(f.offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(file, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			// io.EOF: nothing more, or a last line without its newline.
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(line) <= maxLine {
			s.add(f, f.offset, line)
		} else {
			s.broken++
		}
		f.offset += int64(len(line))
	}
}

// add indexes one line.
func (s *store) add(f *recordFile, offset int64, line []byte) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		s.broken++
		return
	}
	switch head.Type {
	case record.TypeStart:
		var st record.Start
		if json.Unmarshal(line, &st) != nil {
			s.broken++
			return
		}
		if _, seen := s.starts[st.Run]; !seen {
			s.runs = append(s.runs, st.Run)
		}
		s.rules[st.Run] = st.Rules
		st.Rules = nil
		s.starts[st.Run] = st
	case record.TypeRequest:
		var rec record.Request
		if json.Unmarshal(line, &rec) != nil || rec.ID == "" {
			s.broken++
			return
		}
		if _, dup := s.byID[rec.ID]; dup {
			return
		}
		e := &entry{
			id:         rec.ID,
			run:        rec.Run,
			time:       rec.Time,
			alert:      rec.Alert,
			score:      rec.Score.Total,
			ip:         rec.Client.IP,
			method:     rec.HTTP.Method,
			path:       rec.HTTP.Path,
			host:       rec.Server.Host,
			userAgent:  rec.HTTP.UserAgent,
			incomplete: !rec.Analysis.Complete,
			alertBy:    rec.AlertBy,
			threshold:  rec.Score.Threshold,
			file:       f,
			offset:     offset,
			length:     len(line),
		}
		if rec.Application != nil {
			e.app = rec.Application.Name
		}
		if rec.Profile != nil {
			e.profiled = len(rec.Profile.Findings) > 0
			for _, finding := range rec.Profile.Findings {
				e.profFindings = append(e.profFindings, profFinding{finding.Kind, finding.Location})
				if !slices.Contains(e.profileKinds, finding.Kind) {
					e.profileKinds = append(e.profileKinds, finding.Kind)
				}
			}
		}
		// Each rule, group and location once, in the order of the
		// findings. Locations come only from attack rules: the score rule
		// 949110 "matches" in TX:BLOCKING_INBOUND_ANOMALY_SCORE, which is
		// not a part of the request.
		for _, finding := range rec.Findings {
			if !slices.Contains(e.rules, finding.RuleID) {
				e.rules = append(e.rules, finding.RuleID)
			}
			f := entryFinding{rule: finding.RuleID, location: finding.Location}
			if groupOf(finding.RuleID).counts {
				f.weight = severityWeights[strings.ToUpper(finding.Severity)]
			}
			e.findings = append(e.findings, f)
			g := groupOf(finding.RuleID)
			if !g.counts {
				continue
			}
			if !slices.Contains(e.groups, g.name) {
				e.groups = append(e.groups, g.name)
			}
			if finding.Location != "" && !slices.Contains(e.locations, finding.Location) {
				e.locations = append(e.locations, finding.Location)
			}
		}
		s.entries = append(s.entries, e)
		s.byID[e.id] = e
	case record.TypeCounts:
		var c record.Counts
		if json.Unmarshal(line, &c) != nil {
			s.broken++
			return
		}
		s.counts = append(s.counts, countsEntry{Counts: c, file: f})
	case record.TypeGap:
		var g record.Gap
		if json.Unmarshal(line, &g) != nil || g.Missed < 1 {
			s.broken++
			return
		}
		s.gaps = append(s.gaps, gapEntry{Gap: g, file: f})
	case "":
		s.broken++
	default:
		// A newer writer's record type: skipped, as the format asks (C4).
		s.skipped++
	}
}

// load reads the whole line of one record from its file.
func (s *store) load(id string) (json.RawMessage, error) {
	s.mu.RLock()
	e, ok := s.byID[id]
	var name string
	var offset int64
	var length int
	if ok {
		name, offset, length = e.file.name, e.offset, e.length
	}
	s.mu.RUnlock()
	if !ok {
		return nil, errNotFound
	}
	file, err := os.Open(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	line := make([]byte, length)
	if _, err := file.ReadAt(line, offset); err != nil {
		return nil, err
	}
	// The line must still be the record that was indexed.
	var check struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(line, &check) != nil || check.ID != id {
		return nil, fmt.Errorf("record %s moved in %s", id, name)
	}
	return bytes.TrimSpace(line), nil
}

var errNotFound = errors.New("not found")

// group is the CRS rule file a rule belongs to. CRS rule ids start with
// the number of their file: 942100 is in REQUEST-942-...-SQLI.conf.
type group struct {
	name string
	// counts is false for the files that set up and score, whose rules
	// match along with any attack and say nothing about its kind.
	counts bool
}

var groups = map[int]group{
	901: {"Setup", false},
	905: {"Common exceptions", false},
	911: {"Method enforcement", true},
	913: {"Scanner detection", true},
	920: {"Protocol enforcement", true},
	921: {"Protocol attack", true},
	922: {"Multipart attack", true},
	930: {"Path traversal and file access", true},
	931: {"Remote file inclusion", true},
	932: {"Remote command execution", true},
	933: {"PHP injection", true},
	934: {"Generic attack", true},
	941: {"Cross-site scripting", true},
	942: {"SQL injection", true},
	943: {"Session fixation", true},
	944: {"Java attack", true},
	949: {"Anomaly score", false},
}

// ownGroup is the group of own rules, whose ids are 1,000 to 99,999
// (docs/development-plan-own-rules.md, N3).
const ownGroup = "Own rules"

func groupOf(ruleID int) group {
	if g, ok := groups[ruleID/1000]; ok {
		return g
	}
	if ruleID >= engine.OwnFirstID && ruleID <= engine.OwnLastID {
		return group{name: ownGroup, counts: true}
	}
	return group{name: "Other", counts: true}
}

// ruleGroup is the group a rule of a start record is shown in: own rules
// are in their own, whatever their file is called.
func ruleGroup(rule record.Rule) string {
	if rule.Own {
		return ownGroup
	}
	return fileGroup(rule.File)
}

// groupName is the name shown for a rule file number, such as "SQL
// injection" for 942.
func groupName(ruleID int) string {
	return groupOf(ruleID).name
}

// fileGroup returns the group of a rule file name such as
// "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".
func fileGroup(file string) string {
	parts := strings.SplitN(file, "-", 3)
	if len(parts) >= 2 {
		var n int
		if _, err := fmt.Sscanf(parts[1], "%d", &n); err == nil {
			if g, ok := groups[n]; ok {
				return g.name
			}
		}
	}
	return "Other"
}
