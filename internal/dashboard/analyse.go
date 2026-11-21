package dashboard

// Tools › Analyse files (W14 of docs/development-plan-dashboard-control.md):
// what ids-offline does, from the dashboard. Request files are uploaded
// or chosen from the example folder, analysed in the background, one
// analysis at a time, with the same summary and expectations as
// ids-offline -summary (package batch). An admin may write the results as
// a run of records, at the time of the analysis or as a replay. The
// requests are kept in memory until the next analysis: the preview of
// changes that add detection tries them (W8), and the Profile tab
// suggests their paths and parameters (W15).

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/batch"
	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
)

const (
	// maxAnalyseBytes is the most request file bytes one analysis reads.
	maxAnalyseBytes = 50 << 20
	// maxAnalyseRows is how many requests the result lists one by one;
	// the summary counts them all.
	maxAnalyseRows = 2000
)

// The ways an analysis writes records.
const (
	writeNone   = ""
	writeRun    = "records"
	writeReplay = "replay"
)

// jobRow is one analysed request of the result.
type jobRow struct {
	Index       int                `json:"index"`
	Source      string             `json:"source"`
	Name        string             `json:"name,omitempty"`
	Method      string             `json:"method"`
	Path        string             `json:"path"`
	Application string             `json:"application,omitempty"`
	Score       int                `json:"score"`
	Alert       bool               `json:"alert"`
	AlertBy     []string           `json:"alert_by,omitempty"`
	Rules       []int              `json:"rules"`
	Incomplete  bool               `json:"incomplete"`
	Expectation *batch.Expectation `json:"expectation,omitempty"`
}

// queuedExample is one request of an analysis, with the file it came from.
type queuedExample struct {
	source string
	ex     offline.Example
}

// job is an analysis: running, or the last one done.
type job struct {
	ID      string    `json:"id"`
	User    string    `json:"user"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitzero"`
	Running bool      `json:"running"`
	Stopped bool      `json:"stopped,omitempty"`
	Error   string    `json:"error,omitempty"`

	Config      string   `json:"config"`
	Level       int      `json:"level,omitempty"`
	Application string   `json:"application,omitempty"`
	Write       string   `json:"write,omitempty"`
	Files       []string `json:"files"`
	Bytes       int64    `json:"bytes"`

	Total int `json:"total"`
	Done  int `json:"done"`

	Requests  int           `json:"requests"`
	Alerts    int           `json:"alerts"`
	Unmet     int           `json:"unmet"`
	Summary   []batch.Group `json:"summary"`
	Rows      []jobRow      `json:"rows"`
	Profiled  bool          `json:"profiled"`
	RecordRun string        `json:"record_run,omitempty"`
	Written   int           `json:"written,omitempty"`

	cancel   context.CancelFunc
	examples []queuedExample
	surveys  map[string]*profile.Survey // by application
}

// analyser runs one analysis at a time.
type analyser struct {
	recordsDir string
	now        func() time.Time

	mu  sync.Mutex
	job *job
}

// analyseConfig is a configuration an analysis may use.
type analyseConfig struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	// IDS is true for the configuration ids-live runs.
	IDS  bool     `json:"ids"`
	Apps []string `json:"applications"`
	path string
}

// analyseConfigs are the IDS's configuration, then the test tab's.
func (s *Server) analyseConfigs() []analyseConfig {
	var out []analyseConfig
	seen := map[string]bool{}
	add := func(path string, ids bool) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		c := analyseConfig{Index: len(out), Name: filepath.Base(path), IDS: ids, Apps: []string{}, path: path}
		if p, err := config.Load(path); err == nil {
			for _, a := range p.Applications {
				c.Apps = append(c.Apps, a.Name)
			}
		}
		out = append(out, c)
	}
	add(s.cfg.IDSConfig, true)
	for _, c := range s.cfg.TestConfigs {
		add(c, false)
	}
	return out
}

// analysePage is what the page shows: the choices and the job.
type analysePage struct {
	Configs []analyseConfig `json:"configs"`
	// Folder lists the example files of the test tab's folder.
	Folder   []testFile `json:"folder"`
	MaxBytes int        `json:"max_bytes"`
	Write    bool       `json:"write"`
	Job      *job       `json:"job,omitempty"`
}

func (s *Server) apiAnalyse(w http.ResponseWriter, r *http.Request) {
	p := analysePage{Configs: s.analyseConfigs(), Folder: []testFile{}, MaxBytes: maxAnalyseBytes,
		Write: allows(s.auth.users.role(s.auth.user(sessionToken(r))), RoleAdmin)}
	if p.Configs == nil {
		p.Configs = []analyseConfig{}
	}
	if s.test.dir != "" {
		if files, err := s.test.files(); err == nil {
			p.Folder = files
		}
	}
	s.analyse.mu.Lock()
	if j := s.analyse.job; j != nil {
		cp := *j
		p.Job = &cp
	}
	s.analyse.mu.Unlock()
	writeJSON(w, http.StatusOK, p)
}

// apiAnalyseStart reads the form of an analysis: the files, uploaded or
// named from the folder, and the choices; and starts it.
func (s *Server) apiAnalyseStart(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	r.Body = http.MaxBytesReader(w, r.Body, maxAnalyseBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		var tooLong *http.MaxBytesError
		if errors.As(err, &tooLong) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("the files are larger than %d MB together", maxAnalyseBytes>>20)})
			return
		}
		badRequest(w, fmt.Errorf("the form can't be read: %v", err))
		return
	}
	defer r.MultipartForm.RemoveAll()
	f := r.MultipartForm.Value
	get := func(k string) string {
		if v := f[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	configs := s.analyseConfigs()
	ci, err := strconv.Atoi(get("config"))
	if err != nil || ci < 0 || ci >= len(configs) {
		badRequest(w, errors.New("choose one of the configurations"))
		return
	}
	cfgChoice := configs[ci]
	level := 0
	if v := get("level"); v != "" && v != "0" {
		if level, err = strconv.Atoi(v); err != nil || level < 1 || level > engine.MaxParanoiaLevel {
			badRequest(w, errors.New("the level is 1 to 4, or 0 for the configuration's"))
			return
		}
	}
	app := get("application")
	if app != "" && !slices.Contains(cfgChoice.Apps, app) {
		badRequest(w, fmt.Errorf("%s has no application %q", cfgChoice.Name, app))
		return
	}
	write := get("write")
	switch write {
	case writeNone:
	case writeRun, writeReplay:
		if !allows(s.auth.users.role(user), RoleAdmin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "only an admin writes records: they go to the records everyone sees"})
			return
		}
	default:
		badRequest(w, fmt.Errorf("write %q is not records or replay", write))
		return
	}

	// The files: uploaded, or named from the folder.
	type input struct {
		name string
		data []byte
	}
	var inputs []input
	var total int64
	for _, fh := range r.MultipartForm.File["files"] {
		if total+fh.Size > maxAnalyseBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("the files are larger than %d MB together", maxAnalyseBytes>>20)})
			return
		}
		file, err := fh.Open()
		if err != nil {
			badRequest(w, err)
			return
		}
		data, err := io.ReadAll(io.LimitReader(file, maxAnalyseBytes+1))
		file.Close()
		if err != nil {
			badRequest(w, err)
			return
		}
		total += int64(len(data))
		inputs = append(inputs, input{name: fh.Filename, data: data})
	}
	folder := f["folder"]
	if len(folder) > 0 {
		if s.test.dir == "" {
			badRequest(w, errors.New("the dashboard has no example folder (test_requests_dir)"))
			return
		}
		listed, err := s.test.files()
		if err != nil {
			badRequest(w, err)
			return
		}
		names := map[string]bool{}
		for _, lf := range listed {
			names[lf.Name] = true
		}
		if slices.Contains(folder, "*") {
			folder = folder[:0]
			for _, lf := range listed {
				folder = append(folder, lf.Name)
			}
		}
		for _, name := range folder {
			if !names[name] {
				badRequest(w, fmt.Errorf("the folder has no file %q", name))
				return
			}
			data, err := os.ReadFile(filepath.Join(s.test.dir, name+".json"))
			if err != nil {
				badRequest(w, err)
				return
			}
			total += int64(len(data))
			if total > maxAnalyseBytes {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("the files are larger than %d MB together", maxAnalyseBytes>>20)})
				return
			}
			inputs = append(inputs, input{name: name + ".json", data: data})
		}
	}
	if len(inputs) == 0 {
		badRequest(w, errors.New("upload request files, or choose files from the folder"))
		return
	}

	cfg, err := config.Load(cfgChoice.path)
	if err != nil {
		badRequest(w, fmt.Errorf("%s does not load: %v", cfgChoice.Name, err))
		return
	}
	var order []queuedExample
	var files []string
	for _, in := range inputs {
		examples, err := offline.LoadWith(bytes.NewReader(in.data), cfg.Parsing())
		if err != nil {
			badRequest(w, fmt.Errorf("%s: %v", in.name, err))
			return
		}
		source := strings.TrimSuffix(filepath.Base(in.name), ".json")
		files = append(files, source)
		for _, ex := range examples {
			order = append(order, queuedExample{source, ex})
		}
	}
	if write == writeReplay {
		for _, q := range order {
			if q.ex.Time.IsZero() {
				badRequest(w, fmt.Errorf("%s: %q has no time; a replay needs the time of every request", q.source, q.ex.Name))
				return
			}
		}
		sort.SliceStable(order, func(i, j int) bool { return order[i].ex.Time.Before(order[j].ex.Time) })
	}

	j := &job{ID: strings.ToLower(rand.Text()[:10]), User: user, Started: s.now().UTC(), Running: true, Config: cfgChoice.Name,
		Level: level, Application: app, Write: write, Files: files, Bytes: total, Total: len(order),
		Summary: []batch.Group{}, Rows: []jobRow{}, examples: order, surveys: map[string]*profile.Survey{}}
	s.analyse.mu.Lock()
	if s.analyse.job != nil && s.analyse.job.Running {
		s.analyse.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an analysis is running; wait for it, or stop it"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	s.analyse.job = j
	s.analyse.mu.Unlock()
	go s.analyse.run(ctx, j, cfg, level, app)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": j.ID})
}

// run analyses a job's requests, as ids-offline does.
func (a *analyser) run(ctx context.Context, j *job, cfg *config.Product, level int, appName string) {
	fail := func(err error) {
		a.mu.Lock()
		j.Error, j.Running, j.Ended = err.Error(), false, a.now().UTC()
		a.mu.Unlock()
	}
	if level != 0 {
		cfg.ParanoiaLevel = level
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		fail(fmt.Errorf("the rules do not load: %w", err))
		return
	}
	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		fail(fmt.Errorf("the applications can't be prepared: %w", err))
		return
	}
	var forced *profile.App
	if appName != "" {
		forced = apps.ByName(appName)
	}
	profiled := len(apps.Apps()) > 0

	var recorder *record.Recorder
	var clock time.Time
	if j.Write != writeNone {
		rc := record.Config{}
		if cfg.Records != nil {
			rc = *cfg.Records
		}
		// The run goes to the folder the dashboard reads.
		rc.Dir = a.recordsDir
		fp, err := cfg.Fingerprint(rules.ParanoiaLevel())
		if err != nil {
			fail(err)
			return
		}
		if j.Write == writeReplay {
			clock = j.examples[0].ex.Time
			recorder, err = record.OpenReplay(rc, record.NewEngine(rules, fp), rules.Statuses(), apps, a.now(), func() time.Time { return clock })
		} else {
			recorder, err = record.Open(rc, record.NewEngine(rules, fp), rules.Statuses(), apps)
		}
		if errors.Is(err, record.ErrInUse) {
			fail(errors.New("ids-live writes the records folder now, so nothing was analysed; stop it first (scripts/ids-live-ctl stop), or analyse without writing records"))
			return
		}
		if err != nil {
			fail(err)
			return
		}
	}

	var items []batch.Item
	var rows []jobRow
	alerts, unmet, written := 0, 0, 0
	for i, q := range j.examples {
		if ctx.Err() != nil {
			break
		}
		if j.Write == writeReplay {
			clock = q.ex.Time
		}
		app := forced
		if app == nil {
			app = apps.Match(q.ex.Request)
		}
		res, prof := analysis.Run(rules, apps, q.ex.Request, app)
		an := result.NewAnalysed(res, prof, app, rules.ParanoiaLevel(), result.Options{})
		exp := batch.Check(q.ex, res)
		it := batch.Item{Source: q.source, Exceeded: an.Score.Exceeded, Complete: an.Analysis.Complete, ByProfile: slices.Contains(an.AlertBy, result.AlertByProfile), Expectation: exp}
		if an.Application != nil {
			it.Application = an.Application.Name
		}
		if an.Profile != nil {
			it.Findings = an.Profile.Findings
		}
		items = append(items, it)
		alert := an.Score.Exceeded || it.ByProfile
		if alert {
			alerts++
		}
		if exp != nil && !exp.Met {
			unmet++
		}
		if len(rows) < maxAnalyseRows {
			row := jobRow{Index: i + 1, Source: q.source, Name: q.ex.Name, Method: q.ex.Request.Received.Method, Path: q.ex.Request.Parsed.DecodedPath,
				Score: an.Score.Total, Alert: alert, AlertBy: an.AlertBy, Rules: []int{}, Incomplete: !an.Analysis.Complete, Expectation: exp}
			if an.Application != nil {
				row.Application = an.Application.Name
			}
			for _, id := range res.MatchedIDs() {
				if !slices.Contains(row.Rules, id) {
					row.Rules = append(row.Rules, id)
				}
			}
			rows = append(rows, row)
		}
		if app != nil {
			sv := j.surveys[app.Name]
			if sv == nil {
				sv = profile.NewSurvey()
				j.surveys[app.Name] = sv
			}
			sv.Add(q.ex.Request)
		}
		if recorder != nil {
			if err := recorder.Add(res.Request, res, prof); err != nil {
				recorder.Close()
				fail(err)
				return
			}
			if record.Wanted(res.Request, res, prof) {
				written++
			}
		}
		if i%50 == 0 {
			a.mu.Lock()
			j.Done = i + 1
			a.mu.Unlock()
		}
	}
	var closeErr error
	if recorder != nil {
		closeErr = recorder.Close()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	j.Done, j.Requests, j.Alerts, j.Unmet = len(items), len(items), alerts, unmet
	j.Summary, j.Rows, j.Profiled = batch.Summarize(items, rules.Statuses(), profiled), rows, profiled
	if j.Summary == nil {
		j.Summary = []batch.Group{}
	}
	if recorder != nil {
		j.RecordRun, j.Written = recorder.Run(), written
	}
	j.Stopped = ctx.Err() != nil
	j.Running, j.Ended = false, a.now().UTC()
	if closeErr != nil {
		j.Error = closeErr.Error()
	}
}

func (s *Server) apiAnalyseStop(w http.ResponseWriter, r *http.Request) {
	s.analyse.mu.Lock()
	defer s.analyse.mu.Unlock()
	if s.analyse.job == nil || !s.analyse.job.Running {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no analysis is running"})
		return
	}
	s.analyse.job.cancel()
	writeJSON(w, http.StatusOK, map[string]string{"stopping": s.analyse.job.ID})
}

// tryResult is what an object's pending changes do to the requests of the
// last analysis (W8): the changes that add detection can be tried here.
type tryResult struct {
	Object       string    `json:"object"`
	Reach        string    `json:"reach"`
	Requests     int       `json:"requests"`
	AlertsBefore int       `json:"alerts_before"`
	AlertsAfter  int       `json:"alerts_after"`
	Added        int       `json:"added"`
	Removed      int       `json:"removed"`
	Examples     []tryRow  `json:"examples"`
	Files        []string  `json:"files"`
	Analysed     time.Time `json:"analysed"`
}

type tryRow struct {
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	Path   string `json:"path"`
	Before int    `json:"before"`
	After  int    `json:"after"`
	// Alert is true when the change makes it an alert, false when it
	// takes the alert away.
	Alert bool `json:"alert"`
	// Rules are the rules it matches after the change and not before, or
	// before and not after.
	Rules []int `json:"rules"`
}

// apiAnalyseTry runs the last analysis's requests with the IDS's
// configuration as it is and as an object's pending changes make it.
func (s *Server) apiAnalyseTry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Object string `json:"object"`
	}
	if err := readJSON(w, r, 4<<10, &req); err != nil {
		badRequest(w, err)
		return
	}
	if err := checkObject(req.Object); err != nil {
		badRequest(w, err)
		return
	}
	if s.control.path == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": errNoConfig.Error()})
		return
	}
	s.analyse.mu.Lock()
	j := s.analyse.job
	if j == nil || j.Running || len(j.examples) == 0 {
		s.analyse.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "analyse request files first; their requests are tried"})
		return
	}
	examples, files, analysed := j.examples, j.Files, j.Started
	s.analyse.mu.Unlock()

	list, err := s.control.pending(req.Object)
	if err != nil || len(list) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": reach(req.Object) + " has no pending changes"})
		return
	}
	before, err := config.Load(s.control.path)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "the configuration on disk does not load: " + err.Error()})
		return
	}
	b, err := s.control.build(req.Object, list)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	type set struct {
		rules *engine.RuleSet
		apps  *profile.Set
	}
	prepare := func(p *config.Product) (set, error) {
		rules, err := engine.Load(p.Config)
		if err != nil {
			return set{}, err
		}
		apps, err := profile.NewSet(rules, p.Applications, p.RequireProfile)
		return set{rules, apps}, err
	}
	old, err := prepare(before)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	now, err := prepare(b.product)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	out := tryResult{Object: req.Object, Reach: reach(req.Object), Examples: []tryRow{}, Files: files, Analysed: analysed}
	app := objectApp(req.Object)
	for _, q := range examples {
		if r.Context().Err() != nil {
			return
		}
		run := func(st set) (bool, int, []int, string) {
			a := st.apps.Match(q.ex.Request)
			res, prof := analysis.Run(st.rules, st.apps, q.ex.Request, a)
			an := result.NewAnalysed(res, prof, a, st.rules.ParanoiaLevel(), result.Options{})
			name := profile.NoApplication
			if a != nil {
				name = a.Name
			}
			return an.Score.Exceeded || slices.Contains(an.AlertBy, result.AlertByProfile), an.Score.Total, res.MatchedIDs(), name
		}
		wasAlert, oldScore, oldRules, oldApp := run(old)
		isAlert, newScore, newRules, newApp := run(now)
		if req.Object != objectGlobal && oldApp != app && newApp != app {
			continue
		}
		out.Requests++
		if wasAlert {
			out.AlertsBefore++
		}
		if isAlert {
			out.AlertsAfter++
		}
		if wasAlert == isAlert {
			continue
		}
		row := tryRow{Source: q.source, Name: q.ex.Name, Path: q.ex.Request.Parsed.DecodedPath, Before: oldScore, After: newScore, Alert: isAlert, Rules: []int{}}
		if isAlert {
			out.Added++
			for _, id := range newRules {
				if !slices.Contains(oldRules, id) && !slices.Contains(row.Rules, id) {
					row.Rules = append(row.Rules, id)
				}
			}
		} else {
			out.Removed++
			for _, id := range oldRules {
				if !slices.Contains(newRules, id) && !slices.Contains(row.Rules, id) {
					row.Rules = append(row.Rules, id)
				}
			}
		}
		if len(out.Examples) < maxExamples {
			out.Examples = append(out.Examples, row)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// fileSurvey returns the survey of an application's requests in the last
// analysis, if it had any.
func (a *analyser) fileSurvey(app string) (*profile.Survey, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.job == nil || a.job.Running {
		return nil, nil
	}
	return a.job.surveys[app], a.job.Files
}
