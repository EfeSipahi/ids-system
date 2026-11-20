package dashboard

// The test tab (docs/development-plan-test-tab.md, decisions S1–S4): a
// user writes a request as raw HTTP text, and the dashboard analyses it
// with the IDS's own engine and profiles, as ids-offline would. Nothing of
// the request is kept: no record, no setting, no log line with its
// content (C1).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/analysis"
	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/result"
)

const (
	// maxTestText is the longest request text, in bytes (C3). The largest
	// example request in the repository is about 66 KB.
	maxTestText = 1 << 20
	// maxRuleSets is how many prepared rule sets are kept; each holds
	// about 13 MB (C2). The least recently used one goes first.
	maxRuleSets = 4
	// maxTests is how many tests run at the same time; another one waits
	// (C3).
	maxTests = 2
	// recheckAfter is how long a rule set is used before its files are
	// read again to see whether its fingerprint changed (C2).
	recheckAfter = 2 * time.Second
	// maxShown is how many parameters, cookies or files the answer lists
	// of what the engine read.
	maxShown = 200
)

// tester runs the tab's tests. It is safe for use by many requests.
type tester struct {
	configs  []string // the product configuration files (S2)
	dir      string   // the folder of example request files (S4), or ""
	examples []testExample
	slots    chan struct{}
	now      func() time.Time

	mu    sync.Mutex
	sets  map[setKey]*ruleSet
	clock int64
}

// setKey names a prepared rule set: a configuration of the list, and the
// paranoia level the test asked for (0: the configuration's own).
type setKey struct {
	config, level int
}

type ruleSet struct {
	rules       *engine.RuleSet
	apps        *profile.Set
	parsing     httpmodel.Options
	level       int // the level the rules run at
	fingerprint string
	checked     time.Time
	used        int64
}

func newTester(configs []string, dir string, now func() time.Time) (*tester, error) {
	t := &tester{configs: configs, dir: dir, slots: make(chan struct{}, maxTests), now: now, sets: map[setKey]*ruleSet{}}
	f, err := webFiles.Open("web/examples.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	examples, err := offline.Load(f)
	if err != nil {
		return nil, fmt.Errorf("the built-in test examples: %w", err)
	}
	for _, ex := range examples {
		t.examples = append(t.examples, newTestExample(ex))
	}
	return t, nil
}

// testExample is a request the tab can load: a built-in one, or one of an
// example file, such as a CRS test with the rules it expects.
type testExample struct {
	Name     string `json:"name"`
	Text     string `json:"text,omitempty"`
	BodyCRLF bool   `json:"body_crlf"`
	// Writable is false when raw text can't hold the request exactly
	// (offline.Raw); Text is then empty.
	Writable    bool   `json:"writable"`
	Client      string `json:"client,omitempty"`
	ExpectIDs   []int  `json:"expect_ids,omitempty"`
	NoExpectIDs []int  `json:"no_expect_ids,omitempty"`
}

func newTestExample(ex offline.Example) testExample {
	text, crlf, ok := offline.Raw(ex.Request.Received)
	return testExample{
		Name: ex.Name, Text: text, BodyCRLF: crlf, Writable: ok,
		Client:    ex.Request.Received.RemoteAddr,
		ExpectIDs: ex.ExpectIDs, NoExpectIDs: ex.NoExpectIDs,
	}
}

// testConfig describes one configuration of the list.
type testConfig struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	// Level is the configuration's paranoia level.
	Level        int      `json:"paranoia_level,omitempty"`
	Applications []string `json:"applications"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	// Newest is true when the fingerprint is that of the newest run in
	// the records: the tab tests the rules the IDS runs.
	Newest bool   `json:"newest"`
	Error  string `json:"error,omitempty"`
}

// testFile is one example request file of the picker.
type testFile struct {
	Name  string `json:"name"`
	Tests int    `json:"tests"`
}

// testPage is what the tab needs to start.
type testPage struct {
	Enabled  bool          `json:"enabled"`
	Configs  []testConfig  `json:"configs"`
	Examples []testExample `json:"examples"`
	// Files are the example files of the picker, and FilesError why they
	// can't be listed.
	Files      []testFile `json:"files"`
	FilesError string     `json:"files_error,omitempty"`
	MaxText    int        `json:"max_text"`
}

func (t *tester) page(newest string) testPage {
	p := testPage{Enabled: len(t.configs) > 0, Configs: []testConfig{}, Examples: t.examples, Files: []testFile{}, MaxText: maxTestText}
	for i, path := range t.configs {
		c := testConfig{Index: i, Name: filepath.Base(path), Applications: []string{}}
		cfg, err := config.Load(path)
		if err == nil {
			c.Level = cfg.Level()
			c.Fingerprint, err = cfg.Fingerprint(c.Level)
			for _, app := range cfg.Applications {
				c.Applications = append(c.Applications, app.Name)
			}
		}
		if err != nil {
			c.Error = err.Error()
		}
		c.Newest = c.Fingerprint != "" && c.Fingerprint == newest
		p.Configs = append(p.Configs, c)
	}
	if t.dir != "" {
		files, err := t.files()
		if err != nil {
			p.FilesError = err.Error()
		}
		p.Files = append(p.Files, files...)
	}
	return p
}

// files lists the example request files of the folder, with how many
// requests each has. Only what this listing shows can be opened.
func (t *tester) files() ([]testFile, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var files []testFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(t.dir, e.Name()))
		if err != nil {
			return files, err
		}
		var list []json.RawMessage
		if json.Unmarshal(data, &list) != nil {
			continue
		}
		files = append(files, testFile{Name: strings.TrimSuffix(e.Name(), ".json"), Tests: len(list)})
	}
	return files, nil
}

// ruleFile returns the name of the example file of a rule's CRS tests, as
// the picker lists it, or "" when the folder has none.
func (t *tester) ruleFile(id int) string {
	if t == nil || t.dir == "" {
		return ""
	}
	name := strconv.Itoa(id)
	if info, err := os.Stat(filepath.Join(t.dir, name+".json")); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return name
}

// errNoSuchFile is the answer for a name the folder's listing does not
// show.
var errNoSuchFile = errors.New("no such example file")

// fileExamples returns the requests of one example file, by its name
// without ".json", as the listing gives it.
func (t *tester) fileExamples(name string) ([]testExample, error) {
	if t.dir == "" {
		return nil, errNoSuchFile
	}
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return !e.IsDir() && e.Name() == name+".json" }) {
		return nil, errNoSuchFile
	}
	examples, err := offline.LoadFile(filepath.Join(t.dir, name+".json"))
	if err != nil {
		return nil, err
	}
	list := make([]testExample, 0, len(examples))
	for _, ex := range examples {
		list = append(list, newTestExample(ex))
	}
	return list, nil
}

// testRequest is one test.
type testRequest struct {
	Config int // the index in the list
	// Level is the paranoia level, 1 to 4, in place of the
	// configuration's; 0 keeps it (as ids-offline -paranoia-level).
	Level int
	// Application names the application whose profile and exceptions
	// apply (as ids-offline -application); "" chooses it by Host and path.
	Application string
	// Client is the client's IP address, or "" for none, as an example
	// file without remote_addr.
	Client   string
	BodyCRLF bool
	Text     string
}

// testAnswer is what a test found.
type testAnswer struct {
	Config testConfig `json:"config"`
	// Level is the paranoia level the configuration's rules ran at; an
	// application may have its own, given in Result.Application.
	Level int `json:"paranoia_level"`
	// Millis is how long the analysis took, in milliseconds.
	Millis float64         `json:"ms"`
	Result result.Analysed `json:"result"`
	Read   testRead        `json:"read"`
	// ContentLength is set when the Content-Length header does not give
	// the length of the body.
	ContentLength *lengthNote `json:"content_length,omitempty"`
}

// testRead is what the engine read from the request.
type testRead struct {
	Method      string      `json:"method"`
	Target      string      `json:"target"`
	Version     string      `json:"version,omitempty"`
	Path        string      `json:"path"`
	Headers     int         `json:"headers"`
	BodyLength  int         `json:"body_length"`
	Client      string      `json:"client,omitempty"`
	Params      []testParam `json:"params"`
	Cookies     []testParam `json:"cookies"`
	Files       []testParam `json:"files"`
	NotShown    int         `json:"not_shown,omitempty"`
	Application string      `json:"application,omitempty"`
}

// testParam is a parameter, a cookie or a file: where it came from, its
// name and its value (for a file, its file name and size).
type testParam struct {
	Origin string `json:"origin,omitempty"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type lengthNote struct {
	Declared string `json:"declared"`
	Body     int    `json:"body"`
}

// testError is an error of a test with the HTTP status to answer.
type testError struct {
	status int
	msg    string
}

func (e *testError) Error() string { return e.msg }

func badTest(format string, a ...any) error {
	return &testError{status: 400, msg: fmt.Sprintf(format, a...)}
}

// run analyses one request. newest is the fingerprint of the newest run.
func (t *tester) run(ctx context.Context, tr testRequest, newest string) (testAnswer, error) {
	switch {
	case len(t.configs) == 0:
		return testAnswer{}, &testError{status: 404, msg: "the test tab is off: list configurations under test_configs in the dashboard's configuration"}
	case tr.Config < 0 || tr.Config >= len(t.configs):
		return testAnswer{}, badTest("there is no configuration %d", tr.Config)
	case tr.Level < 0 || tr.Level > engine.MaxParanoiaLevel:
		return testAnswer{}, badTest("paranoia level %d: give 1 to %d, or 0 for the configuration's", tr.Level, engine.MaxParanoiaLevel)
	case len(tr.Text) > maxTestText:
		return testAnswer{}, &testError{status: 413, msg: fmt.Sprintf("the request is longer than %d bytes", maxTestText)}
	}
	if tr.Client != "" {
		addr, err := netip.ParseAddr(tr.Client)
		if err != nil || addr.Zone() != "" {
			return testAnswer{}, badTest("client address %q is not an IP address", tr.Client)
		}
	}
	rec, err := offline.ParseRaw(tr.Text, tr.BodyCRLF)
	if err != nil {
		return testAnswer{}, badTest("%v", err)
	}
	rec.RemoteAddr = tr.Client

	select {
	case t.slots <- struct{}{}:
		defer func() { <-t.slots }()
	case <-ctx.Done():
		return testAnswer{}, ctx.Err()
	}
	rs, err := t.ruleSet(setKey{tr.Config, tr.Level})
	if err != nil {
		return testAnswer{}, &testError{status: 500, msg: fmt.Sprintf("the configuration %s can't be loaded: %v", filepath.Base(t.configs[tr.Config]), err)}
	}
	req := httpmodel.NewWith(rec, rs.parsing)
	var app *profile.App
	if tr.Application != "" {
		if app = rs.apps.ByName(tr.Application); app == nil {
			return testAnswer{}, badTest("the configuration %s has no application %q", filepath.Base(t.configs[tr.Config]), tr.Application)
		}
	} else {
		app = rs.apps.Match(req)
	}

	start := time.Now()
	res, prof := analysis.Run(rs.rules, rs.apps, req, app)
	took := time.Since(start)

	a := testAnswer{
		Config: testConfig{Index: tr.Config, Name: filepath.Base(t.configs[tr.Config]), Level: rs.level, Applications: []string{},
			Fingerprint: rs.fingerprint, Newest: rs.fingerprint == newest},
		Level:  rs.level,
		Millis: float64(took.Microseconds()) / 1000,
		Result: result.NewAnalysed(res, prof, app, rs.level, result.Options{ShowValues: true}),
		Read:   newTestRead(res.Request),
	}
	for _, ap := range rs.apps.Apps() {
		a.Config.Applications = append(a.Config.Applications, ap.Name)
	}
	if app != nil {
		a.Read.Application = app.Name
	}
	a.ContentLength = contentLength(res.Request)
	return a, nil
}

// ruleSet returns the prepared rules of a configuration at a level,
// preparing them when needed (C2).
func (t *tester) ruleSet(key setKey) (*ruleSet, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clock++
	now := t.now()
	rs := t.sets[key]
	if rs != nil && now.Sub(rs.checked) < recheckAfter {
		rs.used = t.clock
		return rs, nil
	}
	cfg, err := config.Load(t.configs[key.config])
	if err != nil {
		delete(t.sets, key)
		return nil, err
	}
	level := key.level
	if level == 0 {
		level = cfg.Level()
	}
	fingerprint, err := cfg.Fingerprint(level)
	if err != nil {
		delete(t.sets, key)
		return nil, err
	}
	if rs != nil && rs.fingerprint == fingerprint {
		rs.checked, rs.used = now, t.clock
		return rs, nil
	}
	cfg.ParanoiaLevel = level
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		delete(t.sets, key)
		return nil, err
	}
	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		delete(t.sets, key)
		return nil, err
	}
	rs = &ruleSet{rules: rules, apps: apps, parsing: cfg.Parsing(), level: rules.ParanoiaLevel(),
		fingerprint: fingerprint, checked: now, used: t.clock}
	t.sets[key] = rs
	for len(t.sets) > maxRuleSets {
		var oldest setKey
		first := true
		for k, s := range t.sets {
			if first || s.used < t.sets[oldest].used {
				oldest, first = k, false
			}
		}
		delete(t.sets, oldest)
	}
	return rs, nil
}

func newTestRead(req *httpmodel.Request) testRead {
	rec, p := req.Received, req.Parsed
	r := testRead{
		Method: rec.Method, Target: result.Printable(rec.Target), Version: rec.Version,
		Path: result.Printable(p.DecodedPath), Headers: len(rec.Headers), BodyLength: len(rec.Body),
		Client: rec.RemoteAddr, Params: []testParam{}, Cookies: []testParam{}, Files: []testParam{},
	}
	add := func(list *[]testParam, tp testParam) {
		if len(*list) >= maxShown {
			r.NotShown++
			return
		}
		tp.Name, tp.Value = result.Printable(tp.Name), result.Printable(tp.Value)
		*list = append(*list, tp)
	}
	for _, a := range req.Args() {
		add(&r.Params, testParam{Origin: a.Origin.String(), Name: a.Name, Value: a.Value})
	}
	for _, c := range p.Cookies {
		add(&r.Cookies, testParam{Name: c.Name, Value: c.Value})
	}
	for _, f := range p.Files {
		add(&r.Files, testParam{Origin: f.Field, Name: f.Name, Value: strconv.Itoa(f.Size) + " bytes"})
	}
	return r
}

// contentLength returns a note when the Content-Length header does not
// give the body's length; the tab offers to correct it. A request without
// the header gets none.
func contentLength(req *httpmodel.Request) *lengthNote {
	values := req.HeaderValues("Content-Length")
	if len(values) == 0 {
		return nil
	}
	body := len(req.Received.Body)
	if len(values) == 1 {
		if n, err := strconv.Atoi(values[0]); err == nil && n == body {
			return nil
		}
	}
	return &lengthNote{Declared: result.Printable(strings.Join(values, ", ")), Body: body}
}
