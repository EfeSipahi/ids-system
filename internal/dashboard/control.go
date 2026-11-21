package dashboard

// Changing the IDS from the dashboard (decisions W7–W13 of
// docs/development-plan-dashboard-control.md).
//
// A change is first pending (W7): each object, an application or the
// settings for every application, collects its pending changes in the
// state folder. They are applied together, with one reason, as one
// version (W11): the files they change are checked by the same readers the
// IDS uses, the files they replace are kept, and only then are the IDS's
// own files written, in place (W12). ids-live sees the new files and
// takes them without stopping (W13).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/jsonedit"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// Files and folders of the state folder.
const (
	// PendingFile holds the pending changes of every object (W7).
	PendingFile = "pending.json"
	// VersionsDir holds a folder per applied change, with the files it
	// replaced and wrote (W11).
	VersionsDir = "versions"
)

// The objects changes belong to.
const (
	objectGlobal = "global"
	appPrefix    = "app:"
)

// The kinds of change.
const (
	// For one application.
	kindRuleOff       = "rule_off"       // Rule; Reason
	kindRuleSkip      = "rule_skip"      // Rule, Targets; Reason
	kindRuleOn        = "rule_on"        // Rule: its exception goes
	kindSetting       = "setting"        // Setting, Value; Reason
	kindSettingRemove = "setting_remove" // Setting
	kindMode          = "mode"           // Mode
	kindLevel         = "level"          // Level, 0 for the default
	kindHosts         = "hosts"          // Hosts
	kindPaths         = "paths"          // Paths
	kindRemoveApp     = "remove_app"     //
	kindProfile       = "profile"        // Text: the whole profile
	// For every application.
	kindDefaultLevel   = "default_level"   // Level
	kindExclude        = "exclude"         // Rule; Reason
	kindInclude        = "include"         // Rule
	kindFiles          = "files"           // Files, as the configuration writes them
	kindBodyLimit      = "body_limit"      // Number, 0 for the default
	kindRequireProfile = "require_profile" // On
	kindRecords        = "records"         // Records
	kindLive           = "live"            // Live
	kindAddApp         = "add_app"         // Name, Hosts, Paths
	// For either: the files of a version as they were before it (undo).
	kindRestore = "restore" // Version
)

// appKinds are the kinds of an application's change; analystKinds those an
// analyst may propose (W9).
var (
	appKinds     = []string{kindRuleOff, kindRuleSkip, kindRuleOn, kindSetting, kindSettingRemove, kindMode, kindLevel, kindHosts, kindPaths, kindRemoveApp, kindProfile, kindRestore}
	globalKinds  = []string{kindDefaultLevel, kindExclude, kindInclude, kindFiles, kindBodyLimit, kindRequireProfile, kindRecords, kindLive, kindAddApp, kindRestore}
	analystKinds = []string{kindRuleOff, kindRuleSkip, kindRuleOn, kindSetting}
)

// recordSettings are the "records" settings a change may set; the folder
// is not one of them (W4).
type recordSettings struct {
	MaxFileMB    int      `json:"max_file_mb"`
	KeepFiles    int      `json:"keep_files"`
	FullRequests bool     `json:"full_requests"`
	SecretNames  []string `json:"secret_names"`
}

// liveSettings are the "live" settings a change may set; the socket is not
// one of them, as Caddy's side names it too (W4).
type liveSettings struct {
	Workers     int `json:"workers"`
	QueueCopies int `json:"queue_copies"`
	QueueMB     int `json:"queue_mb"`
	MaxFrameMB  int `json:"max_frame_mb"`
}

// pendingChange is one change that waits to be applied (W7).
type pendingChange struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Rule     int             `json:"rule,omitempty"`
	Targets  []string        `json:"targets,omitempty"`
	Setting  string          `json:"setting,omitempty"`
	Value    *string         `json:"value,omitempty"`
	Mode     string          `json:"mode,omitempty"`
	Level    *int            `json:"level,omitempty"`
	Hosts    []string        `json:"hosts,omitempty"`
	Paths    []string        `json:"paths,omitempty"`
	Text     string          `json:"text,omitempty"`
	Number   *int            `json:"number,omitempty"`
	On       *bool           `json:"on,omitempty"`
	Files    []string        `json:"files,omitempty"`
	Records  *recordSettings `json:"records,omitempty"`
	Live     *liveSettings   `json:"live,omitempty"`
	Name     string          `json:"name,omitempty"`
	Version  string          `json:"version,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	User     string          `json:"user"`
	Time     time.Time       `json:"time"`
	Proposal bool            `json:"proposal,omitempty"`
	// What is a sentence that says what the change does, with its reach
	// (W5): "Rule 942100 off for csic-shop".
	What string `json:"what"`
	// From names the record a change was proposed from, if any.
	From string `json:"from,omitempty"`
}

// pendingFile is the pending changes of every object.
type pendingFile struct {
	Objects map[string][]pendingChange `json:"objects"`
}

// versionFile is one file a version changed.
type versionFile struct {
	// Path is the file's path as the dashboard writes it.
	Path string `json:"path"`
	// Created is true when the version made the file; Before is then
	// empty.
	Created bool   `json:"created,omitempty"`
	Before  string `json:"before_sha256,omitempty"`
	After   string `json:"after_sha256"`
}

// version is one applied change (W11). Its folder holds meta.json and the
// files before and after it, as before-N and after-N.
type version struct {
	ID     string          `json:"id"`
	Seq    int             `json:"seq"`
	Object string          `json:"object"`
	Time   time.Time       `json:"time"`
	User   string          `json:"user"`
	Reason string          `json:"reason"`
	Items  []pendingChange `json:"changes"`
	Files  []versionFile   `json:"files"`
	// Fingerprint is the configuration's fingerprint after the change:
	// ids-live runs it once a run of this fingerprint starts.
	Fingerprint string `json:"fingerprint"`
	// Undoes names the version this one took back, if it is an undo.
	Undoes string `json:"undoes,omitempty"`
}

// control changes the IDS's configuration. It is safe for use by many
// requests; one change is applied at a time.
type control struct {
	// path is the product configuration ids-live runs (W12), or "".
	path     string
	stateDir string
	now      func() time.Time

	mu sync.Mutex
	// loadRules prepares the rules of a configuration; a test may swap it.
	loadRules func(engine.Config) (*engine.RuleSet, error)
}

func newControl(path, stateDir string, now func() time.Time) *control {
	return &control{path: path, stateDir: stateDir, now: now, loadRules: engine.Load}
}

// errNoConfig is the answer when the dashboard does not know the IDS's
// configuration.
var errNoConfig = errors.New("the dashboard does not know the IDS's configuration; name it as ids_config in the dashboard's configuration file")

// objectApp returns the application of an object, or "" for the settings
// for every application.
func objectApp(object string) string {
	return strings.TrimPrefix(object, appPrefix)
}

// checkObject checks an object's name.
func checkObject(object string) error {
	if object == objectGlobal {
		return nil
	}
	if name, ok := strings.CutPrefix(object, appPrefix); ok && validAppName(name) && name != profile.NoApplication {
		return nil
	}
	return fmt.Errorf("object %q is not %s or %s and an application's name", object, objectGlobal, appPrefix)
}

// reach says in words whom an object's changes concern (W5).
func reach(object string) string {
	if object == objectGlobal {
		return "every application"
	}
	return objectApp(object)
}

// ---- Pending changes (W7) ----

func (c *control) readPending() (pendingFile, error) {
	p := pendingFile{Objects: map[string][]pendingChange{}}
	data, err := os.ReadFile(filepath.Join(c.stateDir, PendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("%s: %w", PendingFile, err)
	}
	if p.Objects == nil {
		p.Objects = map[string][]pendingChange{}
	}
	return p, nil
}

func (c *control) writePending(p pendingFile) error {
	for k, list := range p.Objects {
		if len(list) == 0 {
			delete(p.Objects, k)
		}
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.stateDir, PendingFile), append(data, '\n'), 0o600)
}

// pending returns an object's pending changes, oldest first.
func (c *control) pending(object string) ([]pendingChange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.readPending()
	if err != nil {
		return nil, err
	}
	list := p.Objects[object]
	if list == nil {
		list = []pendingChange{}
	}
	return list, nil
}

// allPending returns the pending changes of every object.
func (c *control) allPending() (map[string][]pendingChange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.readPending()
	return p.Objects, err
}

// maxPending is the most pending changes one object may have.
const maxPending = 200

// add checks a change and adds it to its object's pending changes. The
// change is tried on the files as they are now together with the object's
// other pending changes, so a change that can't be applied is refused at
// once.
func (c *control) add(object string, ch pendingChange) (pendingChange, error) {
	if c.path == "" {
		return ch, errNoConfig
	}
	if err := checkObject(object); err != nil {
		return ch, err
	}
	if err := checkChange(object, &ch); err != nil {
		return ch, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.readPending()
	if err != nil {
		return ch, err
	}
	if len(p.Objects[object]) >= maxPending {
		return ch, fmt.Errorf("%s has %d pending changes already; apply or drop some first", reach(object), maxPending)
	}
	ch.ID = strings.ToLower(rand.Text()[:12])
	ch.Time = c.now().UTC()
	list := append(slices.Clone(p.Objects[object]), ch)
	b, err := c.build(object, list)
	if err != nil {
		return ch, err
	}
	if err := c.check(b); err != nil {
		return ch, err
	}
	p.Objects[object] = list
	return ch, c.writePending(p)
}

// drop takes a pending change out. It returns the change.
func (c *control) drop(object, id string) (pendingChange, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.readPending()
	if err != nil {
		return pendingChange{}, err
	}
	list := p.Objects[object]
	i := slices.IndexFunc(list, func(x pendingChange) bool { return x.ID == id })
	if i < 0 {
		return pendingChange{}, errNoPending
	}
	ch := list[i]
	p.Objects[object] = slices.Delete(slices.Clone(list), i, i+1)
	return ch, c.writePending(p)
}

var errNoPending = errors.New("no such pending change")

// maxReason is the longest reason or exception text, in characters.
const maxReason = 1000

// checkChange checks the form of a change and writes its What.
func checkChange(object string, ch *pendingChange) error {
	app := objectApp(object)
	kinds := globalKinds
	if object != objectGlobal {
		kinds = appKinds
	}
	if !slices.Contains(kinds, ch.Kind) {
		return fmt.Errorf("kind %q is not a change for %s", ch.Kind, reach(object))
	}
	ch.Reason = strings.TrimSpace(ch.Reason)
	if !utf8.ValidString(ch.Reason) || utf8.RuneCountInString(ch.Reason) > maxReason {
		return fmt.Errorf("the reason is not text of at most %d characters", maxReason)
	}
	needReason := func() error {
		if ch.Reason == "" {
			return errors.New("give a reason: the IDS shows it next to the exception")
		}
		return nil
	}
	needRule := func() error {
		if ch.Rule < 1 {
			return errors.New("give the rule's number")
		}
		return nil
	}
	switch ch.Kind {
	case kindRuleOff:
		if err := errors.Join(needRule(), needReason()); err != nil {
			return err
		}
		ch.What = fmt.Sprintf("Rule %d off for %s", ch.Rule, app)
	case kindRuleSkip:
		if err := errors.Join(needRule(), needReason()); err != nil {
			return err
		}
		if len(ch.Targets) == 0 || len(ch.Targets) > 20 {
			return errors.New("give 1 to 20 places for the rule to skip, such as ARGS:search")
		}
		for i, t := range ch.Targets {
			ch.Targets[i] = strings.TrimSpace(t)
			if err := engine.CheckTarget(ch.Targets[i]); err != nil {
				return fmt.Errorf("place %q: %v", t, err)
			}
		}
		ch.What = fmt.Sprintf("Rule %d skips %s for %s", ch.Rule, strings.Join(ch.Targets, ", "), app)
	case kindRuleOn:
		if err := needRule(); err != nil {
			return err
		}
		ch.What = fmt.Sprintf("Rule %d back on for %s, without exception", ch.Rule, app)
	case kindSetting:
		if err := needReason(); err != nil {
			return err
		}
		if ch.Setting == "" || ch.Value == nil {
			return errors.New("give the setting and its value")
		}
		ch.What = fmt.Sprintf("CRS setting %s = %q for %s", ch.Setting, *ch.Value, app)
	case kindSettingRemove:
		if ch.Setting == "" {
			return errors.New("give the setting")
		}
		ch.What = fmt.Sprintf("CRS setting %s as the default for %s", ch.Setting, app)
	case kindMode:
		if ch.Mode != profile.ModeMonitor && ch.Mode != profile.ModeAlert {
			return fmt.Errorf("mode %q is not monitor or alert", ch.Mode)
		}
		ch.What = fmt.Sprintf("Mode %s for %s", ch.Mode, app)
	case kindLevel, kindDefaultLevel:
		if ch.Level == nil || *ch.Level < 0 || *ch.Level > engine.MaxParanoiaLevel || ch.Kind == kindDefaultLevel && *ch.Level == 0 {
			return errors.New("give a paranoia level of 1 to 4 (0 for an application: the default)")
		}
		switch {
		case ch.Kind == kindDefaultLevel:
			ch.What = fmt.Sprintf("Default paranoia level %d (for requests of no application, and applications without their own)", *ch.Level)
		case *ch.Level == 0:
			ch.What = fmt.Sprintf("Paranoia level of %s: the default", app)
		default:
			ch.What = fmt.Sprintf("Paranoia level %d for %s", *ch.Level, app)
		}
	case kindHosts:
		if len(ch.Hosts) == 0 || len(ch.Hosts) > 50 {
			return errors.New("give 1 to 50 hosts")
		}
		ch.What = fmt.Sprintf("Hosts of %s: %s", app, strings.Join(ch.Hosts, ", "))
	case kindPaths:
		if len(ch.Paths) > 50 {
			return errors.New("give at most 50 paths")
		}
		ch.What = fmt.Sprintf("Paths of %s: %s", app, orText(strings.Join(ch.Paths, ", "), "every path"))
	case kindRemoveApp:
		ch.What = fmt.Sprintf("Remove the application %s (its profile file is kept)", app)
	case kindProfile:
		if len(ch.Text) == 0 || len(ch.Text) > maxProfileText {
			return fmt.Errorf("the profile must be 1 to %d bytes", maxProfileText)
		}
		ch.What = fmt.Sprintf("The profile of %s, written as a whole", app)
	case kindExclude:
		if err := errors.Join(needRule(), needReason()); err != nil {
			return err
		}
		ch.What = fmt.Sprintf("Rule %d off for every application", ch.Rule)
	case kindInclude:
		if err := needRule(); err != nil {
			return err
		}
		ch.What = fmt.Sprintf("Rule %d back on for every application", ch.Rule)
	case kindFiles:
		if len(ch.Files) == 0 || len(ch.Files) > 100 {
			return errors.New("give 1 to 100 rule files")
		}
		ch.What = fmt.Sprintf("Rule files for every application: %d files", len(ch.Files))
	case kindBodyLimit:
		if ch.Number == nil || *ch.Number < 0 || *ch.Number > httpmodel.MaxBodyLimit {
			return fmt.Errorf("give a body limit of 1 to %d bytes, or 0 for the default", httpmodel.MaxBodyLimit)
		}
		ch.What = fmt.Sprintf("Body limit for every application: %s", orText(bytesText(*ch.Number), "the default"))
	case kindRequireProfile:
		if ch.On == nil {
			return errors.New("say on or off")
		}
		ch.What = "Requests of no application get a no_profile finding: " + onOff(*ch.On)
	case kindRecords:
		if ch.Records == nil {
			return errors.New("give the records settings")
		}
		ch.What = fmt.Sprintf("Records: files of %d MB, %d kept, full requests %s, %d extra secret names", ch.Records.MaxFileMB, ch.Records.KeepFiles, onOff(ch.Records.FullRequests), len(ch.Records.SecretNames))
	case kindLive:
		if ch.Live == nil {
			return errors.New("give the live input settings")
		}
		ch.What = fmt.Sprintf("Live input: %d workers, a queue of %d copies or %d MB, copies up to %d MB", ch.Live.Workers, ch.Live.QueueCopies, ch.Live.QueueMB, ch.Live.MaxFrameMB)
	case kindAddApp:
		if !validAppName(ch.Name) || ch.Name == profile.NoApplication {
			return fmt.Errorf("name %q: use 1 to 64 letters, digits, ., - and _", ch.Name)
		}
		if len(ch.Hosts) == 0 || len(ch.Hosts) > 50 {
			return errors.New("give 1 to 50 hosts")
		}
		ch.What = fmt.Sprintf("Add the application %s for %s, in monitor mode", ch.Name, strings.Join(ch.Hosts, ", "))
	case kindRestore:
		if !validVersionID(ch.Version) {
			return errors.New("give the version to undo")
		}
		ch.What = "Undo version " + ch.Version
	}
	return nil
}

const maxProfileText = 1 << 20

func orText(s, empty string) string {
	if s == "" {
		return empty
	}
	return s
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func bytesText(n int) string {
	switch {
	case n == 0:
		return ""
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MB", n>>20)
	case n%(1<<10) == 0:
		return fmt.Sprintf("%d kB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

// ---- Building the files of a change ----

// workFile is one file a change reads or writes.
type workFile struct {
	path    string
	before  []byte // nil when the file does not exist
	value   *jsonedit.Value
	created bool
	// raw, when set, is the file's new content as given (a restore, or a
	// profile written as a whole).
	raw []byte
}

func (f *workFile) after() []byte {
	if f.raw != nil {
		return f.raw
	}
	return f.value.Marshal()
}

// changed reports whether the change writes the file.
func (f *workFile) changed() bool {
	return f.created || !bytes.Equal(f.before, f.after())
}

// work is a change being built: the configuration and the profiles it
// touches.
type work struct {
	c       *control
	config  *workFile
	files   map[string]*workFile // by path
	order   []string
	undoing string
}

func (c *control) newWork() (*work, error) {
	if c.path == "" {
		return nil, errNoConfig
	}
	w := &work{c: c, files: map[string]*workFile{}}
	f, err := w.file(c.path)
	if err != nil {
		return nil, err
	}
	w.config = f
	return w, nil
}

// file reads a file once.
func (w *work) file(path string) (*workFile, error) {
	if f := w.files[path]; f != nil {
		return f, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := jsonedit.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	f := &workFile{path: path, before: data, value: v}
	w.files[path] = f
	w.order = append(w.order, path)
	return f, nil
}

// value returns a file's value, read again from its raw content when it
// was given as a whole.
func (f *workFile) current() (*jsonedit.Value, error) {
	if f.raw != nil {
		v, err := jsonedit.Parse(f.raw)
		if err != nil {
			return nil, err
		}
		f.value, f.raw = v, nil
	}
	return f.value, nil
}

// apps returns the configuration's application entries.
func (w *work) apps() (*jsonedit.Value, error) {
	cfg, err := w.config.current()
	if err != nil {
		return nil, err
	}
	a := cfg.Get("applications")
	if a == nil {
		return &jsonedit.Value{Kind: jsonedit.Array, Items: []*jsonedit.Value{}}, nil
	}
	if a.Kind != jsonedit.Array {
		return nil, errors.New("the configuration's applications is not a list")
	}
	return a, nil
}

// appEntry returns an application's entry of the configuration.
func (w *work) appEntry(name string) (*jsonedit.Value, error) {
	apps, err := w.apps()
	if err != nil {
		return nil, err
	}
	for _, a := range apps.Items {
		var n string
		if v := a.Get("name"); v != nil && v.Decode(&n) == nil && n == name {
			return a, nil
		}
	}
	return nil, fmt.Errorf("the configuration has no application %s", name)
}

// profilePath returns the path of an application's profile file.
func (w *work) profilePath(name string) (string, error) {
	a, err := w.appEntry(name)
	if err != nil {
		return "", err
	}
	var p string
	if v := a.Get("profile"); v == nil || v.Decode(&p) != nil || p == "" {
		return "", fmt.Errorf("application %s has no profile file", name)
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(w.c.path), p)
	}
	return p, nil
}

// profile returns an application's profile file.
func (w *work) profile(name string) (*workFile, error) {
	p, err := w.profilePath(name)
	if err != nil {
		return nil, err
	}
	return w.file(p)
}

// apply makes one change to the files.
func (w *work) apply(object string, ch pendingChange) error {
	app := objectApp(object)
	switch ch.Kind {
	case kindRestore:
		return w.restore(ch.Version)
	case kindRuleOff, kindRuleSkip, kindRuleOn, kindSetting, kindSettingRemove:
		f, err := w.profile(app)
		if err != nil {
			return err
		}
		p, err := f.current()
		if err != nil {
			return err
		}
		return editExceptions(p, ch)
	case kindMode:
		f, err := w.profile(app)
		if err != nil {
			return err
		}
		p, err := f.current()
		if err != nil {
			return err
		}
		p.SetAfter("mode", jsonedit.Must(ch.Mode), "note")
	case kindLevel:
		f, err := w.profile(app)
		if err != nil {
			return err
		}
		p, err := f.current()
		if err != nil {
			return err
		}
		if *ch.Level == 0 {
			p.Delete("paranoia_level")
		} else {
			p.SetAfter("paranoia_level", jsonedit.Must(*ch.Level), "mode", "note")
		}
	case kindProfile:
		f, err := w.profile(app)
		if err != nil {
			return err
		}
		if _, err := jsonedit.Parse([]byte(ch.Text)); err != nil {
			return fmt.Errorf("the profile is not JSON: %v", err)
		}
		f.raw = []byte(ch.Text)
		if !bytes.HasSuffix(f.raw, []byte("\n")) {
			f.raw = append(f.raw, '\n')
		}
	case kindHosts, kindPaths:
		a, err := w.appEntry(app)
		if err != nil {
			return err
		}
		if ch.Kind == kindHosts {
			a.Set("hosts", jsonedit.Must(ch.Hosts))
		} else if len(ch.Paths) == 0 {
			a.Delete("paths")
		} else {
			a.SetAfter("paths", jsonedit.Must(ch.Paths), "hosts")
		}
	case kindRemoveApp:
		if _, err := w.appEntry(app); err != nil {
			return err
		}
		apps, _ := w.apps()
		cfg, _ := w.config.current()
		apps.Items = slices.DeleteFunc(apps.Items, func(a *jsonedit.Value) bool {
			var n string
			return a.Get("name").Decode(&n) == nil && n == app
		})
		if len(apps.Items) == 0 {
			cfg.Delete("applications")
		}
	default:
		return w.applyGlobal(ch)
	}
	return nil
}

// editExceptions changes a profile's rule exceptions (F5): one exception
// per rule, and one per CRS setting.
func editExceptions(p *jsonedit.Value, ch pendingChange) error {
	list := p.Get("exceptions")
	if list == nil {
		list = &jsonedit.Value{Kind: jsonedit.Array, Items: []*jsonedit.Value{}}
		p.SetAfter("exceptions", list, "headers", "cookies", "endpoints", "paranoia_level", "mode", "note")
	}
	if list.Kind != jsonedit.Array {
		return errors.New("the profile's exceptions is not a list")
	}
	ruleOf := func(e *jsonedit.Value) int {
		var n int
		if v := e.Get("rule"); v != nil {
			v.Decode(&n)
		}
		return n
	}
	settingOf := func(e *jsonedit.Value) string {
		var s string
		if v := e.Get("setting"); v != nil {
			v.Decode(&s)
		}
		return s
	}
	i := -1
	for j, e := range list.Items {
		if ch.Setting != "" && settingOf(e) == ch.Setting || ch.Setting == "" && ch.Rule != 0 && ruleOf(e) == ch.Rule {
			i = j
		}
	}
	put := func(e *jsonedit.Value) {
		if i >= 0 {
			list.Items[i] = e
		} else {
			list.Items = append(list.Items, e)
		}
	}
	switch ch.Kind {
	case kindRuleOff:
		e := &jsonedit.Value{Kind: jsonedit.Object}
		e.Set("rule", jsonedit.Must(ch.Rule))
		e.Set("off", jsonedit.Must(true))
		e.Set("reason", jsonedit.Must(ch.Reason))
		put(e)
	case kindRuleSkip:
		targets := slices.Clone(ch.Targets)
		if i >= 0 && list.Items[i].Get("skip") != nil {
			var old []string
			list.Items[i].Get("skip").Decode(&old)
			targets = append(old, targets...)
		}
		slices.Sort(targets)
		targets = slices.Compact(targets)
		e := &jsonedit.Value{Kind: jsonedit.Object}
		e.Set("rule", jsonedit.Must(ch.Rule))
		e.Set("skip", jsonedit.Must(targets))
		e.Set("reason", jsonedit.Must(ch.Reason))
		put(e)
	case kindSetting:
		e := &jsonedit.Value{Kind: jsonedit.Object}
		e.Set("setting", jsonedit.Must(ch.Setting))
		e.Set("value", jsonedit.Must(*ch.Value))
		e.Set("reason", jsonedit.Must(ch.Reason))
		put(e)
	case kindRuleOn, kindSettingRemove:
		if i < 0 {
			if ch.Kind == kindRuleOn {
				return fmt.Errorf("rule %d has no exception to take back", ch.Rule)
			}
			return fmt.Errorf("the setting %s has no exception to take back", ch.Setting)
		}
		list.Items = slices.Delete(list.Items, i, i+1)
	}
	if len(list.Items) == 0 {
		p.Delete("exceptions")
	}
	return nil
}

// applyGlobal makes a change for every application.
func (w *work) applyGlobal(ch pendingChange) error {
	cfg, err := w.config.current()
	if err != nil {
		return err
	}
	switch ch.Kind {
	case kindDefaultLevel:
		cfg.SetAfter("paranoia_level", jsonedit.Must(*ch.Level), "exclude", "files")
	case kindExclude, kindInclude:
		list := cfg.Get("exclude")
		if list == nil {
			list = &jsonedit.Value{Kind: jsonedit.Array, Items: []*jsonedit.Value{}}
			cfg.SetAfter("exclude", list, "files")
		}
		i := slices.IndexFunc(list.Items, func(e *jsonedit.Value) bool {
			var n int
			return e.Get("id") != nil && e.Get("id").Decode(&n) == nil && n == ch.Rule
		})
		if ch.Kind == kindInclude {
			if i < 0 {
				return fmt.Errorf("rule %d is not off for every application", ch.Rule)
			}
			list.Items = slices.Delete(list.Items, i, i+1)
			if len(list.Items) == 0 {
				cfg.Delete("exclude")
			}
			return nil
		}
		e := &jsonedit.Value{Kind: jsonedit.Object}
		e.Set("id", jsonedit.Must(ch.Rule))
		e.Set("reason", jsonedit.Must(ch.Reason))
		if i >= 0 {
			list.Items[i] = e
		} else {
			list.Items = append(list.Items, e)
		}
	case kindFiles:
		cfg.Set("files", jsonedit.Must(ch.Files))
	case kindBodyLimit:
		if *ch.Number == 0 {
			cfg.Delete("request_body_limit")
		} else {
			cfg.SetAfter("request_body_limit", jsonedit.Must(*ch.Number), "paranoia_level", "exclude", "files")
		}
	case kindRequireProfile:
		if *ch.On {
			cfg.SetAfter("require_profile", jsonedit.Must(true), "applications")
		} else {
			cfg.Delete("require_profile")
		}
	case kindRecords:
		rec := cfg.Get("records")
		if rec == nil {
			return errors.New("the configuration has no records section, so it has no records folder; add one by hand first")
		}
		rec.Set("max_file_mb", jsonedit.Must(ch.Records.MaxFileMB))
		rec.Set("keep_files", jsonedit.Must(ch.Records.KeepFiles))
		rec.Set("full_requests", jsonedit.Must(ch.Records.FullRequests))
		names := ch.Records.SecretNames
		if names == nil {
			names = []string{}
		}
		rec.Set("secret_names", jsonedit.Must(names))
	case kindLive:
		live := cfg.Get("live")
		if live == nil {
			live = &jsonedit.Value{Kind: jsonedit.Object}
			cfg.Set("live", live)
		}
		live.Set("workers", jsonedit.Must(ch.Live.Workers))
		live.Set("queue_copies", jsonedit.Must(ch.Live.QueueCopies))
		live.Set("queue_mb", jsonedit.Must(ch.Live.QueueMB))
		live.Set("max_frame_mb", jsonedit.Must(ch.Live.MaxFrameMB))
	case kindAddApp:
		return w.addApp(ch)
	default:
		return fmt.Errorf("kind %q is not a change for every application", ch.Kind)
	}
	return nil
}

// newProfile is the profile of an application added in the dashboard: it
// allows every path, in monitor mode, until its profile is written.
func newProfile(name string, at time.Time) []byte {
	v := &jsonedit.Value{Kind: jsonedit.Object}
	v.Set("note", jsonedit.Must(fmt.Sprintf("The profile of %s, made by the dashboard on %s. It allows every path and parameter until its endpoints are written; in monitor mode its findings are recorded, not alerts.", name, at.Format("2 January 2006"))))
	v.Set("mode", jsonedit.Must(profile.ModeMonitor))
	ep := &jsonedit.Value{Kind: jsonedit.Object}
	ep.Set("note", jsonedit.Must("Every path, until the endpoints are written"))
	ep.Set("methods", jsonedit.Must([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}))
	ep.Set("path", jsonedit.Must("/*"))
	ep.Set("other_params", jsonedit.Must("allow"))
	v.Set("endpoints", &jsonedit.Value{Kind: jsonedit.Array, Items: []*jsonedit.Value{ep}})
	return v.Marshal()
}

// addApp adds an application with a new profile file, in the folder of the
// other profiles, or a "profiles" folder beside the configuration's.
func (w *work) addApp(ch pendingChange) error {
	if _, err := w.appEntry(ch.Name); err == nil {
		return fmt.Errorf("the application %s exists already", ch.Name)
	}
	apps, err := w.apps()
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(filepath.Dir(w.c.path)), "profiles")
	for _, a := range apps.Items {
		var n string
		if a.Get("name").Decode(&n) == nil {
			if p, err := w.profilePath(n); err == nil {
				dir = filepath.Dir(p)
				break
			}
		}
	}
	path := filepath.Join(dir, ch.Name+".json")
	rel, err := filepath.Rel(filepath.Dir(w.c.path), path)
	if err != nil {
		rel = path
	}
	if _, err := os.Stat(path); err == nil {
		// A profile of this name is there already, perhaps from an
		// application removed earlier: it is used as it is.
		if _, err := w.file(path); err != nil {
			return err
		}
	} else {
		f := &workFile{path: path, created: true, raw: newProfile(ch.Name, w.c.now())}
		w.files[path] = f
		w.order = append(w.order, path)
	}
	e := &jsonedit.Value{Kind: jsonedit.Object}
	e.Set("name", jsonedit.Must(ch.Name))
	e.Set("hosts", jsonedit.Must(ch.Hosts))
	if len(ch.Paths) > 0 {
		e.Set("paths", jsonedit.Must(ch.Paths))
	}
	e.Set("profile", jsonedit.Must(filepath.ToSlash(rel)))
	cfg, _ := w.config.current()
	if cfg.Get("applications") == nil {
		apps = &jsonedit.Value{Kind: jsonedit.Array, Items: []*jsonedit.Value{}}
		cfg.SetAfter("applications", apps, "records", "request_body_limit", "paranoia_level", "exclude", "files")
	}
	apps.Items = append(apps.Items, e)
	return nil
}

// restore gives each file of a version its content from before it.
func (w *work) restore(id string) error {
	v, err := w.c.readVersion(id)
	if err != nil {
		return err
	}
	w.undoing = id
	for i, vf := range v.Files {
		if vf.Created {
			// A file the version made stays; the configuration that
			// named it is restored, so nothing reads it.
			continue
		}
		before, err := os.ReadFile(filepath.Join(w.c.stateDir, VersionsDir, id, "before-"+strconv.Itoa(i)))
		if err != nil {
			return fmt.Errorf("version %s: %w", id, err)
		}
		f := w.files[vf.Path]
		if f == nil {
			data, err := os.ReadFile(vf.Path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			f = &workFile{path: vf.Path, before: data, created: data == nil}
			w.files[vf.Path] = f
			w.order = append(w.order, vf.Path)
		}
		f.raw = before
	}
	return nil
}

// built is the outcome of a change: the files it writes, checked.
type built struct {
	files   []*workFile
	product *config.Product
	undoing string
}

// build makes the changes of list on the files as they are now and reads
// the outcome with the IDS's own configuration reader, which also reads
// the profiles. check does the rest.
func (c *control) build(object string, list []pendingChange) (*built, error) {
	w, err := c.newWork()
	if err != nil {
		return nil, err
	}
	for _, ch := range list {
		if err := w.apply(object, ch); err != nil {
			return nil, fmt.Errorf("%s: %w", ch.What, err)
		}
	}
	b := &built{undoing: w.undoing}
	contents := map[string][]byte{}
	for _, p := range w.order {
		f := w.files[p]
		contents[p] = f.after()
		if f.changed() {
			b.files = append(b.files, f)
		}
	}
	read := func(path string) ([]byte, error) {
		if data, ok := contents[path]; ok {
			return data, nil
		}
		return os.ReadFile(path)
	}
	product, err := config.Parse(c.path, contents[c.path], read)
	if err != nil {
		return nil, fmt.Errorf("the configuration would not load: %w", err)
	}
	b.product = product
	return b, nil
}

// check loads the rules of a built change and prepares its applications,
// as ids-live will: what the configuration reader can't see, such as an
// exception of a rule that is in no loaded file, is found here.
func (c *control) check(b *built) error {
	rules, err := c.loadRules(b.product.Config)
	if err != nil {
		return fmt.Errorf("the rules would not load: %w", err)
	}
	if _, err := profile.NewSet(rules, b.product.Applications, b.product.RequireProfile); err != nil {
		return fmt.Errorf("the applications would not load: %w", err)
	}
	return nil
}

// ---- Applying (W11, W12) ----

// applied is what apply did.
type applied struct {
	Version version `json:"version"`
	// Unchanged is true when the changes left every file as it was.
	Unchanged bool `json:"unchanged,omitempty"`
}

// apply applies an object's pending changes together, as one version.
func (c *control) apply(object, user, reason string) (applied, error) {
	if c.path == "" {
		return applied{}, errNoConfig
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	lock, err := lockFile(c.lockPath(), true)
	if err != nil {
		return applied{}, fmt.Errorf("the configuration is being changed by another program: %w", err)
	}
	defer unlockFile(lock)

	p, err := c.readPending()
	if err != nil {
		return applied{}, err
	}
	list := p.Objects[object]
	if len(list) == 0 {
		return applied{}, fmt.Errorf("%s has no pending changes", reach(object))
	}
	b, err := c.build(object, list)
	if err != nil {
		return applied{}, err
	}
	if err := c.check(b); err != nil {
		return applied{}, err
	}
	v := version{Object: object, Time: c.now().UTC(), User: user, Reason: reason, Items: list, Undoes: b.undoing}
	if len(b.files) == 0 {
		delete(p.Objects, object)
		return applied{Version: v, Unchanged: true}, c.writePending(p)
	}
	if err := c.saveVersion(&v, b.files); err != nil {
		return applied{}, err
	}
	// The IDS's files last, each in one rename: a reader sees the old file
	// or the new one, never half of one.
	for _, f := range b.files {
		mode := os.FileMode(0o644)
		if info, err := os.Stat(f.path); err == nil {
			mode = info.Mode().Perm()
		}
		if f.created {
			if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
				return applied{}, err
			}
		}
		if err := writeFileAtomic(f.path, f.after(), mode); err != nil {
			return applied{}, fmt.Errorf("%s could not be written: %w; the files before it are written, and version %s keeps them all", f.path, err, v.ID)
		}
	}
	if fp, err := b.product.Fingerprint(b.product.Level()); err == nil {
		v.Fingerprint = fp
		c.writeMeta(v)
	}
	delete(p.Objects, object)
	return applied{Version: v}, c.writePending(p)
}

// lockPath is the file locked while the configuration is written, beside
// it, so that two dashboards never write it at once.
func (c *control) lockPath() string {
	return filepath.Join(filepath.Dir(c.path), "."+filepath.Base(c.path)+".lock")
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// saveVersion keeps the files of a change before and after it, and gives v
// its ID and number.
func (c *control) saveVersion(v *version, files []*workFile) error {
	dir := filepath.Join(c.stateDir, VersionsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	list, err := c.versions("")
	if err != nil {
		return err
	}
	v.Seq = 1
	if len(list) > 0 {
		v.Seq = list[0].Seq + 1
	}
	v.ID = fmt.Sprintf("%06d-%s", v.Seq, strings.ToLower(rand.Text()[:6]))
	vdir := filepath.Join(dir, v.ID)
	if err := os.Mkdir(vdir, 0o700); err != nil {
		return err
	}
	for i, f := range files {
		vf := versionFile{Path: f.path, Created: f.created, After: sha(f.after())}
		if !f.created {
			vf.Before = sha(f.before)
			if err := os.WriteFile(filepath.Join(vdir, "before-"+strconv.Itoa(i)), f.before, 0o600); err != nil {
				return err
			}
		}
		if err := os.WriteFile(filepath.Join(vdir, "after-"+strconv.Itoa(i)), f.after(), 0o600); err != nil {
			return err
		}
		v.Files = append(v.Files, vf)
	}
	return c.writeMeta(*v)
}

func (c *control) writeMeta(v version) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.stateDir, VersionsDir, v.ID, "meta.json"), append(data, '\n'), 0o600)
}

func validVersionID(id string) bool {
	if len(id) != 13 || id[6] != '-' {
		return false
	}
	for i, r := range id {
		if i == 6 {
			continue
		}
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

var errNoVersion = errors.New("no such version")

func (c *control) readVersion(id string) (version, error) {
	if !validVersionID(id) {
		return version{}, errNoVersion
	}
	data, err := os.ReadFile(filepath.Join(c.stateDir, VersionsDir, id, "meta.json"))
	if errors.Is(err, os.ErrNotExist) {
		return version{}, errNoVersion
	}
	if err != nil {
		return version{}, err
	}
	var v version
	if err := json.Unmarshal(data, &v); err != nil {
		return version{}, fmt.Errorf("version %s: %w", id, err)
	}
	return v, nil
}

// versions returns the versions of an object, newest first; every version
// when object is "".
func (c *control) versions(object string) ([]version, error) {
	entries, err := os.ReadDir(filepath.Join(c.stateDir, VersionsDir))
	if errors.Is(err, os.ErrNotExist) {
		return []version{}, nil
	}
	if err != nil {
		return nil, err
	}
	list := []version{}
	for _, e := range entries {
		if !e.IsDir() || !validVersionID(e.Name()) {
			continue
		}
		v, err := c.readVersion(e.Name())
		if err != nil {
			continue
		}
		if object == "" || v.Object == object {
			list = append(list, v)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Seq > list[j].Seq })
	return list, nil
}

// laterChanges returns the versions after v that changed one of its files,
// oldest first: undoing v also takes back what they did to those files.
func (c *control) laterChanges(v version) ([]version, error) {
	all, err := c.versions("")
	if err != nil {
		return nil, err
	}
	var later []version
	for i := len(all) - 1; i >= 0; i-- {
		o := all[i]
		if o.Seq <= v.Seq {
			continue
		}
		if slices.ContainsFunc(o.Files, func(f versionFile) bool {
			return slices.ContainsFunc(v.Files, func(g versionFile) bool { return g.Path == f.Path })
		}) {
			later = append(later, o)
		}
	}
	return later, nil
}

// writeFileAtomic writes data to a new file beside path and renames it over
// path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, mode)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}
