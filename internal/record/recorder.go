package record

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/result"
	"github.com/EfeSipahi/ids-system/internal/version"
)

// KeyFile is the file in the record directory that holds the key of the
// cookie hashes. It is made on the first run and kept, so the same cookie
// gives the same hash across runs.
const KeyFile = "hash.key"

// countsInterval is how often a counts record is written while requests
// arrive.
const countsInterval = time.Minute

// Recorder writes the records of one run of the IDS. It is safe for use by
// many goroutines.
type Recorder struct {
	w *writer
	b builder
	// apps holds the builder of each application, whose masker also knows
	// the profile's secrets (F8). profiled is true when there are
	// applications.
	apps     map[*profile.App]builder
	profiled bool
	run      string
	now      func() time.Time

	mu     sync.Mutex
	counts Counts
}

// NewEngine describes the running engine for the records. fingerprint
// identifies the configuration and rule files (see config.Product).
func NewEngine(rs *engine.RuleSet, fingerprint string) Engine {
	return Engine{
		Version:       version.Version,
		Revision:      version.Revision(),
		CRS:           rs.Signature(),
		ParanoiaLevel: rs.ParanoiaLevel(),
		Config:        fingerprint,
	}
}

// Open starts a run: it opens the record files of cfg.Dir and writes the
// start record, with the status of every rule and the applications of
// apps. apps may be nil when the configuration has no applications.
func Open(cfg Config, eng Engine, statuses []engine.RuleStatus, apps *profile.Set) (*Recorder, error) {
	return open(cfg, eng, statuses, apps, time.Now)
}

func open(cfg Config, eng Engine, statuses []engine.RuleStatus, apps *profile.Set, now func() time.Time) (*Recorder, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	w, err := openWriter(cfg.Dir, int64(cfg.MaxFileMB)<<20, cfg.KeepFiles, now)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	key, err := loadKey(filepath.Join(cfg.Dir, KeyFile))
	if err != nil {
		w.close()
		return nil, fmt.Errorf("records: %w", err)
	}
	r := &Recorder{
		w:   w,
		b:   builder{masker: newMasker(cfg.SecretNames, key), full: cfg.FullRequests, engine: eng},
		run: newID(),
		now: now,
	}
	start := Start{Type: TypeStart, Schema: Schema, Run: r.run, Time: now().UTC(), Engine: eng, Rules: []Rule{}}
	if apps != nil && len(apps.Apps()) > 0 {
		r.profiled = true
		r.apps = map[*profile.App]builder{}
		for _, a := range apps.Apps() {
			b := r.b
			b.masker = b.masker.forProfile(a.Profile)
			r.apps[a] = b
		}
		start.Applications = result.AppStartups(apps)
		start.RequireProfile = apps.RequireProfile()
	}
	for _, st := range statuses {
		start.Rules = append(start.Rules, Rule{
			ID:            st.ID,
			File:          filepath.Base(st.Pos.File),
			Line:          st.Pos.Line,
			Phase:         st.Phase,
			ParanoiaLevel: st.ParanoiaLevel,
			Msg:           st.Msg,
			Active:        st.Active,
			Reason:        st.Reason,
		})
	}
	if err := w.setHeader(start); err != nil {
		w.close()
		return nil, fmt.Errorf("records: %w", err)
	}
	r.counts = Counts{Type: TypeCounts, Schema: Schema, Run: r.run, From: start.Time}
	return r, nil
}

// Run returns the ID of this run, which every record of it carries.
func (r *Recorder) Run() string {
	return r.run
}

// Add counts one analysed request and writes its record when it gets one
// (R1). req must be the request as the rules of phase 2 saw it, which is
// res.Request. prof is the result of checking req against its application's
// profile; it is nil when the configuration has no applications.
func (r *Recorder) Add(req *httpmodel.Request, res *engine.Result, prof *profile.Result) error {
	if r.profiled && prof == nil {
		prof = &profile.Result{BodyChecked: req.Status.Body.Complete()}
	}
	b := r.b
	if prof != nil && prof.App != nil {
		if ab, ok := r.apps[prof.App]; ok {
			b = ab
		} else {
			b.masker = b.masker.forProfile(prof.App.Profile)
		}
	}
	now := r.now()
	wanted := Wanted(req, res, prof)
	var rec Request
	if wanted {
		rec = b.build(req, res, prof, newID(), r.run, now)
		if err := r.w.write(rec); err != nil {
			return fmt.Errorf("records: %w", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts.Analysed++
	if wanted {
		r.counts.Recorded++
		if rec.Alert {
			r.counts.Alerts++
		}
	}
	if !req.Status.Body.Complete() {
		r.counts.Incomplete++
	}
	if prof != nil && prof.App == nil {
		r.counts.NoProfile++
	}
	if now.Sub(r.counts.From) >= countsInterval {
		return r.flushLocked(now)
	}
	return nil
}

// Flush writes the counts since the last counts record. A service calls it
// from time to time, so that quiet periods are counted too.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked(r.now())
}

func (r *Recorder) flushLocked(now time.Time) error {
	r.counts.To = now.UTC()
	if err := r.w.write(r.counts); err != nil {
		return fmt.Errorf("records: %w", err)
	}
	r.counts = Counts{Type: TypeCounts, Schema: Schema, Run: r.run, From: r.counts.To}
	return nil
}

// Close writes the last counts record and closes the file.
func (r *Recorder) Close() error {
	err := r.Flush()
	return errors.Join(err, r.w.close())
}

// newID returns a random ID of 26 letters and digits.
func newID() string {
	return strings.ToLower(rand.Text())
}

// loadKey reads the hash key, or makes one when the file does not exist.
func loadKey(path string) ([]byte, error) {
	text, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		rand.Read(key)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
			f.Close()
			return nil, err
		}
		return key, f.Close()
	}
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: not a key of 64 hex digits", path)
	}
	return key, nil
}
