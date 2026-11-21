package dashboard

// The dashboard's side of changing the IDS: who may do what (W9), the
// password asked again for the widest changes (W10), the change log, and
// whether ids-live runs what was applied (W13).

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// The change log's actions of changes to the IDS.
const (
	actionChangeAdded      = "change_added"
	actionChangeProposed   = "change_proposed"
	actionChangeDropped    = "change_dropped"
	actionChangeTurnedDown = "change_turned_down"
	actionChangesApplied   = "changes_applied"
)

// maxChangeBody is the largest request of the changes API: a profile
// written as a whole is at most 1 MiB.
const maxChangeBody = 2 << 20

// changeRequest is a request of POST /api/changes.
type changeRequest struct {
	Action   string         `json:"action"`
	Object   string         `json:"object"`
	Change   *pendingChange `json:"change,omitempty"`
	ID       string         `json:"id,omitempty"`
	Version  string         `json:"version,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	Password string         `json:"password,omitempty"`
}

// changesAnswer is an object's pending changes, with what the user may do
// with them.
type changesAnswer struct {
	Object     string          `json:"object"`
	Reach      string          `json:"reach"`
	Configured bool            `json:"configured"`
	Items      []pendingChange `json:"items"`
	// Propose, Apply and Password say whether the user may propose and
	// apply changes, and whether applying asks for the password (W9,
	// W10).
	Propose  bool `json:"propose"`
	Apply    bool `json:"apply"`
	Password bool `json:"password"`
}

func (s *Server) apiChanges(w http.ResponseWriter, r *http.Request) {
	object := r.URL.Query().Get("object")
	if err := checkObject(object); err != nil {
		badRequest(w, err)
		return
	}
	role := s.auth.users.role(s.auth.user(sessionToken(r)))
	a := changesAnswer{Object: object, Reach: reach(object), Configured: s.control.path != "", Items: []pendingChange{},
		Propose: allows(role, RoleAnalyst), Apply: allows(role, RoleAdmin), Password: object == objectGlobal}
	if a.Configured {
		list, err := s.control.pending(object)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.Items = list
	}
	writeJSON(w, http.StatusOK, a)
}

// apiProposals lists every object's pending changes, for the admins' list
// of proposals (W9).
func (s *Server) apiProposals(w http.ResponseWriter, r *http.Request) {
	all, err := s.control.allPending()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if all == nil {
		all = map[string][]pendingChange{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": all, "configured": s.control.path != ""})
}

func (s *Server) apiChangesPost(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	role := s.auth.users.role(user)
	var cr changeRequest
	if err := readJSON(w, r, maxChangeBody, &cr); err != nil {
		badRequest(w, err)
		return
	}
	if s.control.path == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": errNoConfig.Error()})
		return
	}
	admin := allows(role, RoleAdmin)
	refuse := func(msg string) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
	}
	if cr.Action == "undo" {
		v, err := s.control.readVersion(cr.Version)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such version"})
			return
		}
		cr.Object = v.Object
		cr.Action = "add"
		cr.Change = &pendingChange{Kind: kindRestore, Version: v.ID}
	}
	if err := checkObject(cr.Object); err != nil {
		badRequest(w, err)
		return
	}
	cr.Reason = strings.TrimSpace(cr.Reason)
	switch cr.Action {
	case "add":
		if cr.Change == nil {
			badRequest(w, errors.New("give the change"))
			return
		}
		ch := *cr.Change
		ch.User, ch.Proposal, ch.ID, ch.What = user, !admin, "", ""
		if !admin && (cr.Object == objectGlobal || !slices.Contains(analystKinds, ch.Kind)) {
			refuse("an analyst may propose a rule exception for an application; other changes need an admin")
			return
		}
		ch, err := s.control.add(cr.Object, ch)
		if err != nil {
			s.controlError(w, err)
			return
		}
		action := actionChangeAdded
		if ch.Proposal {
			action = actionChangeProposed
		}
		s.logChange(change{User: user, Action: action, Object: cr.Object, What: []string{ch.What}, Reason: ch.Reason})
		writeJSON(w, http.StatusOK, ch)
	case "drop", "turn_down":
		list, err := s.control.pending(cr.Object)
		if err != nil {
			s.controlError(w, err)
			return
		}
		i := slices.IndexFunc(list, func(x pendingChange) bool { return x.ID == cr.ID })
		if i < 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": errNoPending.Error()})
			return
		}
		ch := list[i]
		switch {
		case cr.Action == "turn_down" && !admin:
			refuse("only an admin turns a proposal down")
			return
		case cr.Action == "turn_down" && cr.Reason == "":
			badRequest(w, errors.New("say why the proposal is turned down"))
			return
		case !admin && (!ch.Proposal || ch.User != user):
			refuse("an analyst may drop only their own proposals")
			return
		}
		if _, err := s.control.drop(cr.Object, cr.ID); err != nil {
			s.controlError(w, err)
			return
		}
		action := actionChangeDropped
		if cr.Action == "turn_down" {
			action = actionChangeTurnedDown
		}
		s.logChange(change{User: user, Action: action, Object: cr.Object, What: []string{ch.What}, Target: ch.User, Reason: cr.Reason})
		writeJSON(w, http.StatusOK, map[string]string{"dropped": ch.ID})
	case "apply":
		if !admin {
			refuse("only an admin applies changes; an analyst's changes wait as proposals")
			return
		}
		if cr.Reason == "" {
			badRequest(w, errors.New("give a reason for the change: the change log and the version keep it"))
			return
		}
		if cr.Object == objectGlobal && !s.confirm(w, r, user, cr.Password) {
			return
		}
		a, err := s.control.apply(cr.Object, user, cr.Reason)
		if err != nil {
			s.controlError(w, err)
			return
		}
		what := []string{}
		for _, ch := range a.Version.Items {
			what = append(what, ch.What)
		}
		s.logChange(change{User: user, Action: actionChangesApplied, Object: cr.Object, What: what, Reason: cr.Reason, Version: a.Version.ID})
		writeJSON(w, http.StatusOK, a)
	default:
		badRequest(w, fmt.Errorf("action %q is not add, drop, turn_down, apply or undo", cr.Action))
	}
}

// controlError answers an error of the control: a change that can't be
// made is the user's to correct.
func (s *Server) controlError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNoPending), errors.Is(err, errNoVersion):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, errInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
	}
}

// logChange writes a change log entry; a failure is logged, as the change
// itself is made.
func (s *Server) logChange(c change) {
	c.Time = s.now()
	if _, err := s.changes.add(c); err != nil {
		s.log.Printf("change log: %v", err)
	}
}

func (s *Server) apiPreview(w http.ResponseWriter, r *http.Request) {
	object := r.URL.Query().Get("object")
	if err := checkObject(object); err != nil {
		badRequest(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.preview(object))
}

// preview works out what an object's pending changes would do (W8).
func (s *Server) preview(object string) preview {
	p := preview{Object: object, Reach: reach(object), ByRule: []item{}, Examples: []row{}, Untested: []string{}}
	if s.control.path == "" {
		p.Error = errNoConfig.Error()
		return p
	}
	list, err := s.control.pending(object)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Changes = len(list)
	if len(list) == 0 {
		return p
	}
	before, err := config.Load(s.control.path)
	if err != nil {
		p.Error = "the configuration on disk does not load: " + err.Error()
		return p
	}
	b, err := s.control.build(object, list)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	out := s.store.previewChanges(object, before, b.product)
	out.Changes = len(list)
	return out
}

// versionRow is a version on a History tab.
type versionRow struct {
	version
	// Current is true while the files are as the version wrote them.
	Current bool `json:"current"`
	// Live is when ids-live started running the version's configuration,
	// if it did.
	Live time.Time `json:"live,omitzero"`
	// Later counts the versions after it that changed one of its files.
	Later int `json:"later"`
}

func (s *Server) apiVersions(w http.ResponseWriter, r *http.Request) {
	object := r.URL.Query().Get("object")
	if object != "" {
		if err := checkObject(object); err != nil {
			badRequest(w, err)
			return
		}
	}
	list, err := s.control.versions(object)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := []versionRow{}
	for _, v := range list {
		row := versionRow{version: v, Current: true}
		for _, f := range v.Files {
			data, err := os.ReadFile(f.Path)
			if err != nil || sha(data) != f.After {
				row.Current = false
			}
		}
		row.Live = s.store.liveSince(v.Fingerprint, v.Time)
		if later, err := s.control.laterChanges(v); err == nil {
			row.Later = len(later)
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": rows})
}

// controlState is what the Engine page and the change panels say about
// the configuration on disk and what ids-live runs (W13).
type controlState struct {
	Configured bool `json:"configured"`
	// File is the configuration's file name.
	File string `json:"file,omitempty"`
	// OnDisk is the fingerprint of the files as they are; Error says why
	// they don't load.
	OnDisk string `json:"on_disk,omitempty"`
	Error  string `json:"error,omitempty"`
	// Running is the fingerprint of the newest live run, and Taken is
	// true when it is that of the files on disk, since Since.
	Running string    `json:"running,omitempty"`
	Taken   bool      `json:"taken"`
	Since   time.Time `json:"since,omitzero"`
	// LiveRun is the newest live run's state.
	Live *liveStatus `json:"live,omitempty"`
}

// diskState caches the fingerprint of the files on disk for a moment: the
// pages ask every few seconds, and it reads every rule file.
type diskState struct {
	mu   sync.Mutex
	at   time.Time
	fp   string
	err  string
	path string
}

func (d *diskState) get(path string, now time.Time) (string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.path == path && now.Sub(d.at) < 3*time.Second && now.After(d.at) {
		return d.fp, d.err
	}
	d.path, d.at, d.fp, d.err = path, now, "", ""
	p, err := config.Load(path)
	if err == nil {
		d.fp, err = p.Fingerprint(p.Level())
	}
	if err != nil {
		d.err = err.Error()
	}
	return d.fp, d.err
}

func (s *Server) apiControl(w http.ResponseWriter, r *http.Request) {
	st := controlState{Configured: s.control.path != ""}
	if st.Configured {
		st.File = filepath.Base(s.control.path)
		st.OnDisk, st.Error = s.disk.get(s.control.path, time.Now())
	}
	st.Running, st.Since, st.Live = s.store.newestLive(s.now())
	if st.Running != "" && st.Running == st.OnDisk {
		st.Taken = true
	}
	writeJSON(w, http.StatusOK, st)
}

// newestLive returns the fingerprint of the newest live run, since when it
// runs, and its state.
func (s *store) newestLive(now time.Time) (string, time.Time, *liveStatus) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var newest record.Start
	for _, run := range s.runs {
		st := s.starts[run]
		if st.Input != nil && st.Input.Kind == record.InputLive && st.Time.After(newest.Time) {
			newest = st
		}
	}
	if newest.Run == "" {
		return "", time.Time{}, nil
	}
	var o overview
	s.liveParts(&o, timeRange{From: now.Add(-time.Hour), To: now})
	return newest.Engine.Config, newest.Time, o.Live
}

// liveSince returns when the first live run of fingerprint started after
// at, or the zero time.
func (s *store) liveSince(fingerprint string, at time.Time) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var since time.Time
	for _, run := range s.runs {
		st := s.starts[run]
		if st.Input != nil && st.Input.Kind == record.InputLive && st.Engine.Config == fingerprint && !st.Time.Before(at.Add(-time.Second)) {
			if since.IsZero() || st.Time.Before(since) {
				since = st.Time
			}
		}
	}
	return since
}
