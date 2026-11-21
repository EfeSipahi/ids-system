package dashboard

// Users, one's own password, and the change log (G4, G5 of
// docs/development-plan-marks-users.md). Everything here writes only the
// dashboard's state folder (C1).

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Files of the state folder (G6).
const (
	// ChangesFile is the change log: one JSON line per action.
	ChangesFile = "changes.jsonl"
	// stateLockFile is held by the running dashboard (C4).
	stateLockFile = "dashboard.lock"
)

// The actions of the change log.
const (
	actionMark            = "mark"
	actionUserAdded       = "user_added"
	actionUserRemoved     = "user_removed"
	actionRoleChanged     = "role_changed"
	actionPasswordReset   = "password_reset"
	actionPasswordChanged = "password_changed"
)

// change is one line of the change log. It never holds a password.
type change struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	// Target is the user a user change is about.
	Target  string `json:"target,omitempty"`
	Role    string `json:"role,omitempty"`
	OldRole string `json:"old_role,omitempty"`
	// A mark: the verdict and note given, how many records, the list's
	// filter or the records chosen, and how many of them had each verdict
	// before (G5).
	Verdict string         `json:"verdict,omitempty"`
	Note    string         `json:"note,omitempty"`
	Records int            `json:"records,omitempty"`
	Filter  string         `json:"filter,omitempty"`
	IDs     []string       `json:"ids,omitempty"`
	Before  map[string]int `json:"before,omitempty"`
	// A change to the IDS (W7–W11): its object, what it does, its
	// reason, and the version it made.
	Object  string   `json:"object,omitempty"`
	What    []string `json:"what,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Version string   `json:"version,omitempty"`
}

// changeLog appends to the change log. It is only ever appended to (G5).
type changeLog struct {
	path string
	mu   sync.Mutex
}

func (l *changeLog) add(c change) (change, error) {
	if c.ID == "" {
		c.ID = rand.Text()
	}
	c.Time = c.Time.UTC()
	line, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return c, err
	}
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return c, err
}

// logEntry is a line of the Log page: a change or a login.
type logEntry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	Kind   string    `json:"kind"` // "change" or "login"
	Change *change   `json:"change,omitempty"`
	// Result and IP are those of a login line.
	Result string `json:"result,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// logPage is a page of the Log.
type logPage struct {
	Entries []logEntry `json:"entries"`
	Total   int        `json:"total"`
	Page    int        `json:"page"`
	Pages   int        `json:"pages"`
	Users   []string   `json:"users"`
	// Unreadable counts lines of the two files that could not be read.
	Unreadable int `json:"unreadable"`
}

const logPageSize = 100

// readLog reads the change log and the log of logins, newest first,
// keeping the entries of user (all when "") and kind ("change", "login"
// or an action of the change log; all when "").
func readLog(stateDir, user, kind string, page int) (logPage, error) {
	var all []logEntry
	users := map[string]bool{}
	p := logPage{Entries: []logEntry{}}
	read := func(name string, line func([]byte) (logEntry, bool)) error {
		f, err := os.Open(filepath.Join(stateDir, name))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 4<<20)
		for sc.Scan() {
			e, ok := line(sc.Bytes())
			if !ok {
				p.Unreadable++
				continue
			}
			users[e.User] = true
			all = append(all, e)
		}
		return sc.Err()
	}
	err := read(ChangesFile, func(b []byte) (logEntry, bool) {
		var c change
		if json.Unmarshal(b, &c) != nil || c.Action == "" {
			return logEntry{}, false
		}
		return logEntry{Time: c.Time, User: c.User, Kind: "change", Change: &c}, true
	})
	if err != nil {
		return p, err
	}
	err = read(AuthLogFile, func(b []byte) (logEntry, bool) {
		var l struct {
			Time   time.Time `json:"time"`
			User   string    `json:"user"`
			Result string    `json:"result"`
			IP     string    `json:"ip"`
		}
		if json.Unmarshal(b, &l) != nil || l.Result == "" {
			return logEntry{}, false
		}
		return logEntry{Time: l.Time, User: l.User, Kind: "login", Result: l.Result, IP: l.IP}, true
	})
	if err != nil {
		return p, err
	}
	for u := range users {
		p.Users = append(p.Users, u)
	}
	slices.Sort(p.Users)
	var kept []logEntry
	for _, e := range all {
		if user != "" && e.User != user {
			continue
		}
		switch {
		case kind == "", kind == e.Kind:
		case e.Change != nil && e.Change.Action == kind:
		default:
			continue
		}
		kept = append(kept, e)
	}
	slices.SortStableFunc(kept, func(a, b logEntry) int { return b.Time.Compare(a.Time) })
	p.Total = len(kept)
	p.Pages = max(1, (len(kept)+logPageSize-1)/logPageSize)
	p.Page = min(max(page, 1), p.Pages)
	from := (p.Page - 1) * logPageSize
	p.Entries = append(p.Entries, kept[from:min(from+logPageSize, len(kept))]...)
	return p, nil
}

// maxAdminBody is the largest body of a change of users or of one's own
// password.
const maxAdminBody = 4 << 10

// readJSON reads a small JSON body strictly into v.
func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("the request can't be read: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("the request can't be read: more after the JSON")
	}
	return nil
}

// confirm asks the user for their password again before a change (G4,
// C8). It writes the answer and returns false when the password is wrong
// or the user must wait.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request, user, password string) bool {
	_, result, wait := s.auth.verify(user, password, clientIP(r), "confirm")
	switch result {
	case loginWait:
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("too many wrong passwords; try again in %d seconds", int(wait.Seconds())+1)})
		return false
	case loginFailed:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "your password is not right"})
		return false
	}
	return true
}

// apiUsers lists the users for the Users page.
func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"users": s.auth.users.infos(), "roles": Roles, "you": s.auth.user(sessionToken(r))})
}

// userChange is what the Users page posts.
type userChange struct {
	Action   string `json:"action"` // "add", "remove", "role" or "reset"
	Name     string `json:"name"`
	Role     string `json:"role"`
	Password string `json:"password"` // the admin's own
}

// apiUsersChange adds, removes, changes the role of, or resets the
// password of a user, after the admin's password (G4), and logs it (G5).
// A new password is in the answer, once.
func (s *Server) apiUsersChange(w http.ResponseWriter, r *http.Request) {
	admin := s.auth.user(sessionToken(r))
	var uc userChange
	if err := readJSON(w, r, maxAdminBody, &uc); err != nil {
		badRequest(w, err)
		return
	}
	if !s.confirm(w, r, admin, uc.Password) {
		return
	}
	u := s.auth.users
	c := change{Time: s.now(), User: admin, Target: uc.Name}
	answer := map[string]any{"ok": true}
	var err error
	switch uc.Action {
	case "add":
		var password string
		if password, err = u.add(uc.Name, uc.Role); err == nil {
			c.Action, c.Role = actionUserAdded, uc.Role
			answer["password"] = password
		}
	case "remove":
		role := u.role(uc.Name)
		if err = u.remove(uc.Name); err == nil {
			c.Action, c.Role = actionUserRemoved, role
		}
	case "role":
		old := u.role(uc.Name)
		if err = u.setRole(uc.Name, uc.Role); err == nil {
			c.Action, c.Role, c.OldRole = actionRoleChanged, uc.Role, old
		}
	case "reset":
		var password string
		if password, err = u.reset(uc.Name); err == nil {
			c.Action = actionPasswordReset
			answer["password"] = password
		}
	default:
		err = fmt.Errorf("action %q: give add, remove, role or reset", uc.Action)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errLastAdmin) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.changes.add(c); err != nil {
		// The change is made; the log could not be written.
		s.log.Printf("change log: %v", err)
		answer["warning"] = "the change is made, but the change log could not be written: " + err.Error()
	}
	writeJSON(w, http.StatusOK, answer)
}

// passwordChange is what the Account page posts.
type passwordChange struct {
	Current string `json:"current"`
	New     string `json:"new"`
	Again   string `json:"again"`
}

// apiAccount changes the user's own password (G4). The session goes on
// with a new token; the user's other sessions end.
func (s *Server) apiAccount(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	var pc passwordChange
	if err := readJSON(w, r, maxAdminBody, &pc); err != nil {
		badRequest(w, err)
		return
	}
	if pc.New != pc.Again {
		badRequest(w, errors.New("the two new passwords are not the same"))
		return
	}
	if err := checkChosen(pc.New); err != nil {
		badRequest(w, err)
		return
	}
	if !s.confirm(w, r, user, pc.Current) {
		return
	}
	stamp, err := s.auth.users.setPassword(user, pc.New)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auth.end(sessionToken(r))
	setSession(w, s.auth.start(user, stamp))
	answer := map[string]any{"ok": true}
	if _, err := s.changes.add(change{Time: s.now(), User: user, Action: actionPasswordChanged, Target: user}); err != nil {
		s.log.Printf("change log: %v", err)
		answer["warning"] = "the password is changed, but the change log could not be written: " + err.Error()
	}
	writeJSON(w, http.StatusOK, answer)
}

// apiLog gives a page of the change log and the logins (G5).
func (s *Server) apiLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := 1
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			badRequest(w, fmt.Errorf("page %q is not a page number", v))
			return
		}
		page = n
	}
	kind := q.Get("kind")
	known := []string{"", "change", "login", actionMark, actionUserAdded, actionUserRemoved, actionRoleChanged, actionPasswordReset, actionPasswordChanged}
	if !slices.Contains(known, kind) {
		badRequest(w, fmt.Errorf("kind %q is not known", kind))
		return
	}
	p, err := readLog(s.cfg.StateDir, strings.TrimSpace(q.Get("user")), kind, page)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}
