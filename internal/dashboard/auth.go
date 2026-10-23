package dashboard

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SessionCookie is the name of the login cookie. The "__Host-" prefix
// makes browsers accept it only over HTTPS, for this host alone and the
// whole site, so no other site or subdomain can set or read it.
const SessionCookie = "__Host-ids-session"

// AuthLogFile is the file in the state directory where logins are logged.
const AuthLogFile = "auth.jsonl"

// Limits of logins.
const (
	// sessionMaxAge ends a login after this long, however much it is used.
	sessionMaxAge = 12 * time.Hour
	// freeTries is how many wrong passwords a user name may have in a row
	// before each further try must wait.
	freeTries = 5
	firstWait = 30 * time.Second
	maxWait   = 15 * time.Minute
	// maxTracked limits how many user names with failed tries are kept,
	// so that guessing many names cannot fill the memory.
	maxTracked = 10_000
)

type session struct {
	user     string
	stamp    string // the password's stamp at login; see users.stamp
	created  time.Time
	lastSeen time.Time
}

type failures struct {
	count int
	until time.Time // no try is checked before this time
}

// auth keeps the logins. Sessions live in memory: a restart of the
// dashboard ends every login.
type auth struct {
	users *users
	idle  time.Duration
	now   func() time.Time
	log   string

	mu       sync.Mutex
	sessions map[string]*session
	failed   map[string]*failures
}

func newAuth(u *users, stateDir string, idle time.Duration, now func() time.Time) *auth {
	return &auth{
		users:    u,
		idle:     idle,
		now:      now,
		log:      filepath.Join(stateDir, AuthLogFile),
		sessions: map[string]*session{},
		failed:   map[string]*failures{},
	}
}

// loginResult says how a login went.
type loginResult int

const (
	loginOK loginResult = iota
	loginFailed
	// loginWait: too many wrong passwords; the password was not checked.
	loginWait
)

// login checks a user name and password. On success it returns a new
// session token. On loginWait it returns how long to wait.
func (a *auth) login(name, password, ip string) (token string, result loginResult, wait time.Duration) {
	now := a.now()
	key := strings.ToLower(name)

	a.mu.Lock()
	if f := a.failed[key]; f != nil && now.Before(f.until) {
		wait = f.until.Sub(now)
		a.mu.Unlock()
		a.write(name, "wait", ip)
		return "", loginWait, wait
	}
	a.mu.Unlock()

	stamp, ok := a.users.check(name, password)

	a.mu.Lock()
	defer a.mu.Unlock()
	if !ok {
		f := a.failed[key]
		if f == nil {
			a.trimFailed(now)
			f = &failures{}
			a.failed[key] = f
		}
		f.count++
		if f.count >= freeTries {
			f.until = now.Add(waitAfter(f.count))
		}
		a.write(name, "failed", ip)
		return "", loginFailed, 0
	}
	delete(a.failed, key)
	token = rand.Text()
	a.sessions[token] = &session{user: name, stamp: stamp, created: now, lastSeen: now}
	a.write(name, "ok", ip)
	return token, loginOK, 0
}

// waitAfter is the wait after count wrong passwords in a row: 30 seconds
// after the fifth, doubling with each one after it, up to 15 minutes.
func waitAfter(count int) time.Duration {
	wait := firstWait
	for i := freeTries; i < count && wait < maxWait; i++ {
		wait *= 2
	}
	return min(wait, maxWait)
}

// trimFailed makes room in the failed list: first by dropping names whose
// wait is over, then, if still full, by dropping one. A user name dropped
// early only gets its free tries back.
func (a *auth) trimFailed(now time.Time) {
	if len(a.failed) < maxTracked {
		return
	}
	for k, f := range a.failed {
		if now.After(f.until) && f.count < freeTries {
			delete(a.failed, k)
		}
	}
	for k := range a.failed {
		if len(a.failed) < maxTracked {
			break
		}
		delete(a.failed, k)
	}
}

// user returns the user of a session token, or "" when the token is
// unknown, idle too long, too old, or its user was removed or given a new
// password since.
func (a *auth) user(token string) string {
	if token == "" {
		return ""
	}
	now := a.now()
	a.mu.Lock()
	s := a.sessions[token]
	if s == nil {
		a.mu.Unlock()
		return ""
	}
	if now.Sub(s.lastSeen) > a.idle || now.Sub(s.created) > sessionMaxAge {
		delete(a.sessions, token)
		a.mu.Unlock()
		return ""
	}
	user, stamp := s.user, s.stamp
	a.mu.Unlock()

	if a.users.stamp(user) != stamp {
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		return ""
	}
	a.mu.Lock()
	s.lastSeen = now
	a.mu.Unlock()
	return user
}

// logout ends a session.
func (a *auth) logout(token, ip string) {
	a.mu.Lock()
	s := a.sessions[token]
	delete(a.sessions, token)
	a.mu.Unlock()
	if s != nil {
		a.write(s.user, "logout", ip)
	}
}

// write adds one line to the log of logins. It never holds a password.
func (a *auth) write(name, result, ip string) {
	if len(name) > 64 {
		name = name[:64]
	}
	line, err := json.Marshal(struct {
		Time   time.Time `json:"time"`
		User   string    `json:"user"`
		Result string    `json:"result"`
		IP     string    `json:"ip"`
	}{a.now().UTC(), name, result, ip})
	if err != nil {
		return
	}
	f, err := os.OpenFile(a.log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

// clientIP returns the address of the browser's connection.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// setSession sends the login cookie.
func setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionMaxAge / time.Second),
	})
}

// clearSession removes the login cookie from the browser.
func clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
