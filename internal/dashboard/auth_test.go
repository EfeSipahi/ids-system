package dashboard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEveryRouteNeedsALogin: without a session, pages send the browser to
// the login page and the API answers 401. Only the login page and the
// static files are open.
func TestEveryRouteNeedsALogin(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	d := newDashboard(t, dir)
	stale := &http.Cookie{Name: SessionCookie, Value: "NOT-A-SESSION"}

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/", http.StatusSeeOther},
		{"GET", "/alerts", http.StatusSeeOther},
		{"GET", "/alerts/a", http.StatusSeeOther},
		{"GET", "/rules", http.StatusSeeOther},
		{"GET", "/engine", http.StatusSeeOther},
		{"GET", "/nothing", http.StatusSeeOther},
		{"GET", "/api/nothing", http.StatusSeeOther},
		{"GET", "/api/overview", http.StatusUnauthorized},
		{"GET", "/api/alerts", http.StatusUnauthorized},
		{"GET", "/api/records/a", http.StatusUnauthorized},
		{"GET", "/api/rules", http.StatusUnauthorized},
		{"GET", "/api/engine", http.StatusUnauthorized},
		{"POST", "/api/overview", http.StatusSeeOther},
		{"GET", "/login", http.StatusOK},
		{"GET", "/static/app.js", http.StatusOK},
		{"GET", "/static/app.css", http.StatusOK},
	} {
		for _, session := range []*http.Cookie{nil, stale} {
			w := d.do(tc.method, tc.path, nil, session)
			if w.Code != tc.want {
				t.Errorf("%s %s (cookie %v): %d, want %d", tc.method, tc.path, session != nil, w.Code, tc.want)
				continue
			}
			switch w.Code {
			case http.StatusSeeOther:
				if loc := w.Header().Get("Location"); loc != "/login" {
					t.Errorf("%s %s: redirect to %q", tc.method, tc.path, loc)
				}
			case http.StatusUnauthorized:
				if !strings.Contains(w.Body.String(), "login required") || strings.Contains(w.Body.String(), "203.0.113") {
					t.Errorf("%s %s: %s", tc.method, tc.path, w.Body)
				}
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	d := newDashboard(t, "")
	session := d.login(t, "admin", d.password)
	for _, path := range []string{"/login", "/", "/api/overview", "/static/app.js", "/nothing"} {
		h := d.do("GET", path, nil, session).Header()
		csp := h.Get("Content-Security-Policy")
		for _, part := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, part) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, part)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: CSP %q allows inline script", path, csp)
		}
		for name, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
			"X-Frame-Options":        "DENY",
			"Cache-Control":          "no-store",
		} {
			if got := h.Get(name); got != want {
				t.Errorf("%s: %s = %q, want %q", path, name, got, want)
			}
		}
	}
}

func TestLoginAndLogout(t *testing.T) {
	d := newDashboard(t, "")

	w := d.do("POST", "/login", url.Values{"user": {"admin"}, "password": {"wrong"}}, nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Wrong user name or password") {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("a failed login set a cookie")
	}
	// An unknown name gets the same answer.
	w2 := d.do("POST", "/login", url.Values{"user": {"nobody"}, "password": {"wrong"}}, nil)
	if w2.Code != w.Code || w2.Body.String() != w.Body.String() {
		t.Error("an unknown user name is answered differently")
	}

	w = d.do("POST", "/login", url.Values{"user": {"admin"}, "password": {d.password}}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("login: %d to %q", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	if c.Name != "__Host-ids-session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie = %+v", c)
	}
	if len(c.Value) < 26 {
		t.Errorf("session token %q is short", c.Value)
	}

	if w := d.do("GET", "/api/overview", nil, c); w.Code != http.StatusOK {
		t.Fatalf("with the session: %d", w.Code)
	}
	if w := d.do("GET", "/login", nil, c); w.Code != http.StatusSeeOther {
		t.Errorf("login page when logged in: %d", w.Code)
	}

	w = d.do("POST", "/logout", nil, c)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("logout: %d to %q", w.Code, w.Header().Get("Location"))
	}
	if cs := w.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Errorf("logout cookies = %v", cs)
	}
	if w := d.do("GET", "/api/overview", nil, c); w.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", w.Code)
	}

	// The log of logins has every try, and never a password.
	data, err := os.ReadFile(filepath.Join(d.cfg.StateDir, AuthLogFile))
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		var line struct{ User, Result, IP string }
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		if line.IP != "192.0.2.1" {
			t.Errorf("log IP = %q", line.IP)
		}
		results = append(results, line.User+" "+line.Result)
	}
	if got := strings.Join(results, ", "); got != "admin failed, nobody failed, admin ok, admin logout" {
		t.Errorf("log = %s", got)
	}
	if strings.Contains(string(data), d.password) || strings.Contains(string(data), "wrong") {
		t.Error("the log holds a password")
	}
	if info, _ := os.Stat(filepath.Join(d.cfg.StateDir, AuthLogFile)); info.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v", info.Mode().Perm())
	}
}

func TestWaitAfterWrongPasswords(t *testing.T) {
	d := newDashboard(t, "")
	try := func(password string) int {
		return d.do("POST", "/login", url.Values{"user": {"admin"}, "password": {password}}, nil).Code
	}
	for i := range freeTries {
		if code := try("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("wrong try %d: %d", i+1, code)
		}
	}
	// Now even the right password is not checked.
	w := d.do("POST", "/login", url.Values{"user": {"admin"}, "password": {d.password}}, nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "30 seconds") {
		t.Fatalf("during the wait: %d %s", w.Code, w.Body)
	}
	d.clock.advance(29 * time.Second)
	if code := try(d.password); code != http.StatusTooManyRequests {
		t.Fatalf("after 29 s: %d", code)
	}
	// Another user name is not held up.
	if code := d.do("POST", "/login", url.Values{"user": {"other"}, "password": {"x"}}, nil).Code; code != http.StatusUnauthorized {
		t.Errorf("another name: %d", code)
	}
	d.clock.advance(time.Second)
	// The sixth wrong password: the next wait is twice as long.
	if code := try("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("after the wait: %d", code)
	}
	d.clock.advance(59 * time.Second)
	if code := try(d.password); code != http.StatusTooManyRequests {
		t.Fatalf("59 s into the second wait: %d", code)
	}
	d.clock.advance(time.Second)
	if code := try(d.password); code != http.StatusSeeOther {
		t.Fatalf("right password after the wait: %d", code)
	}
	// A login clears the count.
	if code := try("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("after a login: %d", code)
	}
	if code := try(d.password); code != http.StatusSeeOther {
		t.Errorf("one wrong password after a login holds up the next: %d", code)
	}
}

func TestWaitAfter(t *testing.T) {
	// 30 s after the fifth wrong password, doubling up to 15 minutes.
	for count, want := range map[int]time.Duration{
		5: 30 * time.Second, 6: time.Minute, 7: 2 * time.Minute, 8: 4 * time.Minute,
		9: 8 * time.Minute, 10: 15 * time.Minute, 50: 15 * time.Minute,
	} {
		if got := waitAfter(count); got != want {
			t.Errorf("waitAfter(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestTrimFailed(t *testing.T) {
	a := newAuth(nil, t.TempDir(), time.Hour, newClock().now)
	for i := range maxTracked {
		a.failed[fmt.Sprintf("name%d", i)] = &failures{count: 1}
	}
	a.failed["held"] = &failures{count: freeTries, until: t0.Add(time.Minute)}
	a.trimFailed(t0)
	if len(a.failed) >= maxTracked {
		t.Errorf("%d names still tracked", len(a.failed))
	}
	if a.failed["held"] == nil {
		t.Error("a name that must wait was dropped while others could go")
	}
}

func TestSessionLimits(t *testing.T) {
	d := newDashboard(t, "")
	ok := func(c *http.Cookie) bool { return d.do("GET", "/api/engine", nil, c).Code == http.StatusOK }

	// Idle for longer than the setting (60 minutes): the session ends.
	c := d.login(t, "admin", d.password)
	d.clock.advance(60 * time.Minute)
	if !ok(c) {
		t.Fatal("ended after exactly the idle time")
	}
	d.clock.advance(60*time.Minute + time.Second)
	if ok(c) {
		t.Fatal("still valid after more than the idle time")
	}

	// Used often, it still ends after 12 hours.
	c = d.login(t, "admin", d.password)
	for range 12 * 60 / 50 {
		d.clock.advance(50 * time.Minute)
		if !ok(c) {
			t.Fatal("ended while in use")
		}
	}
	d.clock.advance(time.Hour)
	if ok(c) {
		t.Fatal("still valid after 12 hours")
	}
}

func TestSessionEndsWithUserChanges(t *testing.T) {
	d := newDashboard(t, "")
	c := d.login(t, "admin", d.password)
	password, err := ResetPassword(d.cfg.StateDir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if d.do("GET", "/api/engine", nil, c).Code != http.StatusUnauthorized {
		t.Error("a new password did not end the session")
	}
	if d.do("POST", "/login", url.Values{"user": {"admin"}, "password": {d.password}}, nil).Code != http.StatusUnauthorized {
		t.Error("the old password still works")
	}
	c = d.login(t, "admin", password)
	if err := RemoveUser(d.cfg.StateDir, "admin"); err != nil {
		t.Fatal(err)
	}
	if d.do("GET", "/api/engine", nil, c).Code != http.StatusUnauthorized {
		t.Error("removing the user did not end the session")
	}
}

// TestCrossOriginRequestsAreRejected: another site cannot post to the
// dashboard from a logged-in user's browser.
func TestCrossOriginRequestsAreRejected(t *testing.T) {
	d := newDashboard(t, "")
	c := d.login(t, "admin", d.password)
	form := url.Values{"user": {"admin"}, "password": {d.password}}

	for _, headers := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
		{"Origin", "https://evil.example"},
	} {
		if w := d.do("POST", "/login", form, nil, headers...); w.Code != http.StatusForbidden {
			t.Errorf("login with %v: %d", headers, w.Code)
		}
		if w := d.do("POST", "/logout", nil, c, headers...); w.Code != http.StatusForbidden {
			t.Errorf("logout with %v: %d", headers, w.Code)
		}
	}
	if d.do("GET", "/api/engine", nil, c).Code != http.StatusOK {
		t.Error("a rejected logout ended the session")
	}
	// The dashboard's own pages may post.
	if w := d.do("POST", "/logout", nil, c, "Sec-Fetch-Site", "same-origin"); w.Code != http.StatusSeeOther {
		t.Errorf("same-origin logout: %d", w.Code)
	}
}

func TestLoginFormLimit(t *testing.T) {
	d := newDashboard(t, "")
	big := url.Values{"user": {"admin"}, "password": {strings.Repeat("x", maxForm)}}
	if w := d.do("POST", "/login", big, nil); w.Code != http.StatusBadRequest {
		t.Errorf("a form over the limit: %d", w.Code)
	}
}

func TestUsers(t *testing.T) {
	dir := t.TempDir()
	password, err := AddUser(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	u, err := openUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.check("admin", password); !ok {
		t.Error("the new password does not work")
	}
	for _, tc := range [][2]string{{"admin", "wrong"}, {"Admin", password}, {"nobody", password}, {"admin", ""}} {
		if _, ok := u.check(tc[0], tc[1]); ok {
			t.Errorf("check(%q, %q) passed", tc[0], tc[1])
		}
	}
	if _, err := AddUser(dir, "admin"); err == nil {
		t.Error("the same name was added twice")
	}
	for _, bad := range []string{"", "a b", "ali/../x", strings.Repeat("a", 65), "<script>"} {
		if _, err := AddUser(dir, bad); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
	if _, err := ResetPassword(dir, "nobody"); err == nil {
		t.Error("reset of an unknown user")
	}
	if err := RemoveUser(dir, "nobody"); err == nil {
		t.Error("removal of an unknown user")
	}

	path := filepath.Join(dir, UsersFile)
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), password) {
		t.Error("the file holds the password")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("users file mode %v", info.Mode().Perm())
	}
	var f usersFile
	if err := json.Unmarshal(data, &f); err != nil || len(f.Users) != 1 || f.Users[0].Iterations != newIterations || len(f.Users[0].Salt) != 32 || len(f.Users[0].Key) != 64 {
		t.Errorf("users file: %s", data)
	}

	// A running dashboard sees users added later.
	second, err := AddUser(dir, "second")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.check("second", second); !ok {
		t.Error("a user added after the start does not work")
	}
	if err := RemoveUser(dir, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.check("admin", password); ok {
		t.Error("a removed user can still log in")
	}
}

func TestPasswordWorkFactor(t *testing.T) {
	// The real count, from the OWASP Password Storage Cheat Sheet for
	// PBKDF2-HMAC-SHA256.
	if passwordIterations != 600_000 {
		t.Errorf("passwordIterations = %d", passwordIterations)
	}
	// A user stored with another count is checked with that count.
	dir := t.TempDir()
	old := newIterations
	newIterations = 2000
	password, err := AddUser(dir, "admin")
	newIterations = old
	if err != nil {
		t.Fatal(err)
	}
	u, _ := openUsers(dir)
	if _, ok := u.check("admin", password); !ok {
		t.Error("a user with another iteration count cannot log in")
	}
}
