package dashboard

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// postJSON posts a JSON body as a browser of the dashboard does.
func (d *testDashboard) postJSON(path string, v any, session *http.Cookie, headers ...string) *httptest.ResponseRecorder {
	data, _ := json.Marshal(v)
	r := httptest.NewRequest("POST", "https://127.0.0.1"+path, strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	if session != nil {
		r.AddCookie(session)
	}
	w := httptest.NewRecorder()
	d.h.ServeHTTP(w, r)
	return w
}

// changes reads the change log.
func changes(t *testing.T, stateDir string) []change {
	t.Helper()
	f, err := os.Open(filepath.Join(stateDir, ChangesFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var list []change
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c change
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatalf("change log line %q: %v", sc.Text(), err)
		}
		list = append(list, c)
	}
	return list
}

// noSecretInState fails when any file of the state folder holds one of the
// passwords (rule 3 of the plan, verification 4).
func noSecretInState(t *testing.T, stateDir string, passwords ...string) {
	t.Helper()
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(stateDir, e.Name()))
		if err != nil {
			continue
		}
		for _, p := range passwords {
			if p != "" && strings.Contains(string(data), p) {
				t.Errorf("%s holds a password", e.Name())
			}
		}
	}
}

// TestStateFolderLock (C4): one dashboard per state folder.
func TestStateFolderLock(t *testing.T) {
	d := newDashboard(t, "")
	if _, err := New(d.cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "in use by another dashboard") {
		t.Errorf("a second dashboard on the same state folder: %v", err)
	}
	d.srv.Close()
	again, err := New(d.cfg, io.Discard)
	if err != nil {
		t.Fatalf("after the first let go: %v", err)
	}
	again.Close()
}

// TestUsersAPI (G4, G5, verification 3 and 4): every change of users on
// the page, the admin's password asked again, the last admin, sessions
// that end, one log entry per change, and no password in any file.
func TestUsersAPI(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	before := folderState(t, dir)
	d := newDashboard(t, dir)
	admin := d.login(t, "admin", d.password)
	state := d.cfg.StateDir
	passwords := []string{d.password}
	change := func(uc userChange, session *http.Cookie) *httptest.ResponseRecorder {
		if uc.Password == "" {
			uc.Password = d.password
		}
		return d.postJSON("/api/users", uc, session)
	}

	// Add an analyst; the password is in the answer once and works.
	w := change(userChange{Action: "add", Name: "ayse", Role: RoleAnalyst}, admin)
	var added struct {
		OK       bool   `json:"ok"`
		Password string `json:"password"`
	}
	decode(t, w, &added)
	if w.Code != 200 || len(added.Password) != 26 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	passwords = append(passwords, added.Password)
	ayse := d.login(t, "ayse", added.Password)
	if r := d.srv.auth.users.role("ayse"); r != RoleAnalyst {
		t.Errorf("role %q", r)
	}
	var list struct {
		Users []userInfo `json:"users"`
		You   string     `json:"you"`
	}
	decode(t, d.do("GET", "/api/users", nil, admin), &list)
	if len(list.Users) != 2 || list.Users[1].Name != "ayse" || list.You != "admin" || strings.Contains(d.do("GET", "/api/users", nil, admin).Body.String(), `"salt"`) {
		t.Errorf("users: %+v", list)
	}

	// An analyst can't change users; nor can anyone without the password.
	if w := change(userChange{Action: "add", Name: "x", Role: RoleViewer, Password: added.Password}, ayse); w.Code != http.StatusForbidden {
		t.Errorf("an analyst added a user: %d", w.Code)
	}
	if w := change(userChange{Action: "add", Name: "x", Role: RoleViewer, Password: "wrong"}, admin); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not right") {
		t.Errorf("wrong password: %d %s", w.Code, w.Body)
	}

	// A new role ends the user's session; the log has the old role.
	if w := change(userChange{Action: "role", Name: "ayse", Role: RoleViewer}, admin); w.Code != 200 {
		t.Fatalf("role: %d %s", w.Code, w.Body)
	}
	if d.do("GET", "/api/engine", nil, ayse).Code != http.StatusUnauthorized {
		t.Error("a new role did not end the session")
	}
	ayse = d.login(t, "ayse", added.Password)

	// A reset ends the session, and only the new password works.
	w = change(userChange{Action: "reset", Name: "ayse"}, admin)
	var reset struct {
		Password string `json:"password"`
	}
	decode(t, w, &reset)
	if w.Code != 200 || len(reset.Password) != 26 || reset.Password == added.Password {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	passwords = append(passwords, reset.Password)
	if d.do("GET", "/api/engine", nil, ayse).Code != http.StatusUnauthorized {
		t.Error("a reset did not end the session")
	}
	ayse = d.login(t, "ayse", reset.Password)

	// The last admin stays; removing another user ends their session.
	if w := change(userChange{Action: "remove", Name: "admin"}, admin); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "last admin") {
		t.Errorf("remove the last admin: %d %s", w.Code, w.Body)
	}
	if w := change(userChange{Action: "role", Name: "admin", Role: RoleAnalyst}, admin); w.Code != http.StatusConflict {
		t.Errorf("demote the last admin: %d", w.Code)
	}
	if w := change(userChange{Action: "remove", Name: "ayse"}, admin); w.Code != 200 {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	if d.do("GET", "/api/engine", nil, ayse).Code != http.StatusUnauthorized {
		t.Error("a removal did not end the session")
	}

	// Bad requests.
	for _, bad := range []userChange{{Action: "rename", Name: "x"}, {Action: "add", Name: "a b", Role: RoleViewer}, {Action: "add", Name: "y", Role: "root"}, {Action: "remove", Name: "nobody"}} {
		if w := change(bad, admin); w.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d", bad, w.Code)
		}
	}
	if w := d.do("POST", "/api/users", nil, admin); w.Code != http.StatusBadRequest {
		t.Errorf("no body: %d", w.Code)
	}
	if w := d.postJSON("/api/users", map[string]string{"action": "add", "extra": "x"}, admin); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown field: %d", w.Code)
	}
	if w := d.postJSON("/api/users", userChange{Action: "add", Name: "z", Role: RoleViewer, Password: d.password}, admin, "Sec-Fetch-Site", "cross-site"); w.Code != http.StatusForbidden {
		t.Errorf("cross-site: %d", w.Code)
	}

	// One entry per change: added, role, reset, removed.
	var actions []string
	for _, c := range changes(t, state) {
		actions = append(actions, c.Action+" "+c.Target+" "+c.OldRole+">"+c.Role)
		if c.User != "admin" || c.ID == "" || c.Time.IsZero() {
			t.Errorf("entry %+v", c)
		}
	}
	want := []string{"user_added ayse >analyst", "role_changed ayse analyst>viewer", "password_reset ayse >", "user_removed ayse >viewer"}
	if strings.Join(actions, "|") != strings.Join(want, "|") {
		t.Errorf("change log:\n got %q\nwant %q", actions, want)
	}

	// Five wrong passwords in a row make the next change wait, whatever the
	// password (C8); the login page counts the same.
	for range freeTries {
		change(userChange{Action: "add", Name: "w", Role: RoleViewer, Password: "wrong"}, admin)
	}
	if w := change(userChange{Action: "add", Name: "w", Role: RoleViewer}, admin); w.Code != http.StatusTooManyRequests {
		t.Errorf("after five wrong passwords: %d %s", w.Code, w.Body)
	}
	if _, result, _ := d.srv.auth.login("admin", d.password, "127.0.0.1"); result != loginWait {
		t.Error("the login page does not wait after wrong passwords at a change")
	}

	noSecretInState(t, state, passwords...)
	if after := folderState(t, dir); after != before {
		t.Error("the records folder changed")
	}
}

// TestAccountAPI (G4): changing one's own password.
func TestAccountAPI(t *testing.T) {
	d := newDashboard(t, "")
	password, err := AddUser(d.cfg.StateDir, "viewer1", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	s := d.login(t, "viewer1", password)
	other := d.login(t, "viewer1", password)
	post := func(pc passwordChange) *httptest.ResponseRecorder { return d.postJSON("/api/account", pc, s) }

	for _, tc := range []struct {
		pc   passwordChange
		code int
		want string
	}{
		{passwordChange{password, "fourteen chars", "fourteen chars"}, 400, "has 14 characters; it needs at least 15"},
		{passwordChange{password, "a long new password", "a long new passw0rd"}, 400, "not the same"},
		{passwordChange{"wrong", "a long new password", "a long new password"}, 403, "not right"},
		{passwordChange{password, strings.Repeat("x", 257), strings.Repeat("x", 257)}, 400, "at most 256"},
	} {
		if w := post(tc.pc); w.Code != tc.code || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%q: %d %s", tc.pc.New, w.Code, w.Body)
		}
	}
	// Fifteen characters, some of them not ASCII, are enough: length counts
	// characters, not bytes.
	chosen := "ağaçgölgeçiçek1"
	w := post(passwordChange{password, chosen, chosen})
	if w.Code != 200 {
		t.Fatalf("15 characters: %d %s", w.Code, w.Body)
	}
	var next *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			next = c
		}
	}
	if next == nil || d.do("GET", "/api/engine", nil, next).Code != 200 {
		t.Error("the session did not go on with a new token")
	}
	if d.do("GET", "/api/engine", nil, s).Code != http.StatusUnauthorized || d.do("GET", "/api/engine", nil, other).Code != http.StatusUnauthorized {
		t.Error("the old sessions still work")
	}
	if _, result, _ := d.srv.auth.login("viewer1", password, ""); result == loginOK {
		t.Error("the old password still works")
	}
	if _, result, _ := d.srv.auth.login("viewer1", chosen, ""); result != loginOK {
		t.Error("the new password does not work")
	}
	cs := changes(t, d.cfg.StateDir)
	if len(cs) != 1 || cs[0].Action != actionPasswordChanged || cs[0].User != "viewer1" {
		t.Errorf("change log: %+v", cs)
	}
	noSecretInState(t, d.cfg.StateDir, password, chosen, "fourteen chars")
}

// TestLogAPI (G5): the changes and the logins, newest first, filtered.
func TestLogAPI(t *testing.T) {
	d := newDashboard(t, "")
	admin := d.login(t, "admin", d.password)
	d.clock.advance(1e9)
	d.postJSON("/api/users", userChange{Action: "add", Name: "b", Role: RoleViewer, Password: d.password}, admin)
	d.clock.advance(1e9)
	d.do("POST", "/login", map[string][]string{"user": {"b"}, "password": {"wrong"}}, nil)
	// A line that can't be read is counted, not shown.
	f, _ := os.OpenFile(filepath.Join(d.cfg.StateDir, ChangesFile), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{not json\n")
	f.Close()

	var p logPage
	decode(t, d.do("GET", "/api/log", nil, admin), &p)
	var got []string
	for _, e := range p.Entries {
		what := e.Result
		if e.Change != nil {
			what = e.Change.Action
		}
		got = append(got, e.Kind+" "+e.User+" "+what)
	}
	want := []string{"login b failed", "change admin user_added", "login admin confirm ok", "login admin ok"}
	if strings.Join(got, "|") != strings.Join(want, "|") || p.Unreadable != 1 || strings.Join(p.Users, ",") != "admin,b" {
		t.Errorf("log: %q, unreadable %d, users %q", got, p.Unreadable, p.Users)
	}
	decode(t, d.do("GET", "/api/log?kind=change", nil, admin), &p)
	if p.Total != 1 {
		t.Errorf("kind=change: %d", p.Total)
	}
	decode(t, d.do("GET", "/api/log?user=b", nil, admin), &p)
	if p.Total != 1 || p.Entries[0].Result != "failed" {
		t.Errorf("user=b: %+v", p.Entries)
	}
	decode(t, d.do("GET", "/api/log?kind=user_added", nil, admin), &p)
	if p.Total != 1 {
		t.Errorf("kind=user_added: %d", p.Total)
	}
	for _, bad := range []string{"?kind=nothing", "?page=0", "?page=x"} {
		if w := d.do("GET", "/api/log"+bad, nil, admin); w.Code != 400 {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
}
