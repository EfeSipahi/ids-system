package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestAllows(t *testing.T) {
	for _, tc := range []struct {
		role, least string
		want        bool
	}{
		{RoleViewer, RoleViewer, true}, {RoleViewer, RoleAnalyst, false}, {RoleViewer, RoleAdmin, false},
		{RoleAnalyst, RoleViewer, true}, {RoleAnalyst, RoleAnalyst, true}, {RoleAnalyst, RoleAdmin, false},
		{RoleAdmin, RoleViewer, true}, {RoleAdmin, RoleAnalyst, true}, {RoleAdmin, RoleAdmin, true},
		{"", RoleViewer, false}, {"root", RoleViewer, false},
	} {
		if got := allows(tc.role, tc.least); got != tc.want {
			t.Errorf("allows(%q, %q) = %v", tc.role, tc.least, got)
		}
	}
}

// TestRoles: the role of a user written before roles (C5), the roles a
// user can have, a reset that keeps the role, and the last admin (G4).
func TestRoles(t *testing.T) {
	dir := t.TempDir()
	if _, err := AddUser(dir, "old", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	// Take the role out, as a file from before roles has it.
	path := filepath.Join(dir, UsersFile)
	data, _ := os.ReadFile(path)
	var f usersFile
	json.Unmarshal(data, &f)
	f.Users[0].Role = ""
	data, _ = json.Marshal(f)
	if strings.Contains(string(data), `"role"`) {
		t.Fatal("the role is still in the file")
	}
	os.WriteFile(path, data, 0o600)

	u, err := openUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := u.role("old"); r != RoleAdmin {
		t.Errorf("a user without a role is %q, want admin", r)
	}
	if r := u.role("nobody"); r != "" {
		t.Errorf("an unknown user is %q", r)
	}
	if _, err := u.add("x", "root"); err == nil || !strings.Contains(err.Error(), `role "root"`) {
		t.Errorf("add with a bad role: %v", err)
	}
	if _, err := u.add("watcher", RoleViewer); err != nil {
		t.Fatal(err)
	}
	// Any write gives every user a written role.
	data, _ = os.ReadFile(path)
	if !strings.Contains(string(data), `"role": "admin"`) || !strings.Contains(string(data), `"role": "viewer"`) {
		t.Errorf("roles not written: %s", data)
	}

	// The last admin can't be demoted or removed; with a second admin it can.
	if err := u.setRole("old", RoleViewer); err != errLastAdmin {
		t.Errorf("demote the last admin: %v", err)
	}
	if err := u.remove("old"); err != errLastAdmin {
		t.Errorf("remove the last admin: %v", err)
	}
	if err := u.setRole("watcher", "root"); err == nil {
		t.Error("a bad role was set")
	}
	if err := u.setRole("nobody", RoleViewer); err == nil {
		t.Error("the role of an unknown user was set")
	}
	if err := u.setRole("watcher", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := u.setRole("old", RoleAnalyst); err != nil {
		t.Errorf("demote one of two admins: %v", err)
	}

	// A reset keeps the role and the time the user was added.
	before := u.list[slices.IndexFunc(u.list, func(s storedUser) bool { return s.Name == "old" })]
	if _, err := u.reset("old"); err != nil {
		t.Fatal(err)
	}
	after := u.list[slices.IndexFunc(u.list, func(s storedUser) bool { return s.Name == "old" })]
	if after.Role != RoleAnalyst || !after.Created.Equal(before.Created) || after.Salt == before.Salt {
		t.Errorf("reset: role %q, created %v (was %v), salt changed %v", after.Role, after.Created, before.Created, after.Salt != before.Salt)
	}
	if err := u.remove("old"); err != nil {
		t.Errorf("remove an analyst: %v", err)
	}
}

// TestUsersFileLock (C3): two programs that change the users file at the
// same time, such as the dashboard and the command, lose nothing.
func TestUsersFileLock(t *testing.T) {
	dir := t.TempDir()
	if _, err := AddUser(dir, "admin", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for p := range 2 {
		u, err := openUsers(dir) // each one its own reader, as two programs
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 15 {
				if _, err := u.add(fmt.Sprintf("p%d-%d", p, i), RoleViewer); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	u, _ := openUsers(dir)
	if n := len(u.names()); n != 31 {
		t.Errorf("%d users after 30 additions and the admin, want 31", n)
	}
}

// TestRoutesByRole (G3, verification 2): every route as a viewer, an
// analyst and an admin.
func TestRoutesByRole(t *testing.T) {
	dir := t.TempDir()
	sampleRecords(t, dir)
	d := newDashboard(t, dir)
	d.srv.test = newTestTester(t, crsFirst)
	sessions := map[string]*http.Cookie{RoleAdmin: d.login(t, "admin", d.password)}
	for _, role := range []string{RoleViewer, RoleAnalyst} {
		password, err := AddUser(d.cfg.StateDir, role+"1", role)
		if err != nil {
			t.Fatal(err)
		}
		sessions[role] = d.login(t, role+"1", password)
	}
	for _, tc := range []struct {
		method, path, least string
	}{
		{"GET", "/", RoleViewer},
		{"GET", "/alerts", RoleViewer},
		{"GET", "/alerts/a", RoleViewer},
		{"GET", "/rules", RoleViewer},
		{"GET", "/rules/942100", RoleViewer},
		{"GET", "/applications", RoleViewer},
		{"GET", "/applications/shop", RoleViewer},
		{"GET", "/applications/shop/rules", RoleViewer},
		{"GET", "/engine", RoleViewer},
		{"GET", "/nothing", RoleViewer},
		{"GET", "/api/rules/942100", RoleViewer},
		{"GET", "/api/applications", RoleViewer},
		{"GET", "/api/applications/none", RoleViewer},
		{"GET", "/applications/shop/history", RoleViewer},
		{"GET", "/applications/shop/settings", RoleViewer},
		{"GET", "/settings", RoleViewer},
		{"GET", "/settings/history", RoleViewer},
		{"GET", "/proposals", RoleAdmin},
		{"GET", "/api/changes?object=global", RoleViewer},
		{"POST", "/api/changes", RoleAnalyst},
		{"GET", "/api/changes/preview?object=global", RoleViewer},
		{"GET", "/api/proposals", RoleAdmin},
		{"GET", "/api/versions", RoleViewer},
		{"GET", "/api/control", RoleViewer},
		{"GET", "/api/settings", RoleViewer},
		{"GET", "/api/applications/shop/settings", RoleViewer},
		{"GET", "/applications/shop/profile", RoleViewer},
		{"GET", "/api/applications/shop/profile", RoleViewer},
		{"POST", "/api/applications/shop/profile/check", RoleViewer},
		{"GET", "/analyse", RoleAnalyst},
		{"GET", "/api/analyse", RoleAnalyst},
		{"POST", "/api/analyse", RoleAnalyst},
		{"POST", "/api/analyse/stop", RoleAnalyst},
		{"POST", "/api/analyse/try", RoleAnalyst},
		{"GET", "/api/overview", RoleViewer},
		{"GET", "/api/alerts", RoleViewer},
		{"GET", "/api/records/a", RoleViewer},
		{"GET", "/api/rules", RoleViewer},
		{"GET", "/api/engine", RoleViewer},
		{"GET", "/test", RoleAnalyst},
		{"GET", "/api/test", RoleAnalyst},
		{"GET", "/api/test/files/920100", RoleAnalyst},
		{"POST", "/api/test", RoleAnalyst},
		{"GET", "/account", RoleViewer},
		{"POST", "/api/account", RoleViewer},
		{"GET", "/users", RoleAdmin},
		{"GET", "/log", RoleAdmin},
		{"GET", "/api/users", RoleAdmin},
		{"POST", "/api/users", RoleAdmin},
		{"GET", "/api/log", RoleAdmin},
		{"GET", "/api/marks/a", RoleViewer},
		{"POST", "/api/marks", RoleAnalyst},
	} {
		for _, role := range Roles {
			w := d.do(tc.method, tc.path, nil, sessions[role])
			refused := w.Code == http.StatusForbidden
			if refused == allows(role, tc.least) {
				t.Errorf("%s %s as %s: %d", tc.method, tc.path, role, w.Code)
			}
			if refused && strings.HasPrefix(tc.path, "/api/") && !strings.Contains(w.Body.String(), "it needs "+tc.least) {
				t.Errorf("%s %s as %s: %s", tc.method, tc.path, role, w.Body)
			}
		}
	}

	// The pages show the role, the Test tab only to whom may use it, and
	// a refused page says what it needs.
	for _, role := range Roles {
		body := d.do("GET", "/", nil, sessions[role]).Body.String()
		if !strings.Contains(body, "· "+role+"</span>") {
			t.Errorf("%s: the role is not shown", role)
		}
		if strings.Contains(body, `href="/test"`) != allows(role, RoleAnalyst) {
			t.Errorf("%s: the Test tab shown %v", role, strings.Contains(body, `href="/test"`))
		}
		if strings.Contains(body, `href="/users"`) != allows(role, RoleAdmin) || strings.Contains(body, `href="/log"`) != allows(role, RoleAdmin) {
			t.Errorf("%s: the Users and Log tabs shown wrongly", role)
		}
		if !strings.Contains(body, `href="/account"`) {
			t.Errorf("%s: no link to the account page", role)
		}
	}
	if body := d.do("GET", "/test", nil, sessions[RoleViewer]).Body.String(); !strings.Contains(body, "needs the role analyst or more. Your role is viewer") {
		t.Errorf("refused page: %s", body)
	}
}
