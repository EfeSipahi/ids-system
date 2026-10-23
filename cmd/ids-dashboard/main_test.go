package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes a dashboard configuration with relative paths, as
// configs/dashboard.json has, and returns its path.
func writeConfig(t *testing.T, listen string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "records"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dashboard.json")
	text := fmt.Sprintf(`{"listen": %q, "records_dir": "records", "state_dir": "state"}`, listen)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTool(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUserCommands(t *testing.T) {
	config := writeConfig(t, "127.0.0.1:8443")

	code, out, errOut := runTool("-config", config, "-add-user", "admin")
	if code != 0 || !strings.HasPrefix(out, "Added user admin. Password (shown only now): ") {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	password := strings.TrimSpace(out[strings.LastIndex(out, " ")+1:])
	if len(password) != 26 {
		t.Errorf("password %q", password)
	}
	users, err := os.ReadFile(filepath.Join(filepath.Dir(config), "state", "users.json"))
	if err != nil || strings.Contains(string(users), password) || !strings.Contains(string(users), `"admin"`) {
		t.Errorf("users file: %s %v", users, err)
	}

	if code, _, errOut := runTool("-config", config, "-add-user", "admin"); code != 2 || !strings.Contains(errOut, "already exists") {
		t.Errorf("add twice: %d %q", code, errOut)
	}
	code, out, _ = runTool("-config", config, "-reset-password", "admin")
	if code != 0 || !strings.HasPrefix(out, "New password for admin (shown only now): ") || strings.Contains(out, password) {
		t.Errorf("reset: %d %q", code, out)
	}
	if code, out, _ := runTool("-config", config, "-remove-user", "admin"); code != 0 || out != "Removed user admin.\n" {
		t.Errorf("remove: %d %q", code, out)
	}
	if code, _, errOut := runTool("-config", config, "-remove-user", "admin"); code != 2 || !strings.Contains(errOut, `no user "admin"`) {
		t.Errorf("remove twice: %d %q", code, errOut)
	}
	if code, _, errOut := runTool("-config", config, "-add-user", "a b"); code != 2 || !strings.Contains(errOut, "user name") {
		t.Errorf("bad name: %d %q", code, errOut)
	}
}

func TestStartupErrors(t *testing.T) {
	config := writeConfig(t, "127.0.0.1:8443")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", config, "extra"}, `unexpected argument "extra"`},
		{[]string{"-config", config, "-add-user", "a", "-remove-user", "b"}, "only one of"},
		{[]string{"-config", filepath.Join(t.TempDir(), "missing.json")}, "no such file"},
		{[]string{"-config", config}, "there is no user yet; add one with: ids-dashboard -add-user NAME"},
	} {
		code, out, errOut := runTool(tc.args...)
		if code != 2 || !strings.Contains(errOut, tc.want) || out != "" {
			t.Errorf("%v: %d, stdout %q, stderr %q", tc.args, code, out, errOut)
		}
	}

	// Without the records directory.
	if err := os.Remove(filepath.Join(filepath.Dir(config), "records")); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runTool("-config", config, "-add-user", "admin"); code != 0 {
		t.Fatal("add-user needs no records")
	}
	if code, _, errOut := runTool("-config", config); code != 2 || !strings.Contains(errOut, "run the IDS with records first") {
		t.Errorf("no records: %d %q", code, errOut)
	}
}

func TestAddressInUse(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	config := writeConfig(t, busy.Addr().String())
	if code, _, _ := runTool("-config", config, "-add-user", "admin"); code != 0 {
		t.Fatal("add-user failed")
	}
	// Everything before listening works: the certificate is made.
	code, out, errOut := runTool("-config", config)
	if code != 2 || !strings.Contains(errOut, "address already in use") {
		t.Errorf("%d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(config), "state", "cert.pem")); err != nil {
		t.Errorf("no certificate was made: %v", err)
	}
}
