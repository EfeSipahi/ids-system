package idscopy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/live"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

const testRules = `
SecComponentSignature "TEST/1"
SecAction "id:1,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule ARGS "@rx (?i)union\s+select" "id:2,phase:2,log,pass,severity:'CRITICAL',msg:'SQL',setvar:tx.blocking_inbound_anomaly_score=+5"
`

// startLive runs the real ids-live server on socket, with the test rules,
// and returns it with its records folder.
func startLive(t *testing.T, socket string) (*live.Server, *record.Recorder, string) {
	t.Helper()
	rulesPath := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(rulesPath, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := engine.Load(engine.Config{Files: []string{rulesPath}})
	if err != nil {
		t.Fatal(err)
	}
	apps, err := profile.NewSet(rs, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "records")
	rec, err := record.OpenWith(record.Config{Dir: dir}, record.NewEngine(rs, "sha256:test"), rs.Statuses(), apps, &record.Input{Kind: record.InputLive, Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	a := &live.Analyzer{Rules: rs, Apps: apps, Recorder: rec}
	srv, err := live.Listen(live.Config{Socket: socket}, rec, a.Analyze, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	return srv, rec, dir
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// loadCaddy adapts a Caddyfile and runs it in this process, as a reload
// does when Caddy already runs.
func loadCaddy(t *testing.T, caddyfile string) {
	t.Helper()
	cfg, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatalf("Caddyfile: %v", err)
	}
	for _, w := range warnings {
		t.Logf("Caddyfile warning: %s", w.String())
	}
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatal(err)
	}
}

// rawRequest sends request bytes as written, so that the case and order
// of the header names are the client's, and reads the status line.
func rawRequest(t *testing.T, port int, request string) string {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.Status + " " + string(body)
}

// The whole road in one process: a client, Caddy from a Caddyfile with
// ids_copy and no "order" option, the copier, the socket, the real
// ids-live server and its records. The client IP follows trusted_proxies
// (T5): without it, X-Forwarded-For is ignored; with 127.0.0.1 trusted, it
// is used, while the connection's address is kept too. The second
// configuration is a reload, and the copier's connection survives it.
func TestCaddyToIDSLive(t *testing.T) {
	// Caddy keeps an instance ID in its data folder, whatever "storage"
	// says; this keeps it out of the home folder.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	socket := shortSocket(t)
	srv, rec, dir := startLive(t, socket)
	port := freePort(t)
	storage := t.TempDir()
	caddyfile := func(global string) string {
		return fmt.Sprintf(`{
	admin off
	persist_config off
	auto_https off
	storage file_system %s
	%s
}
http://127.0.0.1:%d {
	ids_copy {
		application shop
		socket %s
	}
	respond "hello" 200
}
`, storage, global, port, socket)
	}
	request := func(id string) string {
		return fmt.Sprintf("GET /search?q=1+union+select+2&id=%s HTTP/1.1\r\nhost: 127.0.0.1:%d\r\nx-custom: v\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n", id, port)
	}
	waitConnected := func() {
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			s, ok := senderOf(socket)
			if ok && s.isConnected() {
				return
			}
			if time.Now().After(end) {
				t.Fatal("the copier does not connect to ids-live")
			}
		}
	}

	loadCaddy(t, caddyfile(""))
	t.Cleanup(func() { caddy.Stop() })
	waitConnected()
	if got := rawRequest(t, port, request("untrusted")); got != "200 OK hello" {
		t.Fatalf("response %q", got)
	}

	loadCaddy(t, caddyfile("servers {\n\t\ttrusted_proxies static 127.0.0.1/32\n\t}"))
	waitConnected()
	if got := rawRequest(t, port, request("trusted")); got != "200 OK hello" {
		t.Fatalf("response %q", got)
	}

	for end := time.Now().Add(5 * time.Second); srv.Stats().Analysed < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("ids-live analysed %d of 2: %+v", srv.Stats().Analysed, srv.Stats())
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats := srv.Shutdown(ctx)
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if stats.Missed != 0 || stats.Dropped != 0 {
		t.Errorf("stats %+v", stats)
	}

	records := map[string]map[string]any{}
	data, err := os.ReadFile(filepath.Join(dir, record.CurrentFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if m["type"] == record.TypeRequest {
			query := m["request"].(map[string]any)["query"].(string)
			records[query[strings.Index(query, "id=")+3:]] = m
		}
	}
	for id, wantClient := range map[string]string{"untrusted": "127.0.0.1", "trusted": "198.51.100.9"} {
		r := records[id]
		if r == nil {
			t.Fatalf("no record of the %s request; records: %s", id, data)
		}
		client := r["client"].(map[string]any)
		conn := r["connection"].(map[string]any)
		if client["ip"] != wantClient || conn["ip"] != "127.0.0.1" {
			t.Errorf("%s: client %v, connection %v", id, client, conn)
		}
		names := r["request"].(map[string]any)["header_names"].([]any)
		if want := []any{"Host", "Connection", "X-Custom", "X-Forwarded-For"}; fmt.Sprint(names) != fmt.Sprint(want) {
			t.Errorf("%s: header names %v, want %v", id, names, want)
		}
		if p := r["proxy"].(map[string]any); len(p["request_id"].(string)) != 36 {
			t.Errorf("%s: proxy %v", id, p)
		}
		if resp := r["response"].(map[string]any); resp["status"] != 200.0 || resp["body_copied"] != 5.0 {
			t.Errorf("%s: response %v", id, resp)
		}
	}
	if !strings.Contains(string(data), `"unknown_applications":{"shop":2}`) {
		t.Errorf("the counts lack the unknown application name: %s", data)
	}
}

// senderOf returns the pool's sender of socket.
func senderOf(socket string) (*sender, bool) {
	var found *sender
	senders.Range(func(key, value any) bool {
		if key == socket {
			found = value.(*sender)
			return false
		}
		return true
	})
	return found, found != nil
}
