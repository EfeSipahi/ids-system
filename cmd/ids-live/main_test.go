package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/record"
)

const testRules = `
SecComponentSignature "TEST/1"
SecAction "id:1,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule ARGS "@rx (?i)union\s+select" "id:2,phase:2,log,pass,severity:'CRITICAL',msg:'SQL',setvar:tx.blocking_inbound_anomaly_score=+5"
`

// syncBuffer is written by the server's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// setup writes a configuration with the test rules and returns its path,
// the records directory and a socket path short enough for Linux.
func setup(t *testing.T, sections string) (configPath, records, socket string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.conf"), []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	short, err := os.MkdirTemp("", "ids")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	socket = filepath.Join(short, "copy.sock")
	records = filepath.Join(dir, "records")
	text := `{"files": ["rules.conf"]` + sections + `}`
	text = strings.NewReplacer("SOCKET", socket, "RECORDS", records).Replace(text)
	configPath = filepath.Join(dir, "ids.json")
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, records, socket
}

func TestStartErrors(t *testing.T) {
	both, _, _ := setup(t, `, "live": {"socket": "SOCKET"}, "records": {"dir": "RECORDS"}`)
	noLive, _, _ := setup(t, `, "records": {"dir": "RECORDS"}`)
	noRecords, _, _ := setup(t, `, "live": {"socket": "SOCKET"}`)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", noLive}, `has no "live" section with a socket; add one, or give -socket`},
		{[]string{"-config", noRecords}, `has no "records" section; add one, or give -records`},
		{[]string{"-config", both, "-socket", "/run/" + strings.Repeat("x", 110)}, "Linux allows at most 107"},
		{[]string{"-config", both, "extra"}, `unexpected argument "extra"`},
		{[]string{"-config", "missing.json"}, "missing.json"},
	} {
		var stdout, stderr syncBuffer
		if code := run(tt.args, &stdout, &stderr, nil); code != 2 || !strings.Contains(stderr.String(), tt.want) {
			t.Errorf("%v: exit %d, stderr %q; want 2 and %q", tt.args, code, stderr.String(), tt.want)
		}
	}
}

// A whole run: ids-live starts, takes a copy from a copier, records it,
// and stops on SIGTERM. While it runs, the records folder is locked.
func TestRun(t *testing.T) {
	configPath, records, socket := setup(t, `, "live": {"socket": "SOCKET", "workers": 1}`)
	signals := make(chan os.Signal, 1)
	var stdout, stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- run([]string{"-config", configPath, "-records", records}, &stdout, &stderr, signals) }()

	var conn net.Conn
	for end := time.Now().Add(5 * time.Second); conn == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("ids-live does not listen; stdout %q, stderr %q", stdout.String(), stderr.String())
		}
		conn, _ = net.Dial("unix", socket)
	}
	defer conn.Close()
	hello, _ := copyframe.AppendHello(nil, copyframe.Hello{Format: copyframe.Version, Program: "test copier"})
	cp := &copyframe.Copy{
		Meta: copyframe.Meta{
			ID: "req-1", Time: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC),
			Client:   copyframe.Addr{IP: "203.0.113.7", Port: 51234},
			Request:  copyframe.RequestMeta{BodyComplete: true},
			Response: &copyframe.ResponseMeta{Status: 404},
		},
		Method: "GET", Target: "/?q=1+union+select+2", Proto: "HTTP/1.1",
		Headers: []copyframe.Header{{Name: "Host", Value: "localhost"}},
	}
	frame, err := copyframe.AppendCopy(hello, cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(records, record.CurrentFile)
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		data, _ := os.ReadFile(current)
		if bytes.Contains(data, []byte(`"type":"request"`)) {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("no request record; stderr %q", stderr.String())
		}
	}
	if _, err := record.Open(record.Config{Dir: records}, record.Engine{}, nil, nil); !errors.Is(err, record.ErrInUse) {
		t.Errorf("a second writer while ids-live runs: %v", err)
	}

	signals <- syscall.SIGTERM
	select {
	case code := <-exit:
		if code != 0 {
			t.Errorf("exit %d; stderr %q", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("ids-live does not stop")
	}
	out := stdout.String()
	for _, want := range []string{
		"Rules: TEST/1, paranoia level 1, 2 active, 0 excluded\n",
		"Listening on " + socket + ": 1 workers, a queue of 1000 copies or 64 MB, frames up to 16 MB\n",
		"Records: " + records + " (run ",
		"Stopping (terminated)\n",
		"Stopped: 1 copies received, 1 analysed, 0 not analysed (0 with a full queue, 0 at the stop), 0 whose record could not be written; copiers reported 0 not sent\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if logs := stderr.String(); !strings.Contains(logs, "copier connected: test copier") || strings.Contains(logs, "union") {
		t.Errorf("stderr: %s", logs)
	}
	data, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"input":{"kind":"live","socket":"` + socket + `"}`, `"proxy":{"request_id":"req-1"`, `"copiers":1`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("records lack %s:\n%s", want, data)
		}
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket is left after the stop: %v", err)
	}
}

// W13: ids-live takes a changed configuration without stopping, keeps the
// one it runs when the new one does not load, and starts a new run in the
// records.
func TestTakesAChangedConfiguration(t *testing.T) {
	configPath, records, socket := setup(t, `, "live": {"socket": "SOCKET", "workers": 1}, "records": {"dir": "RECORDS"}`)
	signals := make(chan os.Signal, 1)
	var stdout, stderr syncBuffer
	exit := make(chan int, 1)
	go func() { exit <- run([]string{"-config", configPath, "-watch", "20ms"}, &stdout, &stderr, signals) }()
	var conn net.Conn
	for end := time.Now().Add(5 * time.Second); conn == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("ids-live does not listen; stderr %q", stderr.String())
		}
		conn, _ = net.Dial("unix", socket)
	}
	defer conn.Close()
	hello, _ := copyframe.AppendHello(nil, copyframe.Hello{Format: copyframe.Version, Program: "test copier"})
	conn.Write(hello)
	send := func(id string) {
		t.Helper()
		cp := &copyframe.Copy{
			Meta:   copyframe.Meta{ID: id, Time: time.Now(), Client: copyframe.Addr{IP: "203.0.113.7", Port: 1}, Request: copyframe.RequestMeta{BodyComplete: true}},
			Method: "GET", Target: "/?q=1+union+select+2", Proto: "HTTP/1.1",
			Headers: []copyframe.Header{{Name: "Host", Value: "localhost"}},
		}
		frame, err := copyframe.AppendCopy(nil, cp)
		if err != nil {
			t.Fatal(err)
		}
		conn.Write(frame)
	}
	waitFor := func(what func() bool, msg string) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); !what(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("%s; stdout %q, stderr %q", msg, stdout.String(), stderr.String())
			}
		}
	}
	current := filepath.Join(records, record.CurrentFile)
	recordsOf := func(id string) bool {
		data, _ := os.ReadFile(current)
		return bytes.Contains(data, []byte(`"request_id":"`+id+`"`))
	}
	send("before")
	waitFor(func() bool { return recordsOf("before") }, "no record of the first copy")

	// A configuration that does not load: ids-live says so and keeps
	// going.
	orig, _ := os.ReadFile(configPath)
	os.WriteFile(configPath, []byte(`{"files": ["missing.conf"]}`), 0o600)
	waitFor(func() bool { return strings.Contains(stderr.String(), "keeps the one it runs") }, "no word of the broken configuration")
	send("broken")
	waitFor(func() bool { return recordsOf("broken") }, "the copy sent while the file was broken was not analysed with the old rules")

	// Rule 2 excluded: the next copy finds nothing, so it gets no record.
	changed := bytes.Replace(orig, []byte(`"files": ["rules.conf"]`), []byte(`"files": ["rules.conf"], "exclude": [{"id": 2, "reason": "test"}]`), 1)
	os.WriteFile(configPath, changed, 0o600)
	waitFor(func() bool { return strings.Contains(stdout.String(), "Took the changed configuration") }, "the change was not taken")
	send("after")
	send("after2")
	time.Sleep(200 * time.Millisecond)
	if recordsOf("after") || recordsOf("after2") {
		t.Error("a copy after the change was analysed with the old rules")
	}

	signals <- syscall.SIGTERM
	if code := <-exit; code != 0 {
		t.Errorf("exit %d; stderr %q", code, stderr.String())
	}
	data, _ := os.ReadFile(current)
	var starts, counts []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, `"type":"start"`) {
			starts = append(starts, line)
		}
		if strings.Contains(line, `"type":"counts"`) {
			counts = append(counts, line)
		}
	}
	if len(starts) != 2 || !strings.Contains(starts[1], `"id":2,"file":"rules.conf"`) || !strings.Contains(starts[1], `"active":false`) {
		t.Fatalf("start records:\n%s", strings.Join(starts, "\n"))
	}
	// The old run's counts were written when the new run started: two
	// copies analysed; the new run's at the stop: two.
	if len(counts) != 2 || !strings.Contains(counts[0], `"analysed":2`) || !strings.Contains(counts[1], `"analysed":2`) {
		t.Errorf("counts:\n%s", strings.Join(counts, "\n"))
	}
}
