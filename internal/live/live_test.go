package live

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// testRules match an attack in a parameter, a cookie and the Authorization
// header, and in the whole query and body.
const testRules = `
SecComponentSignature "TEST/1"
SecAction "id:1,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS:Authorization "@rx (?i)union\s+select" "id:2,phase:2,log,pass,capture,severity:'CRITICAL',msg:'SQL in %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule QUERY_STRING|REQUEST_BODY "@rx (?i)union" "id:3,phase:2,log,pass,msg:'Union in the whole text',logdata:'%{MATCHED_VAR}'"
`

// shopProfile has a secret JSON field and a secret header (F8). Its mode
// is alert, so its findings are alerts (F6).
const shopProfile = `{
  "mode": "alert",
  "endpoints": [
    {"method": "GET", "path": "/search", "params": {"q": {}}},
    {"method": "POST", "path": "/api/pay", "content_type": ["application/json"],
     "params": {"card.number": {"in": "json", "secret": true}, "note": {"in": "json"}}}
  ],
  "headers": [{"name": "X-Key", "secret": true}]
}`

func loadRules(t testing.TB) *engine.RuleSet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(path, []byte(testRules), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := engine.Load(engine.Config{Files: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// testApps returns the application shop, on shop.example.com.
func testApps(t testing.TB, rs *engine.RuleSet) *profile.Set {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shop.json")
	if err := os.WriteFile(path, []byte(shopProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	set, err := profile.NewSet(rs, []profile.AppConfig{{Name: "shop", Hosts: []string{"shop.example.com"}, Loaded: p}}, false)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// shortDir returns a new directory with a short path, because a socket's
// path can't be longer than 107 bytes and t.TempDir's paths can be.
func shortDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ids")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// logBuffer collects the server's messages; many goroutines write to it.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// harness is a running server with its records.
type harness struct {
	t      *testing.T
	srv    *Server
	rec    *record.Recorder
	dir    string
	socket string
	logs   *logBuffer
	served chan error
}

// options of a test server: wrap may wrap the analysis, for example to
// hold it back; full turns on full_requests.
type options struct {
	cfg  Config
	wrap func(func(*copyframe.Copy) error) func(*copyframe.Copy) error
	full bool
}

func start(t *testing.T, opt options) *harness {
	t.Helper()
	rs := loadRules(t)
	apps := testApps(t, rs)
	h := &harness{t: t, dir: filepath.Join(t.TempDir(), "records"), logs: &logBuffer{}, served: make(chan error, 1)}
	h.socket = filepath.Join(shortDir(t), "copy.sock")
	var err error
	h.rec, err = record.OpenWith(record.Config{Dir: h.dir, FullRequests: opt.full}, record.Engine{Version: "test", CRS: "TEST/1", ParanoiaLevel: 1, Config: "sha256:test"},
		rs.Statuses(), apps, &record.Input{Kind: record.InputLive, Socket: h.socket})
	if err != nil {
		t.Fatal(err)
	}
	a := &Analyzer{Rules: rs, Apps: apps, Recorder: h.rec}
	analyze := a.Analyze
	if opt.wrap != nil {
		analyze = opt.wrap(analyze)
	}
	cfg := opt.cfg
	cfg.Socket = h.socket
	h.srv, err = Listen(cfg, h.rec, analyze, log.New(h.logs, "", 0))
	if err != nil {
		h.rec.Close()
		t.Fatal(err)
	}
	go func() { h.served <- h.srv.Serve() }()
	return h
}

// stop shuts the server down within the deadline, closes the records and
// returns their lines.
func (h *harness) stop(deadline time.Duration) (Stats, []map[string]any) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	stats := h.srv.Shutdown(ctx)
	if err := <-h.served; err != nil {
		h.t.Errorf("Serve: %v", err)
	}
	if err := h.rec.Close(); err != nil {
		h.t.Fatal(err)
	}
	return stats, readLines(h.t, filepath.Join(h.dir, record.CurrentFile))
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %d: %v", len(lines)+1, err)
		}
		lines = append(lines, m)
	}
	return lines
}

// ofType returns the lines of one record type.
func ofType(lines []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["type"] == typ {
			out = append(out, l)
		}
	}
	return out
}

// eventually waits until cond holds, for at most five seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting until %s", what)
}

// copier is a fake proxy copier.
type copier struct {
	t    *testing.T
	conn *net.UnixConn
	r    *copyframe.Reader
}

// dial connects without a hello.
func dial(t *testing.T, path string) *copier {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &copier{t: t, conn: conn, r: copyframe.NewReader(conn, 1<<20)}
}

// connect connects and exchanges hello frames.
func connect(t *testing.T, path string) *copier {
	t.Helper()
	c := dial(t, path)
	c.hello(copyframe.Version)
	f, err := c.r.Next()
	if err != nil || f.Type != copyframe.TypeHello || f.Hello.Error != "" || f.Hello.Program != Program {
		t.Fatalf("hello from the IDS: %+v, %v", f.Hello, err)
	}
	return c
}

func (c *copier) hello(format int) {
	c.t.Helper()
	frame, err := copyframe.AppendHello(nil, copyframe.Hello{Format: format, Program: "test copier", Version: "1"})
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(frame)
}

func (c *copier) write(frame []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(frame); err != nil {
		c.t.Fatal(err)
	}
}

func (c *copier) send(cp *copyframe.Copy) {
	c.t.Helper()
	frame, err := copyframe.AppendCopy(nil, cp)
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(frame)
}

// closed reports whether the IDS closed the connection: a read ends.
func (c *copier) closed() bool {
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.r.Next()
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF)
}

var base = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

// testCopy is a GET of target on host over TLS, answered with 200 and a
// short text.
func testCopy(n int, host, target string) *copyframe.Copy {
	return &copyframe.Copy{
		Meta: copyframe.Meta{
			ID:         "req-" + string(rune('a'+n%26)) + "-" + time.Duration(n).String(),
			Time:       base.Add(time.Duration(n) * time.Second),
			DurationMS: 1.5,
			Client:     copyframe.Addr{IP: "203.0.113.7", Port: 51234},
			Connection: copyframe.Addr{IP: "10.0.0.2", Port: 40000},
			Server:     copyframe.Addr{IP: "10.0.0.5", Port: 443},
			TLS:        &copyframe.TLS{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ServerName: host, ALPN: "http/1.1"},
			Request:    copyframe.RequestMeta{BodyComplete: true},
			Response:   &copyframe.ResponseMeta{Status: 200, BodyLength: 11},
		},
		Method:          "GET",
		Target:          target,
		Proto:           "HTTP/1.1",
		Headers:         []copyframe.Header{{Name: "Host", Value: host}, {Name: "User-Agent", Value: "test"}},
		ResponseHeaders: []copyframe.Header{{Name: "Content-Type", Value: "text/plain"}},
		ResponseBody:    []byte("hello world"),
	}
}

// Copies are analysed like ids-offline's requests and recorded with what
// the proxy saw: the application by the proxy's name or by Host and path
// (T6), rule and profile findings, the client the proxy determined and the
// connection (T5), TLS (T10) and the response (C6).
func TestCopiesAreAnalysedAndRecorded(t *testing.T) {
	h := start(t, options{})
	c := connect(t, h.socket)

	rule := testCopy(1, "shop.example.com", "/search?q=1+union+select+2") // shop by Host, rule finding
	rule.Meta.Application = "shop"
	byHost := testCopy(2, "shop.example.com", "/admin") // shop by Host, profile finding
	none := testCopy(3, "other.example.com", "/?q=1+union+select+2")
	unknown := testCopy(4, "shop.example.com", "/search?q=1+union+select+2")
	unknown.Meta.Application = "shop2"
	clean := testCopy(5, "shop.example.com", "/search?q=books")
	clean.Meta.Application = "shop"
	cut := testCopy(6, "shop.example.com", "/search")
	cut.Method = "POST"
	cut.Headers = append(cut.Headers, copyframe.Header{Name: "Content-Type", Value: "application/x-www-form-urlencoded"})
	cut.Body = []byte("q=1+union+sel")
	cut.Meta.Request = copyframe.RequestMeta{BodyLength: 20_000_000, BodyComplete: true}
	cut.Meta.TLS = nil
	cut.Meta.Response = nil
	cut.ResponseHeaders, cut.ResponseBody = nil, nil
	for _, cp := range []*copyframe.Copy{rule, byHost, none, unknown, clean, cut} {
		c.send(cp)
	}
	eventually(t, "six copies are analysed", func() bool { return h.srv.Stats().Analysed == 6 })
	stats, lines := h.stop(5 * time.Second)
	if stats != (Stats{Received: 6, Analysed: 6}) {
		t.Errorf("stats = %+v", stats)
	}

	start := lines[0]
	if !reflect.DeepEqual(start["input"], map[string]any{"kind": "live", "socket": h.socket}) {
		t.Errorf("start input = %v", start["input"])
	}
	byID := map[string]map[string]any{}
	for _, r := range ofType(lines, "request") {
		byID[r["proxy"].(map[string]any)["request_id"].(string)] = r
	}
	if len(byID) != 5 {
		t.Fatalf("%d request records, want 5 (the clean copy is only counted)", len(byID))
	}
	app := func(cp *copyframe.Copy) string {
		return byID[cp.Meta.ID]["application"].(map[string]any)["name"].(string)
	}
	if app(rule) != "shop" || app(byHost) != "shop" || app(none) != "none" || app(unknown) != "none" {
		t.Errorf("applications: %s, %s, %s, %s", app(rule), app(byHost), app(none), app(unknown))
	}

	r := byID[rule.Meta.ID]
	want := map[string]any{
		"proxy":      map[string]any{"request_id": rule.Meta.ID, "received": "2026-11-18T10:00:01Z"},
		"client":     map[string]any{"ip": "203.0.113.7", "port": 51234.0},
		"connection": map[string]any{"ip": "10.0.0.2", "port": 40000.0},
		"server":     map[string]any{"host": "shop.example.com", "ip": "10.0.0.5", "port": 443.0},
		"tls":        map[string]any{"version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "shop.example.com", "alpn": "http/1.1"},
		"response":   map[string]any{"status": 200.0, "content_type": "text/plain", "body_length": 11.0, "body_copied": 11.0},
		"alert":      true,
		"alert_by":   []any{"rules"},
	}
	for k, v := range want {
		if !reflect.DeepEqual(r[k], v) {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
	if p := byID[byHost.Meta.ID]; p["alert"] != true || !reflect.DeepEqual(p["alert_by"], []any{"profile"}) ||
		p["profile"].(map[string]any)["findings"].([]any)[0].(map[string]any)["kind"] != profile.KindUnknownEndpoint {
		t.Errorf("profile finding: %v %v %v", p["alert"], p["alert_by"], p["profile"])
	}

	// A body the copier cut (T3) is analysed in its first part, and the
	// record says so; the cut attack is not seen.
	cr := byID[cut.Meta.ID]
	analysis := cr["analysis"].(map[string]any)
	if analysis["complete"] != false || analysis["body"] != "partly inspected" ||
		analysis["body_reason"] != "only the first 13 of 20000000 bytes were inspected" {
		t.Errorf("cut body: %v", analysis)
	}
	if cr["request"].(map[string]any)["body_length"] != 20_000_000.0 {
		t.Errorf("body_length = %v", cr["request"].(map[string]any)["body_length"])
	}
	for _, k := range []string{"tls", "response"} {
		if _, ok := cr[k]; ok {
			t.Errorf("a copy without %s has it in its record: %v", k, cr[k])
		}
	}

	counts := ofType(lines, "counts")
	last := counts[len(counts)-1]
	if last["analysed"] != 6.0 || last["recorded"] != 5.0 || last["no_profile"] != 2.0 || last["copiers"] != 1.0 ||
		!reflect.DeepEqual(last["unknown_applications"], map[string]any{"shop2": 1.0}) {
		t.Errorf("counts = %v", last)
	}
	if !strings.Contains(h.logs.String(), "copier connected: test copier 1") {
		t.Errorf("log: %s", h.logs.String())
	}
}

// A missed frame from a copier becomes a gap record of the copier (T8).
func TestMissedFrameBecomesGap(t *testing.T) {
	h := start(t, options{})
	c := connect(t, h.socket)
	frame, err := copyframe.AppendMissed(nil, copyframe.Missed{From: base, To: base.Add(3 * time.Minute), Count: 1240, Reason: copyframe.ReasonNotConnected})
	if err != nil {
		t.Fatal(err)
	}
	c.write(frame)
	eventually(t, "the gap is counted", func() bool { return h.srv.Stats().Missed == 1240 })
	_, lines := h.stop(5 * time.Second)
	gaps := ofType(lines, "gap")
	if len(gaps) != 1 {
		t.Fatalf("gaps = %v", gaps)
	}
	g := gaps[0]
	if g["from"] != "2026-11-18T10:00:00Z" || g["to"] != "2026-11-18T10:03:00Z" || g["missed"] != 1240.0 ||
		g["reason"] != "not connected" || g["source"] != "copier" {
		t.Errorf("gap = %v", g)
	}
}

// T7: when the queue is full, copies are dropped without waiting, counted,
// and written as a gap of the IDS. The copies being analysed count
// against the limit too.
func TestFullQueueDropsAndCounts(t *testing.T) {
	gate := make(chan struct{})
	h := start(t, options{
		cfg: Config{Workers: 1, QueueCopies: 1},
		wrap: func(analyze func(*copyframe.Copy) error) func(*copyframe.Copy) error {
			return func(c *copyframe.Copy) error {
				<-gate
				return analyze(c)
			}
		},
	})
	c := connect(t, h.socket)
	for n := 1; n <= 4; n++ {
		c.send(testCopy(n, "shop.example.com", "/search?q=1+union+select+2"))
	}
	eventually(t, "three copies are dropped", func() bool { return h.srv.Stats().Dropped == 3 })
	close(gate)
	eventually(t, "the first copy is analysed", func() bool { return h.srv.Stats().Analysed == 1 })
	// A copy fits again once the queue has room.
	c.send(testCopy(5, "shop.example.com", "/search?q=1+union+select+2"))
	eventually(t, "the fifth copy is analysed", func() bool { return h.srv.Stats().Analysed == 2 })
	stats, lines := h.stop(5 * time.Second)
	if stats != (Stats{Received: 5, Analysed: 2, Dropped: 3}) {
		t.Errorf("stats = %+v", stats)
	}
	gaps := ofType(lines, "gap")
	want := []map[string]any{{
		"type": "gap", "schema": 1.0, "run": h.rec.Run(),
		"from": "2026-11-18T10:00:02Z", "to": "2026-11-18T10:00:04Z",
		"missed": 3.0, "reason": "queue full", "source": "ids",
	}}
	if !reflect.DeepEqual(gaps, want) {
		t.Errorf("gaps = %v\nwant %v", gaps, want)
	}
}

// The queue's size in bytes is a limit of its own (T7).
func TestQueueBytesLimit(t *testing.T) {
	gate := make(chan struct{})
	h := start(t, options{
		cfg: Config{Workers: 1, QueueMB: 1, MaxFrameMB: 1},
		wrap: func(analyze func(*copyframe.Copy) error) func(*copyframe.Copy) error {
			return func(c *copyframe.Copy) error {
				<-gate
				return analyze(c)
			}
		},
	})
	c := connect(t, h.socket)
	big := func(n int) *copyframe.Copy {
		cp := testCopy(n, "shop.example.com", "/search")
		cp.Method = "POST"
		cp.Body = bytes.Repeat([]byte("a"), 400<<10)
		cp.Meta.Request.BodyLength = int64(len(cp.Body))
		return cp
	}
	for n := 1; n <= 3; n++ { // two fit in 1 MB, the third does not
		c.send(big(n))
	}
	eventually(t, "one copy is dropped", func() bool { return h.srv.Stats().Dropped == 1 })
	close(gate)
	stats, _ := h.stop(5 * time.Second)
	if stats != (Stats{Received: 3, Analysed: 2, Dropped: 1}) {
		t.Errorf("stats = %+v", stats)
	}
}

// A frame that breaks the format closes its connection; the IDS logs it
// and goes on with other copiers.
func TestBrokenFrameClosesTheConnection(t *testing.T) {
	h := start(t, options{})
	bad := connect(t, h.socket)
	// A copy frame whose content is too short for its first length.
	bad.write([]byte{0, 0, 0, 3, byte(copyframe.TypeCopy), 0, 0})
	if !bad.closed() {
		t.Error("the connection stays open after a broken frame")
	}
	good := connect(t, h.socket)
	good.send(testCopy(1, "shop.example.com", "/search?q=1+union+select+2"))
	eventually(t, "the next copier's copy is analysed", func() bool { return h.srv.Stats().Analysed == 1 })
	h.stop(5 * time.Second)
	if logs := h.logs.String(); !strings.Contains(logs, "a frame breaks the copy format: copy frame: metadata: the frame ends early") {
		t.Errorf("log: %s", logs)
	}
}

// A frame over max_frame_mb is refused before it is read, and its
// connection closed (docs/copy-format.md, section 2).
func TestFrameTooLarge(t *testing.T) {
	h := start(t, options{cfg: Config{MaxFrameMB: 1}})
	c := connect(t, h.socket)
	header := binary.BigEndian.AppendUint32(nil, 1<<20+1)
	c.write(append(header, byte(copyframe.TypeCopy)))
	if !c.closed() {
		t.Error("the connection stays open after a frame that is too large")
	}
	h.stop(5 * time.Second)
	if logs := h.logs.String(); !strings.Contains(logs, "a frame of 1048577 bytes is larger than the limit of 1048576 (live.max_frame_mb)") {
		t.Errorf("log: %s", logs)
	}
}

// A copier of another format version gets a hello with an error, and is
// refused (docs/copy-format.md, section 1).
func TestOtherFormatVersionIsRefused(t *testing.T) {
	h := start(t, options{})
	c := dial(t, h.socket)
	c.hello(copyframe.Version + 1)
	f, err := c.r.Next()
	if err != nil || f.Type != copyframe.TypeHello {
		t.Fatalf("answer: %+v, %v", f, err)
	}
	if want := "ids-live speaks copy format 1; the copier speaks 2"; f.Hello.Error != want {
		t.Errorf("error = %q, want %q", f.Hello.Error, want)
	}
	if !c.closed() {
		t.Error("the connection stays open")
	}
	h.stop(5 * time.Second)
	if logs := h.logs.String(); !strings.Contains(logs, "a copier was refused: test copier 1: ids-live speaks copy format 1") {
		t.Errorf("log: %s", logs)
	}
}

// The first frame must be a hello.
func TestFirstFrameMustBeHello(t *testing.T) {
	h := start(t, options{})
	c := dial(t, h.socket)
	c.send(testCopy(1, "shop.example.com", "/"))
	if !c.closed() {
		t.Error("the connection stays open")
	}
	stats, _ := h.stop(5 * time.Second)
	if stats.Received != 0 {
		t.Errorf("stats = %+v", stats)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "the first frame is a copy frame, not a hello frame") {
		t.Errorf("log: %s", logs)
	}
}

// The copiers count shows in the counts record: 0 when no proxy is
// connected, so that "nothing arrives" can be told from "nothing happens".
func TestCopiersAreCounted(t *testing.T) {
	h := start(t, options{})
	first := connect(t, h.socket)
	connect(t, h.socket)
	eventually(t, "two copiers are connected", func() bool { return copiers(h.srv) == 2 })
	h.srv.flush()
	first.conn.Close()
	eventually(t, "one copier is connected", func() bool { return copiers(h.srv) == 1 })
	h.srv.flush()
	_, lines := h.stop(5 * time.Second)
	counts := ofType(lines, "counts")
	var got []any
	for _, c := range counts {
		got = append(got, c["copiers"])
	}
	// Two at once in the first period; still two in the second, until
	// the first left; one in the last.
	if want := []any{2.0, 2.0, 1.0}; !reflect.DeepEqual(got, want) {
		t.Errorf("copiers = %v, want %v", got, want)
	}
}

func copiers(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copiers
}

// SIGTERM: the frames a copier had sent are still read and analysed;
// after the stop its writes fail, so it counts what follows as missed
// (T8), and nothing is lost without a count.
func TestShutdownDrainsTheQueue(t *testing.T) {
	h := start(t, options{cfg: Config{Workers: 1}})
	c := connect(t, h.socket)
	for n := 1; n <= 200; n++ {
		c.send(testCopy(n, "shop.example.com", "/search?q=1+union+select+2"))
	}
	stats, lines := h.stop(10 * time.Second)
	if stats != (Stats{Received: 200, Analysed: 200}) {
		t.Errorf("stats = %+v", stats)
	}
	if n := len(ofType(lines, "request")); n != 200 {
		t.Errorf("%d request records, want 200", n)
	}
	if gaps := ofType(lines, "gap"); len(gaps) != 0 {
		t.Errorf("gaps = %v", gaps)
	}
	frame, _ := copyframe.AppendCopy(nil, testCopy(201, "shop.example.com", "/"))
	if _, err := c.conn.Write(frame); err == nil {
		t.Error("a copier can still write after the stop")
	}
	if _, err := os.Stat(h.socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket file is still there: %v", err)
	}
}

// Copies still queued when the stop's deadline passes are not analysed,
// but counted in a gap of the IDS.
func TestShutdownDeadlineCountsTheRest(t *testing.T) {
	gate := make(chan struct{})
	h := start(t, options{
		cfg: Config{Workers: 1},
		wrap: func(analyze func(*copyframe.Copy) error) func(*copyframe.Copy) error {
			return func(c *copyframe.Copy) error {
				<-gate
				return analyze(c)
			}
		},
	})
	c := connect(t, h.socket)
	for n := 1; n <= 3; n++ {
		c.send(testCopy(n, "shop.example.com", "/search?q=1+union+select+2"))
	}
	eventually(t, "three copies are received", func() bool { return h.srv.Stats().Received == 3 })
	go func() {
		time.Sleep(300 * time.Millisecond) // after the deadline below
		close(gate)
	}()
	stats, lines := h.stop(100 * time.Millisecond)
	if stats != (Stats{Received: 3, Analysed: 1, Stopped: 2}) {
		t.Errorf("stats = %+v", stats)
	}
	gaps := ofType(lines, "gap")
	if len(gaps) != 1 || gaps[0]["missed"] != 2.0 || gaps[0]["reason"] != "IDS stopped" || gaps[0]["source"] != "ids" ||
		gaps[0]["from"] != "2026-11-18T10:00:02Z" || gaps[0]["to"] != "2026-11-18T10:00:03Z" {
		t.Errorf("gaps = %v", gaps)
	}
}

// A panic in the analysis of one copy is logged and counted; the IDS goes
// on.
func TestPanicInAnalysisIsContained(t *testing.T) {
	h := start(t, options{
		wrap: func(analyze func(*copyframe.Copy) error) func(*copyframe.Copy) error {
			return func(c *copyframe.Copy) error {
				if c.Target == "/panic" {
					panic("test panic")
				}
				return analyze(c)
			}
		},
	})
	c := connect(t, h.socket)
	c.send(testCopy(1, "shop.example.com", "/panic"))
	c.send(testCopy(2, "shop.example.com", "/search?q=1+union+select+2"))
	eventually(t, "the second copy is analysed", func() bool { return h.srv.Stats().Analysed == 1 })
	stats, _ := h.stop(5 * time.Second)
	if stats != (Stats{Received: 2, Analysed: 1, Failed: 1}) {
		t.Errorf("stats = %+v", stats)
	}
	if logs := h.logs.String(); !strings.Contains(logs, "the analysis of a copy stopped with an internal error: test panic") {
		t.Errorf("log: %s", logs)
	}
}

// M11: secrets in a copy never reach the records: a password parameter, a
// secret cookie, the Authorization header, and the profile's secret JSON
// field and header (F8), also with full_requests on. The log holds no
// request value either.
func TestNoSecretReachesTheRecords(t *testing.T) {
	h := start(t, options{full: true})
	c := connect(t, h.socket)
	query := testCopy(1, "shop.example.com", "/search?q=1+union+select+2&password=S3CR3T-1+union+select")
	query.Headers = append(query.Headers,
		copyframe.Header{Name: "Cookie", Value: "sid=S3CR3T-2 union select 1"},
		copyframe.Header{Name: "Authorization", Value: "Bearer S3CR3T-3 union select"})
	pay := testCopy(2, "shop.example.com", "/api/pay")
	pay.Meta.Application = "shop"
	pay.Method = "POST"
	pay.Headers = append(pay.Headers,
		copyframe.Header{Name: "Content-Type", Value: "application/json"},
		copyframe.Header{Name: "X-Key", Value: "S3CR3T-4"})
	pay.Body = []byte(`{"card": {"number": "S3CR3T-5 union select"}, "note": "1 union select 2"}`)
	pay.Meta.Request.BodyLength = int64(len(pay.Body))
	pay.ResponseHeaders = append(pay.ResponseHeaders, copyframe.Header{Name: "Set-Cookie", Value: "sid=S3CR3T-6"})
	c.send(query)
	c.send(pay)
	eventually(t, "both copies are analysed", func() bool { return h.srv.Stats().Analysed == 2 })
	_, lines := h.stop(5 * time.Second)
	if n := len(ofType(lines, "request")); n != 2 {
		t.Fatalf("%d request records, want 2", n)
	}
	data, err := os.ReadFile(filepath.Join(h.dir, record.CurrentFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("S3CR3T")) {
		t.Errorf("a secret is in the records:\n%s", data)
	}
	if !bytes.Contains(data, []byte(`"full":`)) {
		t.Error("full_requests wrote no full request, so the test checks less than it should")
	}
	if strings.Contains(h.logs.String(), "S3CR3T") {
		t.Errorf("a secret is in the log:\n%s", h.logs.String())
	}
}
