package live_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/live"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// exampleFiles are the repository's example requests that are not CRS
// tests: attacks, secrets, and the generated variants.
var exampleFiles = []string{
	"../../testdata/requests/path-traversal.json",
	"../../testdata/requests/common-exceptions.json",
	"../../testdata/requests/secrets.json",
	"../../testdata/requests/generated/file-access-variants.json",
	"../../testdata/requests/generated/injection-variants.json",
	"../../testdata/requests/generated/traversal-variants.json",
}

// The live input gives the same request records as ids-offline for the
// same requests, with the real CRS rules, the CSIC profile and four
// workers at once: what goes through a frame, the socket and the queue is
// analysed as it is from a file (M01, M21). The lab repeats this through
// Caddy (T9).
func TestLiveMatchesOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the CRS rules on 1,318 requests twice")
	}
	cfg, err := config.Load("../../configs/csic-shop.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		t.Fatal(err)
	}
	eng := record.NewEngine(rules, "sha256:test")

	var examples []offline.Example
	for _, f := range exampleFiles {
		ex, err := offline.LoadFileWith(f, cfg.Parsing())
		if err != nil {
			t.Fatal(err)
		}
		examples = append(examples, ex...)
	}
	// A request line without a version (HTTP/0.9) can't be a copy: Go's
	// server, and so Caddy, never passes one on.
	examples = slices.DeleteFunc(examples, func(ex offline.Example) bool { return ex.Request.Received.Version == "" })
	if len(examples) != 1318 {
		t.Fatalf("%d examples, want 1318", len(examples))
	}

	// ids-offline's way.
	offDir := filepath.Join(t.TempDir(), "offline")
	off, err := record.Open(record.Config{Dir: offDir}, eng, rules.Statuses(), apps)
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range examples {
		app := apps.Match(ex.Request)
		var tuning *engine.Tuning
		if app != nil {
			tuning = app.Tuning
		}
		res := rules.EvaluateWith(ex.Request, tuning)
		prof := apps.Check(res.Request, app)
		if err := off.Add(res.Request, res, &prof); err != nil {
			t.Fatal(err)
		}
	}
	if err := off.Close(); err != nil {
		t.Fatal(err)
	}

	// The live way, through the socket.
	liveDir := filepath.Join(t.TempDir(), "live")
	rec, err := record.OpenWith(record.Config{Dir: liveDir}, eng, rules.Statuses(), apps, &record.Input{Kind: record.InputLive})
	if err != nil {
		t.Fatal(err)
	}
	short, err := os.MkdirTemp("", "ids")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	socket := filepath.Join(short, "copy.sock")
	a := &live.Analyzer{Rules: rules, Apps: apps, Recorder: rec, Parsing: cfg.Parsing()}
	srv, err := live.Listen(live.Config{Socket: socket, Workers: 4, QueueCopies: len(examples)}, rec, a.Analyze, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := copyframe.AppendHello(nil, copyframe.Hello{Format: copyframe.Version, Program: "test copier"})
	if err != nil {
		t.Fatal(err)
	}
	for i, ex := range examples {
		frames, err = copyframe.AppendCopy(frames, asCopy(i, ex.Request))
		if err != nil {
			t.Fatalf("example %d (%s): %v", i, ex.Name, err)
		}
	}
	go conn.Write(frames)
	r := copyframe.NewReader(conn, 1<<20)
	if f, err := r.Next(); err != nil || f.Hello.Error != "" {
		t.Fatalf("hello: %+v, %v", f, err)
	}
	for end := time.Now().Add(10 * time.Minute); srv.Stats().Analysed < int64(len(examples)); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("analysed %d of %d", srv.Stats().Analysed, len(examples))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stats := srv.Shutdown(ctx)
	cancel()
	conn.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if stats != (live.Stats{Received: int64(len(examples)), Analysed: int64(len(examples))}) {
		t.Errorf("stats = %+v", stats)
	}

	offRecords, offAnalysed := requestRecords(t, offDir)
	liveRecords, liveAnalysed := requestRecords(t, liveDir)
	if offAnalysed != len(examples) || liveAnalysed != len(examples) {
		t.Errorf("analysed: offline %d, live %d, want %d", offAnalysed, liveAnalysed, len(examples))
	}
	if len(offRecords) == 0 || !slices.Equal(offRecords, liveRecords) {
		t.Errorf("%d request records offline, %d live; the first that differ:", len(offRecords), len(liveRecords))
		for i := range min(len(offRecords), len(liveRecords)) {
			if offRecords[i] != liveRecords[i] {
				t.Errorf("offline %s\nlive    %s", offRecords[i], liveRecords[i])
				break
			}
		}
	}
	t.Logf("%d requests, %d request records, the same in both", len(examples), len(offRecords))
}

// asCopy makes the copy a copier would send for a request.
func asCopy(i int, req *httpmodel.Request) *copyframe.Copy {
	r := req.Received
	c := &copyframe.Copy{
		Meta: copyframe.Meta{
			ID:      "example-" + strconv.Itoa(i),
			Time:    time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Millisecond),
			Client:  copyframe.Addr{IP: r.RemoteAddr, Port: r.RemotePort},
			Server:  copyframe.Addr{IP: r.LocalAddr, Port: r.LocalPort},
			Request: copyframe.RequestMeta{BodyLength: int64(len(r.Body)), BodyComplete: true},
		},
		Method: r.Method,
		Target: r.Target,
		Proto:  r.Version,
		Body:   r.Body,
	}
	for _, h := range r.Headers {
		c.Headers = append(c.Headers, copyframe.Header{Name: h.Name, Value: h.Value})
	}
	return c
}

// requestRecords returns the request records of dir, without what differs
// between two runs or comes only from a live input, as sorted JSON texts;
// and the number of requests the counts records say were analysed.
func requestRecords(t *testing.T, dir string) ([]string, int) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, record.CurrentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	analysed := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		switch m["type"] {
		case record.TypeCounts:
			analysed += int(m["analysed"].(float64))
		case record.TypeRequest:
			for _, k := range []string{"id", "run", "time", "proxy", "connection", "tls", "response"} {
				delete(m, k)
			}
			// Each folder has its own hash key.
			delete(m["request"].(map[string]any), "cookies")
			text, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(text))
		}
	}
	slices.Sort(out)
	return out, analysed
}
