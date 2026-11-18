package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// testLive is what a live input knows of secretRequest besides the request.
func testLive() *Live {
	return &Live{
		Proxy:      Proxy{RequestID: "6f1c2d3e-0b4a-4c5d-9e8f-123456789abc", Received: time.Date(2026, 10, 23, 13, 15, 1, 500_000_000, time.FixedZone("TRT", 3*3600))},
		Connection: Client{IP: "10.0.0.2", Port: 40000},
		TLS:        &TLS{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ServerName: "shop.example.com", ALPN: "h2"},
		Response:   &Response{Status: 200, ContentType: "text/html; charset=utf-8", Encoding: "gzip", BodyLength: 5120, BodyCopied: 0, Note: "type not copied"},
	}
}

func buildLive(t *testing.T, live *Live) (Request, []byte) {
	t.Helper()
	res := loadRules(t).Evaluate(secretRequest())
	rec := testBuilder(false).build(res.Request, res, nil, live, "id3", "run1", time.Date(2026, 10, 23, 10, 15, 2, 0, time.UTC))
	line, err := marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return rec, line
}

// TestLiveLineFormat pins the request record of a live input: the proxy's
// ID and time, the connection, TLS and the response (A01, T5, T10, C6),
// next to everything an offline record has.
func TestLiveLineFormat(t *testing.T) {
	_, line := buildLive(t, testLive())
	if strings.Contains(string(line), "S3CR3T") {
		t.Fatalf("a secret is in the record:\n%s", line)
	}
	golden := filepath.Join("testdata", "request-record-live.json")
	if *update {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, line, "", "  "); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, append(pretty.Bytes(), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')
	if !bytes.Equal(compact.Bytes(), line) {
		t.Errorf("the record line changed:\n got %s\nwant %s", line, compact.Bytes())
	}
}

// The live parts are texts from the client or the application, so they
// pass through the secrets too: a server name that holds a password is
// masked like a User-Agent that holds one.
func TestLivePartsAreMasked(t *testing.T) {
	live := testLive()
	live.TLS.ServerName = "S3CR3T-1+union+select"
	live.Response.ContentType = "text/plain; x=S3CR3T-6 union select"
	rec, line := buildLive(t, live)
	if strings.Contains(string(line), "S3CR3T") {
		t.Fatalf("a secret is in the record:\n%s", line)
	}
	if rec.TLS.ServerName != Masked || !strings.Contains(rec.Response.ContentType, Masked) {
		t.Errorf("server name %q, content type %q", rec.TLS.ServerName, rec.Response.ContentType)
	}
}

// An offline record has none of the live parts, so its format is what it
// was (TestLineFormat).
func TestOfflineRecordHasNoLiveParts(t *testing.T) {
	rec, _ := build(t, secretRequest(), false)
	if rec.Proxy != nil || rec.Connection != nil || rec.TLS != nil || rec.Response != nil {
		t.Errorf("live parts in an offline record: %+v %+v %+v %+v", rec.Proxy, rec.Connection, rec.TLS, rec.Response)
	}
}

// A live run names its input in the start record. Its counts say how many
// copiers were connected and which unknown application names came (T6),
// and its gaps say what was not analysed (T7, T8).
func TestLiveRecorder(t *testing.T) {
	rs := loadRules(t)
	dir := filepath.Join(t.TempDir(), "records")
	c := &clock{t: time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)}
	input := &Input{Kind: InputLive, Socket: "/run/ids/copy.sock"}
	r, err := open(Config{Dir: dir}, testEngine, rs.Statuses(), nil, input, c.now)
	if err != nil {
		t.Fatal(err)
	}
	add := func(target, app string) {
		res := rs.Evaluate(httpmodel.New(httpmodel.Received{Method: "GET", Target: target}))
		if err := r.AddWith(res.Request, res, nil, &Live{UnknownApplication: app}); err != nil {
			t.Fatal(err)
		}
	}
	r.SetCopiers(1)
	add("/?q=1+union+select+2", "shop2")
	add("/?q=books", "shop2")
	add("/?q=pens", "")
	r.SetCopiers(2)
	r.SetCopiers(1)
	from := time.Date(2026, 10, 23, 12, 59, 0, 0, time.FixedZone("TRT", 3*3600))
	if err := r.Gap(from, from.Add(30*time.Second), 1240, "not connected", GapCopier); err != nil {
		t.Fatal(err)
	}
	c.add(time.Minute)
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	r.SetCopiers(0)
	c.add(time.Minute)
	if err := r.Flush(); err != nil { // the copier left during this period
		t.Fatal(err)
	}
	c.add(time.Minute)
	if err := r.Close(); err != nil { // no copier in this one
		t.Fatal(err)
	}

	lines := readLines(t, filepath.Join(dir, CurrentFile))
	var types []string
	for _, l := range lines {
		types = append(types, l["type"].(string))
	}
	if want := []string{"start", "request", "gap", "counts", "counts", "counts"}; !reflect.DeepEqual(types, want) {
		t.Fatalf("types = %v, want %v", types, want)
	}
	if got := lines[0]["input"]; !reflect.DeepEqual(got, map[string]any{"kind": "live", "socket": "/run/ids/copy.sock"}) {
		t.Errorf("start input = %v", got)
	}
	gap := lines[2]
	want := map[string]any{
		"type": "gap", "schema": 1.0, "run": r.Run(),
		"from": "2026-10-23T09:59:00Z", "to": "2026-10-23T09:59:30Z",
		"missed": 1240.0, "reason": "not connected", "source": "copier",
	}
	if !reflect.DeepEqual(gap, want) {
		t.Errorf("gap = %v\nwant %v", gap, want)
	}
	counts := lines[3]
	if counts["analysed"] != 3.0 || counts["copiers"] != 2.0 ||
		!reflect.DeepEqual(counts["unknown_applications"], map[string]any{"shop2": 2.0}) {
		t.Errorf("first counts = %v", counts)
	}
	if lines[4]["copiers"] != 1.0 || lines[5]["copiers"] != 0.0 {
		t.Errorf("copiers = %v, then %v; want 1, then 0", lines[4]["copiers"], lines[5]["copiers"])
	}
	if _, ok := lines[4]["unknown_applications"]; ok {
		t.Errorf("unknown applications carried into the next period: %v", lines[4])
	}
}

// An offline run writes neither an input nor copiers, so its records are
// what they were.
func TestOfflineRunHasNoInputOrCopiers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	r, err := Open(Config{Dir: dir}, testEngine, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.SetCopiers(1)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(dir, CurrentFile))
	if _, ok := lines[0]["input"]; ok {
		t.Errorf("start has an input: %v", lines[0])
	}
	if _, ok := lines[1]["copiers"]; ok {
		t.Errorf("counts have copiers: %v", lines[1])
	}
}

// C5: one writer per records folder. A second writer is refused until the
// first one closes; the lock file stays, private like the records.
func TestSecondWriterIsRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the records folder is locked on Linux only")
	}
	dir := filepath.Join(t.TempDir(), "records")
	first, err := Open(Config{Dir: dir}, testEngine, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(Config{Dir: dir}, testEngine, nil, nil)
	if !errors.Is(err, ErrInUse) || !strings.Contains(err.Error(), "the records folder is in use by another writer") {
		t.Fatalf("a second writer gets %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(Config{Dir: dir}, testEngine, nil, nil)
	if err != nil {
		t.Fatalf("after the first writer closed: %v", err)
	}
	defer second.Close()
	info, err := os.Stat(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %v, want 0600", LockFile, info.Mode().Perm())
	}
	// The refused writer wrote nothing: the file has the two runs' start
	// and counts records only.
	second.Close()
	if n := len(readLines(t, filepath.Join(dir, CurrentFile))); n != 4 {
		t.Errorf("%d lines, want 4", n)
	}
}
