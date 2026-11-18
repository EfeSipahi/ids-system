package idscopy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
)

// shortSocket returns a socket path short enough for Linux.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ids")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "copy.sock")
}

// fakeIDS is ids-live's side of the socket: it answers hello with its
// frame limit and collects the frames.
type fakeIDS struct {
	t        *testing.T
	ln       *net.UnixListener
	maxFrame int64
	frames   chan copyframe.Frame
	conns    chan net.Conn
	mu       sync.Mutex
	accepted int
}

func newFakeIDS(t *testing.T, socket string, maxFrame int64) *fakeIDS {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDS{t: t, ln: ln, maxFrame: maxFrame, frames: make(chan copyframe.Frame, 100), conns: make(chan net.Conn, 10)}
	t.Cleanup(func() { ln.Close() })
	go f.accept()
	return f
}

func (f *fakeIDS) accept() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.accepted++
		f.mu.Unlock()
		f.conns <- conn
		go func() {
			defer conn.Close()
			r := copyframe.NewReader(conn, 1<<30)
			hello, err := r.Next()
			if err != nil || hello.Type != copyframe.TypeHello || hello.Hello.Program != Program {
				return
			}
			reply, _ := copyframe.AppendHello(nil, copyframe.Hello{Format: copyframe.Version, Program: "fake ids-live", MaxFrame: f.maxFrame})
			conn.Write(reply)
			for {
				fr, err := r.Next()
				if err != nil {
					return
				}
				if fr.Size > f.maxFrame {
					f.t.Errorf("a frame of %d bytes, over the limit of %d", fr.Size, f.maxFrame)
				}
				f.frames <- fr
			}
		}()
	}
}

func (f *fakeIDS) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted
}

// next returns the next frame, waiting up to five seconds.
func (f *fakeIDS) next() copyframe.Frame {
	f.t.Helper()
	select {
	case fr := <-f.frames:
		return fr
	case <-time.After(5 * time.Second):
		f.t.Fatal("no frame from the copier")
	}
	return copyframe.Frame{}
}

// nextCopy returns the next copy frame.
func (f *fakeIDS) nextCopy() *copyframe.Copy {
	f.t.Helper()
	fr := f.next()
	if fr.Type != copyframe.TypeCopy {
		f.t.Fatalf("a %s frame, not a copy: %+v", fr.Type, fr.Missed)
	}
	return fr.Copy
}

// none checks that no frame comes for a while.
func (f *fakeIDS) none(d time.Duration) {
	f.t.Helper()
	select {
	case fr := <-f.frames:
		f.t.Fatalf("an unexpected %s frame", fr.Type)
	case <-time.After(d):
	}
}

// provision makes a copier for socket and waits until its sender is
// connected when wait is set.
func provision(t *testing.T, c *Copier, wait bool) *Copier {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := c.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Cleanup() })
	if wait {
		for end := time.Now().Add(5 * time.Second); !c.sender.isConnected(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatal("the copier does not connect")
			}
		}
	}
	return c
}

func (s *sender) isConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

// serve runs the copier on a request, prepared as Caddy prepares it, with
// next as the application.
func serve(t *testing.T, c *Copier, r *http.Request, next func(http.ResponseWriter, *http.Request) error) (*httptest.ResponseRecorder, error) {
	t.Helper()
	w := httptest.NewRecorder()
	r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, nil)
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	err := c.ServeHTTP(w, r, caddyhttp.HandlerFunc(next))
	return w, err
}

// readAll is an application that reads the whole body and answers text.
func readAll(w http.ResponseWriter, r *http.Request) error {
	io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("thanks"))
	return nil
}

// A copy holds the request as received, the facts only the proxy knows,
// and the response (docs/copy-format.md, section 4).
func TestCopy(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket, Application: "shop"}, true)

	r := httptest.NewRequest("POST", "https://shop.example.com/login?next=%2Fhome", strings.NewReader("user=ali&pwd=x"))
	r.RequestURI = "/login?next=%2Fhome" // as on the request line
	r.RemoteAddr = "203.0.113.7:51234"
	r.Header = http.Header{
		"User-Agent":      {"test"},
		"Content-Type":    {"application/x-www-form-urlencoded"},
		"Accept":          {"text/html", "*/*"},
		"X-Forwarded-For": {"198.51.100.1"},
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: "shop.example.com", NegotiatedProtocol: "h2"}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 443}))
	if _, err := serve(t, c, r, readAll); err != nil {
		t.Fatal(err)
	}
	cp := ids.nextCopy()

	if cp.Method != "POST" || cp.Target != "/login?next=%2Fhome" || cp.Proto != "HTTP/1.1" {
		t.Errorf("request line %q %q %q", cp.Method, cp.Target, cp.Proto)
	}
	// Host first, then the other names sorted, the values of one name in
	// their order (docs/copy-format.md, section 4.3).
	want := []copyframe.Header{
		{Name: "Host", Value: "shop.example.com"},
		{Name: "Accept", Value: "text/html"},
		{Name: "Accept", Value: "*/*"},
		{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
		{Name: "User-Agent", Value: "test"},
		{Name: "X-Forwarded-For", Value: "198.51.100.1"},
	}
	if !reflect.DeepEqual(cp.Headers, want) {
		t.Errorf("headers %v\nwant %v", cp.Headers, want)
	}
	if string(cp.Body) != "user=ali&pwd=x" {
		t.Errorf("body %q", cp.Body)
	}
	m := cp.Meta
	if len(m.ID) != 36 || m.Application != "shop" || m.Time.IsZero() || m.DurationMS < 0 {
		t.Errorf("id %q, application %q, time %v, duration %v", m.ID, m.Application, m.Time, m.DurationMS)
	}
	// The client is Caddy's, never the X-Forwarded-For header (T5).
	if m.Client != (copyframe.Addr{IP: "203.0.113.7", Port: 51234}) || m.Connection != (copyframe.Addr{IP: "203.0.113.7", Port: 51234}) ||
		m.Server != (copyframe.Addr{IP: "10.0.0.5", Port: 443}) {
		t.Errorf("client %v, connection %v, server %v", m.Client, m.Connection, m.Server)
	}
	if *m.TLS != (copyframe.TLS{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ServerName: "shop.example.com", ALPN: "h2"}) {
		t.Errorf("tls %+v", *m.TLS)
	}
	if m.Request != (copyframe.RequestMeta{BodyLength: 14, BodyComplete: true}) {
		t.Errorf("request %+v", m.Request)
	}
	if *m.Response != (copyframe.ResponseMeta{Status: 200, BodyLength: 6}) || string(cp.ResponseBody) != "thanks" ||
		!reflect.DeepEqual(cp.ResponseHeaders, []copyframe.Header{{Name: "Content-Type", Value: "text/plain; charset=utf-8"}}) {
		t.Errorf("response %+v %v %q", *m.Response, cp.ResponseHeaders, cp.ResponseBody)
	}
}

// T3: the body is copied up to the limit and counted to its end. A body
// the application did not read to its end is marked so.
func TestRequestBody(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket, RequestBodyLimit: 10}, true)
	for _, tt := range []struct {
		body     string
		read     int // -1: all
		copied   string
		length   int64
		complete bool
	}{
		{"123456789", -1, "123456789", 9, true},
		{"1234567890", -1, "1234567890", 10, true},
		{"12345678901", -1, "1234567890", 11, true},
		{"1234567890", 3, "123", 3, false}, // the application stopped reading
		{"", -1, "", 0, true},
	} {
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(tt.body))
		serve(t, c, r, func(w http.ResponseWriter, r *http.Request) error {
			if tt.read < 0 {
				io.Copy(io.Discard, r.Body)
			} else {
				io.ReadFull(r.Body, make([]byte, tt.read))
			}
			return nil
		})
		cp := ids.nextCopy()
		if string(cp.Body) != tt.copied || cp.Meta.Request != (copyframe.RequestMeta{BodyLength: tt.length, BodyComplete: tt.complete}) {
			t.Errorf("body %q read %d: copied %q, %+v", tt.body, tt.read, cp.Body, cp.Meta.Request)
		}
	}
}

// A chunked body: Go keeps Transfer-Encoding out of the header map; the
// copy has it back, in its sorted place, and the body ends at EOF.
func TestChunkedBody(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket}, true)
	r := httptest.NewRequest("POST", "/", strings.NewReader("abc"))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Header = http.Header{"Content-Type": {"text/plain"}, "Via": {"1.1 x"}}
	serve(t, c, r, readAll)
	cp := ids.nextCopy()
	want := []copyframe.Header{
		{Name: "Host", Value: "example.com"},
		{Name: "Content-Type", Value: "text/plain"},
		{Name: "Transfer-Encoding", Value: "chunked"},
		{Name: "Via", Value: "1.1 x"},
	}
	if !reflect.DeepEqual(cp.Headers, want) || cp.Meta.Request != (copyframe.RequestMeta{BodyLength: 3, BodyComplete: true}) {
		t.Errorf("headers %v, request %+v", cp.Headers, cp.Meta.Request)
	}
}

// T4: the response body is copied for the listed types only, up to the
// limit; for others the copy says why it has none.
func TestResponseBody(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket, ResponseBodyLimit: 5}, true)
	for _, tt := range []struct {
		name        string
		contentType string // "-" for none
		body        string
		copied      string
		note        string
		sniffed     string
	}{
		{"text", "text/plain", "hello world", "hello", "", ""},
		{"html with charset, any case", "Text/HTML; charset=UTF-8", "<p>hi</p>", "<p>hi", "", ""},
		{"image", "image/png", "\x89PNG....", "", copyframe.NoteTypeNotCopied, ""},
		{"json", "application/json", `{"a":1}`, "", copyframe.NoteTypeNotCopied, ""},
		{"sniffed", "-", "<html><body>x</body></html>", "<html", "", "text/html; charset=utf-8"},
		{"empty", "image/png", "", "", "", ""},
	} {
		serve(t, c, httptest.NewRequest("GET", "/", nil), func(w http.ResponseWriter, r *http.Request) error {
			if tt.contentType != "-" {
				w.Header().Set("Content-Type", tt.contentType)
			}
			io.WriteString(w, tt.body)
			return nil
		})
		cp := ids.nextCopy()
		r := cp.Meta.Response
		if string(cp.ResponseBody) != tt.copied || r.BodyLength != int64(len(tt.body)) || r.Note != tt.note {
			t.Errorf("%s: copied %q, length %d, note %q", tt.name, cp.ResponseBody, r.BodyLength, r.Note)
		}
		if tt.sniffed != "" && !reflect.DeepEqual(cp.ResponseHeaders, []copyframe.Header{{Name: "Content-Type", Value: tt.sniffed}}) {
			t.Errorf("%s: headers %v", tt.name, cp.ResponseHeaders)
		}
	}
}

// io.Copy into the writer uses ReadFrom, as a static file does; the body
// is still counted, and copied when its type is listed.
func TestResponseReadFrom(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket}, true)
	for _, typ := range []string{"text/html", "application/octet-stream"} {
		serve(t, c, httptest.NewRequest("GET", "/file", nil), func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", typ)
			w.WriteHeader(200)
			_, err := io.Copy(w, strings.NewReader(strings.Repeat("x", 1000)))
			return err
		})
		cp := ids.nextCopy()
		copied := 0
		if typ == "text/html" {
			copied = 1000
		}
		if cp.Meta.Response.BodyLength != 1000 || len(cp.ResponseBody) != copied {
			t.Errorf("%s: length %d, copied %d", typ, cp.Meta.Response.BodyLength, len(cp.ResponseBody))
		}
	}
}

// C7: a response still running after max_wait is sent as it is, "not
// finished", and nothing more is sent for it.
func TestMaxWait(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket, MaxWait: caddy.Duration(50 * time.Millisecond)}, true)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serve(t, c, httptest.NewRequest("GET", "/stream", nil), func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "first ")
			<-release
			io.WriteString(w, "second")
			return nil
		})
	}()
	cp := ids.nextCopy()
	close(release)
	<-done
	if r := cp.Meta.Response; r.Note != copyframe.NoteNotFinished || r.BodyLength != 6 || string(cp.ResponseBody) != "first " {
		t.Errorf("response %+v %q", *r, cp.ResponseBody)
	}
	ids.none(200 * time.Millisecond)
}

// C7: an upgrade, such as a WebSocket, is sent at the upgrade.
func TestUpgrade(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket}, true)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("GET", "/ws", nil)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "Upgrade")
		serve(t, c, r, func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Upgrade", "websocket")
			w.WriteHeader(http.StatusSwitchingProtocols)
			<-release // the WebSocket runs
			return nil
		})
	}()
	cp := ids.nextCopy()
	close(release)
	<-done
	if r := cp.Meta.Response; r.Status != 101 || r.Note != copyframe.NoteUpgraded {
		t.Errorf("response %+v", *r)
	}
	ids.none(100 * time.Millisecond)
}

// When a handler returns an error, Caddy writes the response after the
// copier's part; the copy has the error's status and says so.
func TestHandlerError(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	c := provision(t, &Copier{Socket: socket}, true)
	_, err := serve(t, c, httptest.NewRequest("GET", "/missing", nil), func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusNotFound, errors.New("not found"))
	})
	if err == nil {
		t.Fatal("the error was not passed on")
	}
	cp := ids.nextCopy()
	if r := cp.Meta.Response; *r != (copyframe.ResponseMeta{Status: 404, Note: copyframe.NoteHandlerError}) {
		t.Errorf("response %+v", *r)
	}
	// An error without a status is a 500, as Caddy answers it.
	serve(t, c, httptest.NewRequest("GET", "/broken", nil), func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("broken")
	})
	if r := ids.nextCopy().Meta.Response; r.Status != 500 {
		t.Errorf("status %d", r.Status)
	}
}

// Revised option A (18 November 2026): a copy is fit into the IDS's frame
// limit, request body cut last, its whole length kept. A copy whose heads
// alone don't fit is counted as refused.
func TestFitToTheIDSLimit(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, 2000)
	c := provision(t, &Copier{Socket: socket}, true)
	serve(t, c, httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("b", 5000))), func(w http.ResponseWriter, r *http.Request) error {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("r", 1000))
		return nil
	})
	cp := ids.nextCopy()
	if len(cp.ResponseBody) != 0 || len(cp.Body) == 0 || len(cp.Body) >= 2000 || cp.Meta.Request.BodyLength != 5000 || cp.Meta.Response.BodyLength != 1000 {
		t.Errorf("body %d of %d, response body %d of %d", len(cp.Body), cp.Meta.Request.BodyLength, len(cp.ResponseBody), cp.Meta.Response.BodyLength)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Big", strings.Repeat("h", 3000))
	serve(t, c, r, readAll)
	fr := ids.next()
	if fr.Type != copyframe.TypeMissed || fr.Missed.Reason != copyframe.ReasonRefused || fr.Missed.Count != 1 {
		t.Errorf("frame %s %+v", fr.Type, fr.Missed)
	}
}

// T7: a full queue drops and counts; the count is sent as a missed frame.
func TestFullQueue(t *testing.T) {
	s := &sender{maxCopies: 2, maxBytes: 1 << 20, connected: true, missed: map[string]*copyframe.Missed{}, wake: make(chan struct{}, 1)}
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		s.add(&copyframe.Copy{Meta: copyframe.Meta{Time: t0.Add(time.Duration(i) * time.Second)}})
	}
	if len(s.queue) != 2 {
		t.Errorf("%d queued", len(s.queue))
	}
	m := s.missed[copyframe.ReasonQueueFull]
	if m == nil || m.Count != 3 || !m.From.Equal(t0.Add(2*time.Second)) || !m.To.Equal(t0.Add(4*time.Second)) {
		t.Errorf("missed %+v", m)
	}
	// The bytes limit too.
	// Each copy is counted with 512 bytes of overhead: 1,512 here.
	s = &sender{maxCopies: 10, maxBytes: 3100, connected: true, missed: map[string]*copyframe.Missed{}, wake: make(chan struct{}, 1)}
	for range 3 {
		s.add(&copyframe.Copy{Meta: copyframe.Meta{Time: t0}, Body: make([]byte, 1000)})
	}
	if len(s.queue) != 2 || s.missed[copyframe.ReasonQueueFull].Count != 1 {
		t.Errorf("%d queued, missed %+v", len(s.queue), s.missed)
	}
}

// T8: while ids-live can't be reached, copies are counted; once it is
// back, the copier reconnects within about a second and first sends the
// count.
func TestIDSDownAndBack(t *testing.T) {
	socket := shortSocket(t)
	c := provision(t, &Copier{Socket: socket}, false)
	for range 3 {
		serve(t, c, httptest.NewRequest("GET", "/", nil), readAll)
	}
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	fr := ids.next()
	if fr.Type != copyframe.TypeMissed || fr.Missed.Count != 3 || fr.Missed.Reason != copyframe.ReasonNotConnected {
		t.Fatalf("first frame %s %+v", fr.Type, fr.Missed)
	}
	for end := time.Now().Add(5 * time.Second); !c.sender.isConnected(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("not connected")
		}
	}
	serve(t, c, httptest.NewRequest("GET", "/after", nil), readAll)
	if cp := ids.nextCopy(); cp.Target != "/after" {
		t.Errorf("target %q", cp.Target)
	}

	// ids-live stops: the copier notices, counts, and is back when it is.
	ids.ln.Close()
	conn := <-ids.conns
	conn.Close()
	for end := time.Now().Add(5 * time.Second); c.sender.isConnected(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the copier does not notice that ids-live closed the connection")
		}
	}
	serve(t, c, httptest.NewRequest("GET", "/lost", nil), readAll)
	os.Remove(socket)
	ids2 := newFakeIDS(t, socket, defaultMaxFrame)
	if fr := ids2.next(); fr.Type != copyframe.TypeMissed || fr.Missed.Count != 1 {
		t.Errorf("after the second stop: %s %+v", fr.Type, fr.Missed)
	}
}

// A configuration reload: the new configuration's copier joins the
// sender of the same socket, so the connection stays; the sender stops
// when no configuration uses it.
func TestReloadKeepsTheConnection(t *testing.T) {
	socket := shortSocket(t)
	ids := newFakeIDS(t, socket, defaultMaxFrame)
	old := provision(t, &Copier{Socket: socket, QueueCopies: 5}, true)
	nu := provision(t, &Copier{Socket: socket, QueueCopies: 7}, true)
	if old.sender != nu.sender {
		t.Fatal("two senders for one socket")
	}
	if nu.sender.maxCopies != 7 {
		t.Errorf("queue limit %d; the newest configuration's is 7", nu.sender.maxCopies)
	}
	old.Cleanup()
	serve(t, nu, httptest.NewRequest("GET", "/after-reload", nil), readAll)
	if cp := ids.nextCopy(); cp.Target != "/after-reload" {
		t.Errorf("target %q", cp.Target)
	}
	if n := ids.connections(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
	nu.Cleanup()
	select {
	case <-nu.sender.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the sender does not stop when no configuration uses it")
	}
	if n, ok := senders.References(socket); ok || n != 0 {
		t.Errorf("the pool still has the sender: %d references", n)
	}
}

// The settings are checked.
func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		c    Copier
		want string
	}{
		{Copier{}, "socket is missing"},
		{Copier{Socket: "@ids"}, "abstract sockets"},
		{Copier{Socket: "/" + strings.Repeat("x", 107)}, "Linux allows at most 107"},
		{Copier{Socket: "/s", Application: "a\nb"}, "printable text"},
		{Copier{Socket: "/s", RequestBodyLimit: -1}, "request_body_limit"},
		{Copier{Socket: "/s", ResponseTypes: []string{"text"}}, "not a media type"},
		{Copier{Socket: "/s", ResponseTypes: []string{"text/html; charset=utf-8"}}, "not a media type"},
		{Copier{Socket: "/s", QueueMB: 20000}, "queue_mb"},
	} {
		c := tt.c
		c.withDefaults()
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%+v: %v, want %q", tt.c, err, tt.want)
		}
	}
}

// keep bytes imported for helpers above.
var _ = bytes.Equal
