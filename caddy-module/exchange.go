package idscopy

import (
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
)

// exchange is one request and its response while they pass. The request
// body may be read in another goroutine than the one that writes the
// response (Caddy's reverse proxy does that), and MaxWait's timer runs in
// a third, so everything is under mu.
type exchange struct {
	c     *Copier
	start time.Time

	mu   sync.Mutex
	sent bool
	cp   copyframe.Copy

	contentLength int64 // of the request, -1 when unknown
	reqLength     int64
	reqDone       bool

	wroteHeader bool
	copyBody    bool
	respLength  int64
	upgraded    bool
}

// newExchange takes what is known of the request before any handler
// runs: the request line and headers as received, the addresses and TLS.
func newExchange(c *Copier, r *http.Request) *exchange {
	ex := &exchange{c: c, start: time.Now(), contentLength: r.ContentLength}
	if t, ok := caddyhttp.GetVar(r.Context(), "start_time").(time.Time); ok {
		ex.start = t
	}
	m := &ex.cp.Meta
	m.ID = requestID(r)
	m.Time = ex.start.UTC()
	m.Application = c.Application

	connIP, connPort := splitAddr(r.RemoteAddr)
	m.Connection = copyframe.Addr{IP: connIP, Port: connPort}
	// The client is Caddy's: the connection's address, or the one a
	// trusted proxy in front gave (trusted_proxies, T5). The port is known
	// only when it is the connection's.
	if ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ip != "" && validIP(ip) {
		m.Client.IP = ip
		if ip == connIP {
			m.Client.Port = connPort
		}
	}
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		ip, port := splitAddr(addr.String())
		m.Server = copyframe.Addr{IP: ip, Port: port}
	}
	if s := r.TLS; s != nil {
		m.TLS = &copyframe.TLS{
			Version:    tls.VersionName(s.Version),
			Cipher:     tls.CipherSuiteName(s.CipherSuite),
			ServerName: s.ServerName,
			ALPN:       s.NegotiatedProtocol,
		}
		if !printable(m.TLS.ServerName, 255) {
			m.TLS.ServerName = ""
		}
	}

	ex.cp.Method = r.Method
	ex.cp.Target = r.RequestURI
	if ex.cp.Target == "" {
		ex.cp.Target = r.URL.RequestURI()
	}
	ex.cp.Proto = r.Proto
	ex.cp.Headers = requestHeaders(r)
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		ex.reqDone = true
	}
	return ex
}

// requestID returns Caddy's ID of the request, the {http.request.uuid} of
// its logs, so that a record can be found there. Asking for it also puts
// it in the request's access log line.
func requestID(r *http.Request) string {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		if id, ok := repl.GetString("http.request.uuid"); ok && id != "" {
			return id
		}
	}
	// Outside a Caddy server, as in tests.
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// requestHeaders rebuilds the request's header lines from Go's header map
// (docs/copy-format.md, section 4.3): Host first, then the others sorted by
// name, the values of one name in their order. Go keeps Host and
// Transfer-Encoding out of the map; they come back from their own fields.
func requestHeaders(r *http.Request) []copyframe.Header {
	var headers []copyframe.Header
	if r.Host != "" {
		headers = append(headers, copyframe.Header{Name: "Host", Value: r.Host})
	}
	names := make([]string, 0, len(r.Header)+1)
	for name := range r.Header {
		if name != "Host" {
			names = append(names, name)
		}
	}
	if len(r.TransferEncoding) > 0 && r.Header["Transfer-Encoding"] == nil {
		names = append(names, "Transfer-Encoding")
	}
	slices.Sort(names)
	for _, name := range names {
		if name == "Transfer-Encoding" && r.Header[name] == nil {
			headers = append(headers, copyframe.Header{Name: name, Value: strings.Join(r.TransferEncoding, ", ")})
			continue
		}
		for _, v := range r.Header[name] {
			headers = append(headers, copyframe.Header{Name: name, Value: v})
		}
	}
	return headers
}

// splitAddr returns the IP and port of an address such as
// "203.0.113.7:51234" or "[::1]:443", or empty values when it is not one.
func splitAddr(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !validIP(host) {
		return "", 0
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return host, 0
	}
	return host, p
}

func validIP(s string) bool {
	return net.ParseIP(strings.SplitN(s, "%", 2)[0]) != nil
}

// bodyReader copies the request body as the application reads it, up to
// the limit, and counts all of it (T3).
type bodyReader struct {
	io.ReadCloser
	ex *exchange
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	ex := b.ex
	ex.mu.Lock()
	if !ex.sent {
		if room := ex.c.RequestBodyLimit - int64(len(ex.cp.Body)); room > 0 {
			ex.cp.Body = append(ex.cp.Body, p[:min(int64(n), room)]...)
		}
		ex.reqLength += int64(n)
		if errors.Is(err, io.EOF) || ex.contentLength >= 0 && ex.reqLength >= ex.contentLength {
			ex.reqDone = true
		}
	}
	ex.mu.Unlock()
	return n, err
}

// responseWriter copies the response as the application writes it. It
// keeps Caddy's wrapper, whose Unwrap lets http.ResponseController reach
// Flush and Hijack of the real writer.
type responseWriter struct {
	*caddyhttp.ResponseWriterWrapper
	ex *exchange
}

func (w *responseWriter) WriteHeader(status int) {
	w.ex.header(status, w.Header(), nil)
	w.ResponseWriterWrapper.WriteHeader(status)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	// Without WriteHeader, Go's server sends 200 and, when no type is set,
	// one it sniffs from the first bytes.
	w.ex.header(http.StatusOK, w.Header(), p)
	n, err := w.ResponseWriter.Write(p)
	w.ex.body(p[:n])
	return n, err
}

// ReadFrom keeps the fast path of the real writer (sendfile for a static
// file) when the body is not copied, and counts what passes.
func (w *responseWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.ex.copying() {
		return io.Copy(writerOnly{w}, r)
	}
	n, err := w.ResponseWriterWrapper.ReadFrom(r)
	w.ex.count(n)
	return n, err
}

// writerOnly hides ReadFrom, so that io.Copy calls Write.
type writerOnly struct{ io.Writer }

// header notes the response's status and headers, once. A 1xx other than
// 101 is not the final response. first is the first body bytes, for a
// response without WriteHeader.
func (ex *exchange) header(status int, h http.Header, first []byte) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.wroteHeader || ex.sent || status < 200 && status != http.StatusSwitchingProtocols {
		return
	}
	ex.wroteHeader = true
	headers := responseHeaders(h)
	contentType := h.Get("Content-Type")
	if _, typed := h["Content-Type"]; !typed && first != nil && h.Get("Content-Encoding") == "" && h.Get("Transfer-Encoding") == "" {
		contentType = http.DetectContentType(first)
		headers = append(headers, copyframe.Header{Name: "Content-Type", Value: contentType})
	}
	ex.cp.Meta.Response = &copyframe.ResponseMeta{Status: status}
	ex.cp.ResponseHeaders = headers
	media, _, _ := mime.ParseMediaType(contentType)
	ex.copyBody = ex.c.types[media]
	if status == http.StatusSwitchingProtocols {
		// The connection becomes, for example, a WebSocket, which may
		// stay open for hours: the copy goes now (C7).
		ex.upgraded = true
		ex.sendLocked(copyframe.NoteUpgraded)
	}
}

// responseHeaders returns the response's header lines, sorted by name.
func responseHeaders(h http.Header) []copyframe.Header {
	names := make([]string, 0, len(h))
	for name := range h {
		// Trailer values announced ahead are not header lines yet.
		if !strings.HasPrefix(name, http.TrailerPrefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	var headers []copyframe.Header
	for _, name := range names {
		for _, v := range h[name] {
			headers = append(headers, copyframe.Header{Name: name, Value: v})
		}
	}
	return headers
}

func (ex *exchange) body(p []byte) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.sent {
		return
	}
	ex.respLength += int64(len(p))
	if ex.copyBody {
		if room := ex.c.ResponseBodyLimit - int64(len(ex.cp.ResponseBody)); room > 0 {
			ex.cp.ResponseBody = append(ex.cp.ResponseBody, p[:min(int64(len(p)), room)]...)
		}
	}
}

func (ex *exchange) count(n int64) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if !ex.sent {
		ex.respLength += n
	}
}

// copying reports whether the response's status is known and its body is
// still being copied.
func (ex *exchange) copying() bool {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	return !ex.wroteHeader || !ex.sent && ex.copyBody && int64(len(ex.cp.ResponseBody)) < ex.c.ResponseBodyLimit
}

// timeout sends the copy when the response has not ended after MaxWait
// (C7).
func (ex *exchange) timeout() {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	ex.sendLocked(copyframe.NoteNotFinished)
}

// finish sends the copy when the handlers are done. err is what they
// returned: when it is an error and nothing was written yet, Caddy writes
// the error's response itself, after this handler; the copy then has its
// status only.
func (ex *exchange) finish(err error) {
	ex.mu.Lock()
	defer ex.mu.Unlock()
	if ex.sent {
		return
	}
	if !ex.wroteHeader {
		status := http.StatusOK // Caddy's answer when no handler wrote one
		note := ""
		if err != nil {
			status = http.StatusInternalServerError
			if he, ok := errors.AsType[caddyhttp.HandlerError](err); ok && he.StatusCode != 0 {
				status = he.StatusCode
			}
			note = copyframe.NoteHandlerError
		}
		ex.wroteHeader = true
		ex.cp.Meta.Response = &copyframe.ResponseMeta{Status: status}
		ex.sendLocked(note)
		return
	}
	ex.sendLocked("")
}

// sendLocked completes the copy and gives it to the sender. Nothing is
// copied after it.
func (ex *exchange) sendLocked(note string) {
	if ex.sent {
		return
	}
	ex.sent = true
	m := &ex.cp.Meta
	m.DurationMS = float64(time.Since(ex.start).Microseconds()) / 1000
	m.Request = copyframe.RequestMeta{BodyLength: max(ex.reqLength, int64(len(ex.cp.Body))), BodyComplete: ex.reqDone}
	if r := m.Response; r != nil {
		r.BodyLength = ex.respLength
		switch {
		case note != "":
			r.Note = note
		case ex.respLength > 0 && !ex.copyBody:
			r.Note = copyframe.NoteTypeNotCopied
		}
	}
	cp := ex.cp
	ex.c.sender.add(&cp)
}
