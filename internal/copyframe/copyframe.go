// Package copyframe reads and writes the frames in which a proxy's copier
// sends copies of requests and responses to the IDS (A01, decisions T2–T8).
// docs/copy-format.md describes the format for other programs.
//
// A frame is a 4-byte big-endian length, a 1-byte type and the content; the
// length counts the type byte and the content. The Caddy copier and
// ids-live speak it over a Unix socket, but nothing in a frame depends on
// the connection (T2), so a TCP connection could carry the same frames.
//
// What the client sent (the request line and the headers) travels as raw
// bytes, never as JSON text: JSON can't hold bytes that are not UTF-8, and
// the IDS must see what was received (M16). Only facts that are always
// plain text, such as addresses, times and sizes, are in the JSON part.
package copyframe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is the version of the format, sent in the hello frames. It
// changes when a frame changes its meaning; new optional JSON fields keep
// it.
const Version = 1

// Type is the kind of a frame.
type Type byte

const (
	// TypeHello is the first frame each side sends on a connection.
	TypeHello Type = 1
	// TypeCopy, from the copier, holds one request and its response.
	TypeCopy Type = 2
	// TypeMissed, from the copier, counts copies it could not send.
	TypeMissed Type = 3
	// TypeDecision, from the IDS, is reserved for blocking (K4). It is
	// not sent yet; a reader skips it like any type it does not know.
	TypeDecision Type = 4
)

func (t Type) String() string {
	switch t {
	case TypeHello:
		return "hello"
	case TypeCopy:
		return "copy"
	case TypeMissed:
		return "missed"
	case TypeDecision:
		return "decision"
	}
	return fmt.Sprintf("type %d", byte(t))
}

// MaxMetaSize is the largest JSON part of a copy frame.
const MaxMetaSize = 1 << 20

// MaxTextSize is the longest text the format allows in a short field, such
// as an application name, an ID or a reason.
const MaxTextSize = 64

// Hello is the content of a hello frame.
type Hello struct {
	// Format is the version of the format the sender speaks.
	Format int `json:"format"`
	// Program and Version name the sender, such as "caddy ids_copy" and
	// its version.
	Program string `json:"program"`
	Version string `json:"version,omitempty"`
	// Error is set by the IDS when it refuses the connection, for example
	// because it does not speak the copier's format. The IDS closes the
	// connection after this frame.
	Error string `json:"error,omitempty"`
}

// Copy is one request and its response, as the copier saw them.
type Copy struct {
	Meta Meta

	// Method, Target and Proto are the request line as received, such as
	// "GET", "/a?b=c" and "HTTP/1.1". Target is still percent-encoded.
	Method string
	Target string
	Proto  string
	// Headers are the request headers. Their order and the case of their
	// names are what the proxy kept; docs/copy-format.md says what that is
	// for Caddy.
	Headers []Header
	// Body is the first part of the request body, up to the copier's
	// limit. Meta.Request says how long the whole body was.
	Body []byte

	// ResponseHeaders and ResponseBody are the response's headers and the
	// first part of its body. Both are empty when Meta.Response is nil,
	// and the body is empty when the copier did not copy it.
	ResponseHeaders []Header
	ResponseBody    []byte
}

// Header is one header line. Name and Value hold the bytes as received,
// which need not be UTF-8.
type Header struct {
	Name  string
	Value string
}

// Meta is the JSON part of a copy frame.
type Meta struct {
	// ID identifies the request at the proxy, such as Caddy's request
	// UUID, so that a record can be found in the proxy's own logs.
	ID string `json:"id"`
	// Time is when the proxy received the request, and DurationMS how long
	// it took until the copy was made.
	Time       time.Time `json:"time"`
	DurationMS float64   `json:"duration_ms"`
	// Application is the name the proxy's configuration gives the
	// application (T6). It is empty when the configuration names none.
	Application string `json:"application,omitempty"`

	// Client is the client as the proxy determined it: the connection's
	// address, or the one a proxy in front of it gave, when that proxy is
	// trusted (T5). Connection is the address the connection came from,
	// and Server the address it was made to.
	Client     Addr `json:"client"`
	Connection Addr `json:"connection"`
	Server     Addr `json:"server"`

	// TLS is set when the request came over TLS.
	TLS *TLS `json:"tls,omitempty"`

	Request RequestMeta `json:"request"`
	// Response is nil when no response was written, for example because
	// the client went away first.
	Response *ResponseMeta `json:"response,omitempty"`
}

// Addr is an IP address and port. Either may be left out when unknown.
type Addr struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// TLS describes the connection's TLS session (T10).
type TLS struct {
	// Version is the protocol, such as "TLS 1.3", and Cipher the cipher
	// suite, such as "TLS_AES_128_GCM_SHA256".
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	// ServerName is the name the client asked for (SNI), and ALPN the
	// protocol the two sides agreed on, such as "h2".
	ServerName string `json:"server_name,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
}

// RequestMeta describes the request body.
type RequestMeta struct {
	// BodyLength is how many body bytes the client sent, as far as they
	// were read. BodyComplete is true when the body was read to its end.
	// The body in the frame is shorter than BodyLength when the copier's
	// limit cut it (T3).
	BodyLength   int64 `json:"body_length"`
	BodyComplete bool  `json:"body_complete"`
}

// ResponseMeta describes the response.
type ResponseMeta struct {
	Status int `json:"status"`
	// BodyLength is how many body bytes the application sent. The body in
	// the frame is shorter when the copier's limit cut it or the copier
	// did not copy it (Note).
	BodyLength int64 `json:"body_length"`
	// Note says why the body in the frame is not the response's body: one
	// of the Note constants, or empty.
	Note string `json:"note,omitempty"`
}

// The notes of a response (T4, plan C7).
const (
	// NoteTypeNotCopied: the response's type is not one the copier copies.
	NoteTypeNotCopied = "type not copied"
	// NoteNotFinished: the response was still being sent when the copier
	// sent the copy; BodyLength counts what was sent until then.
	NoteNotFinished = "not finished"
	// NoteUpgraded: the connection was switched to another protocol, such
	// as WebSocket; there is no response body.
	NoteUpgraded = "upgraded"
)

// Missed is the content of a missed frame: Count copies of requests made
// between From and To that the copier could not send, and why (T7, T8).
type Missed struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Count  int64     `json:"count"`
	Reason string    `json:"reason"`
}

// The reasons of a missed frame.
const (
	ReasonQueueFull    = "queue full"
	ReasonNotConnected = "not connected"
	ReasonRefused      = "refused by the IDS"
)

// Frame is one frame read by Reader.Next. For a frame of a known type,
// exactly one of Hello, Copy and Missed is set. For any other type only
// Type is; the reader has skipped its content.
type Frame struct {
	Type   Type
	Hello  *Hello
	Copy   *Copy
	Missed *Missed
}

// TooLargeError is returned for a frame longer than the reader allows.
type TooLargeError struct {
	Size, Max int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("a frame of %d bytes is larger than the limit of %d", e.Size, e.Max)
}

// Reader reads frames from a stream.
type Reader struct {
	r   *bufio.Reader
	max int64
}

// NewReader returns a reader of the frames of r that refuses a frame whose
// length is more than maxFrame bytes.
func NewReader(r io.Reader, maxFrame int64) *Reader {
	return &Reader{r: bufio.NewReader(r), max: maxFrame}
}

// Next reads the next frame. It returns io.EOF when the stream ends
// between two frames and io.ErrUnexpectedEOF when it ends inside one. A
// frame that breaks the format is an error. After any error the stream
// cannot be read further, because the next frame's start is not known.
func (r *Reader) Next() (Frame, error) {
	var length [4]byte
	if _, err := io.ReadFull(r.r, length[:]); err != nil {
		return Frame{}, err
	}
	n := int64(binary.BigEndian.Uint32(length[:]))
	if n == 0 {
		return Frame{}, errors.New("a frame without a type")
	}
	if n > r.max {
		return Frame{}, &TooLargeError{Size: n, Max: r.max}
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	return parse(Type(buf[0]), buf[1:])
}

func parse(t Type, content []byte) (Frame, error) {
	f := Frame{Type: t}
	var err error
	switch t {
	case TypeHello:
		f.Hello = &Hello{}
		if err = decodeStrict(content, f.Hello); err == nil {
			err = f.Hello.validate()
		}
	case TypeCopy:
		f.Copy, err = parseCopy(content)
	case TypeMissed:
		f.Missed = &Missed{}
		if err = decodeStrict(content, f.Missed); err == nil {
			err = f.Missed.validate()
		}
	default:
		return f, nil
	}
	if err != nil {
		return Frame{}, fmt.Errorf("%s frame: %w", t, err)
	}
	return f, nil
}

// decodeStrict reads one JSON object into v. A field v does not have is an
// error, so that a misspelled name cannot be ignored.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("invalid JSON: unexpected content after the object")
	}
	return nil
}

// cursor reads the parts of a copy frame's content.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) uint32(what string) int {
	if c.err != nil {
		return 0
	}
	if len(c.b) < 4 {
		c.err = fmt.Errorf("%s: the frame ends early", what)
		return 0
	}
	n := binary.BigEndian.Uint32(c.b)
	c.b = c.b[4:]
	return int(n)
}

func (c *cursor) bytes(what string) []byte {
	n := c.uint32(what)
	if c.err != nil {
		return nil
	}
	if n > len(c.b) {
		c.err = fmt.Errorf("%s: %d bytes, but only %d are left in the frame", what, n, len(c.b))
		return nil
	}
	b := c.b[:n:n]
	c.b = c.b[n:]
	return b
}

// list reads a part that is a count followed by that many byte strings.
func (c *cursor) list(what string) []string {
	n := c.uint32(what)
	if c.err != nil {
		return nil
	}
	// Each item takes at least its 4-byte length, which bounds n before
	// anything is allocated for it.
	if n > len(c.b)/4 {
		c.err = fmt.Errorf("%s: %d items do not fit in the frame", what, n)
		return nil
	}
	items := make([]string, 0, n)
	for range n {
		b := c.bytes(what)
		if c.err != nil {
			return nil
		}
		items = append(items, string(b))
	}
	return items
}

func parseCopy(content []byte) (*Copy, error) {
	c := &cursor{b: content}
	meta := c.bytes("metadata")
	if c.err == nil && len(meta) > MaxMetaSize {
		return nil, fmt.Errorf("metadata: %d bytes, more than the limit of %d", len(meta), MaxMetaSize)
	}
	head := c.list("request head")
	body := c.bytes("request body")
	respHead := c.list("response head")
	respBody := c.bytes("response body")
	if c.err != nil {
		return nil, c.err
	}
	if len(c.b) > 0 {
		return nil, fmt.Errorf("%d bytes after the response body", len(c.b))
	}

	cp := &Copy{Body: body, ResponseBody: respBody}
	if err := decodeStrict(meta, &cp.Meta); err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	if len(head) < 3 || len(head)%2 != 1 {
		return nil, fmt.Errorf("request head: %d items; it needs the method, target and protocol and then name and value pairs", len(head))
	}
	cp.Method, cp.Target, cp.Proto = head[0], head[1], head[2]
	cp.Headers = pairs(head[3:])
	if len(respHead)%2 != 0 {
		return nil, fmt.Errorf("response head: %d items, not name and value pairs", len(respHead))
	}
	cp.ResponseHeaders = pairs(respHead)
	if err := cp.Validate(); err != nil {
		return nil, err
	}
	return cp, nil
}

func pairs(items []string) []Header {
	if len(items) == 0 {
		return nil
	}
	headers := make([]Header, 0, len(items)/2)
	for i := 0; i+1 < len(items); i += 2 {
		headers = append(headers, Header{Name: items[i], Value: items[i+1]})
	}
	return headers
}

// Validate checks a copy against the rules of the format. Reader.Next
// returns only copies that pass, and AppendCopy writes only those.
func (c *Copy) Validate() error {
	m := c.Meta
	switch {
	case !text(m.ID, MaxTextSize, false):
		return errors.New("metadata: id must be 1 to 64 bytes of printable text")
	case m.Time.IsZero():
		return errors.New("metadata: time is missing")
	case m.DurationMS < 0 || math.IsNaN(m.DurationMS) || math.IsInf(m.DurationMS, 0):
		return errors.New("metadata: duration_ms must be a number of 0 or more")
	case m.Application != "" && !text(m.Application, MaxTextSize, false):
		return errors.New("metadata: application must be at most 64 bytes of printable text")
	}
	for _, a := range []struct {
		what string
		addr Addr
	}{{"client", m.Client}, {"connection", m.Connection}, {"server", m.Server}} {
		if err := a.addr.validate(); err != nil {
			return fmt.Errorf("metadata: %s: %w", a.what, err)
		}
	}
	if m.TLS != nil {
		t := m.TLS
		if !text(t.Version, MaxTextSize, false) || !text(t.Cipher, MaxTextSize, false) ||
			!text(t.ServerName, 255, true) || !text(t.ALPN, MaxTextSize, true) {
			return errors.New("metadata: tls: version and cipher are required, and every field is printable text")
		}
	}

	switch {
	case c.Method == "":
		return errors.New("request head: the method is empty")
	case c.Target == "":
		return errors.New("request head: the target is empty")
	case c.Proto == "":
		return errors.New("request head: the protocol is empty")
	}
	if err := names("request head", c.Headers); err != nil {
		return err
	}
	if m.Request.BodyLength < int64(len(c.Body)) {
		return fmt.Errorf("metadata: request body_length %d is less than the %d bytes copied", m.Request.BodyLength, len(c.Body))
	}

	if m.Response == nil {
		if len(c.ResponseHeaders) > 0 || len(c.ResponseBody) > 0 {
			return errors.New("a response head or body without a response in the metadata")
		}
		return nil
	}
	r := m.Response
	switch {
	case r.Status < 100 || r.Status > 999:
		return fmt.Errorf("metadata: response status %d is not 100 to 999", r.Status)
	case r.BodyLength < int64(len(c.ResponseBody)):
		return fmt.Errorf("metadata: response body_length %d is less than the %d bytes copied", r.BodyLength, len(c.ResponseBody))
	case !text(r.Note, MaxTextSize, true):
		return errors.New("metadata: response note must be at most 64 bytes of printable text")
	}
	return names("response head", c.ResponseHeaders)
}

func names(what string, headers []Header) error {
	for i, h := range headers {
		if h.Name == "" {
			return fmt.Errorf("%s: header %d has an empty name", what, i+1)
		}
	}
	return nil
}

func (a Addr) validate() error {
	if a.IP != "" {
		if _, err := netip.ParseAddr(a.IP); err != nil {
			return err
		}
	}
	if a.Port < 0 || a.Port > 65535 {
		return fmt.Errorf("%d is not a port number", a.Port)
	}
	return nil
}

func (h *Hello) validate() error {
	switch {
	case h.Format < 1:
		return errors.New("format must be 1 or more")
	case !text(h.Program, MaxTextSize, false):
		return errors.New("program must be 1 to 64 bytes of printable text")
	case !text(h.Version, MaxTextSize, true):
		return errors.New("version must be at most 64 bytes of printable text")
	case !text(h.Error, 1024, true):
		return errors.New("error must be at most 1024 bytes of printable text")
	}
	return nil
}

func (m *Missed) validate() error {
	switch {
	case m.From.IsZero() || m.To.IsZero() || m.To.Before(m.From):
		return errors.New("from and to are required, and to may not be before from")
	case m.Count < 1:
		return errors.New("count must be 1 or more")
	case !text(m.Reason, MaxTextSize, false):
		return errors.New("reason must be 1 to 64 bytes of printable text")
	}
	return nil
}

// text reports whether s is valid UTF-8 without control characters, at
// most max bytes long, and not empty unless empty is allowed.
func text(s string, max int, empty bool) bool {
	if s == "" {
		return empty
	}
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// AppendHello appends a hello frame to dst.
func AppendHello(dst []byte, h Hello) ([]byte, error) {
	if err := h.validate(); err != nil {
		return dst, fmt.Errorf("hello frame: %w", err)
	}
	return appendJSON(dst, TypeHello, h)
}

// AppendMissed appends a missed frame to dst.
func AppendMissed(dst []byte, m Missed) ([]byte, error) {
	if err := m.validate(); err != nil {
		return dst, fmt.Errorf("missed frame: %w", err)
	}
	return appendJSON(dst, TypeMissed, m)
}

func appendJSON(dst []byte, t Type, v any) ([]byte, error) {
	content, err := json.Marshal(v)
	if err != nil {
		return dst, err
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(1+len(content)))
	dst = append(dst, byte(t))
	return append(dst, content...), nil
}

// AppendCopy appends a copy frame to dst.
func AppendCopy(dst []byte, c *Copy) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return dst, fmt.Errorf("copy frame: %w", err)
	}
	meta, err := json.Marshal(c.Meta)
	if err != nil {
		return dst, err
	}
	if len(meta) > MaxMetaSize {
		return dst, fmt.Errorf("copy frame: metadata of %d bytes is larger than the limit of %d", len(meta), MaxMetaSize)
	}
	head := []string{c.Method, c.Target, c.Proto}
	for _, h := range c.Headers {
		head = append(head, h.Name, h.Value)
	}
	var respHead []string
	for _, h := range c.ResponseHeaders {
		respHead = append(respHead, h.Name, h.Value)
	}

	size := 1 + 4 + len(meta) + listSize(head) + 4 + len(c.Body) + listSize(respHead) + 4 + len(c.ResponseBody)
	if int64(size) > math.MaxUint32 {
		return dst, fmt.Errorf("copy frame: %d bytes do not fit in a frame", size)
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(size))
	dst = append(dst, byte(TypeCopy))
	dst = appendBytes(dst, meta)
	dst = appendList(dst, head)
	dst = appendBytes(dst, c.Body)
	dst = appendList(dst, respHead)
	return appendBytes(dst, c.ResponseBody), nil
}

func listSize(items []string) int {
	n := 4
	for _, it := range items {
		n += 4 + len(it)
	}
	return n
}

func appendBytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

func appendList(dst []byte, items []string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(items)))
	for _, it := range items {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(it)))
		dst = append(dst, it...)
	}
	return dst
}
