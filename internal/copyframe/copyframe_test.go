package copyframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 26, 14, 2, 3, 456789000, time.UTC)

// sample is a copy with what JSON could not carry: a Latin-1 byte in the
// target and in a header value, and a body with a zero byte and bytes that
// are not UTF-8.
func sample() *Copy {
	return &Copy{
		Meta: Meta{
			ID:          "5f0c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f",
			Time:        t0,
			DurationMS:  1.25,
			Application: "shop",
			Client:      Addr{IP: "203.0.113.9", Port: 51000},
			Connection:  Addr{IP: "127.0.0.1", Port: 40000},
			Server:      Addr{IP: "127.0.0.1", Port: 8080},
			TLS:         &TLS{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ServerName: "localhost", ALPN: "http/1.1"},
			Request:     RequestMeta{BodyLength: 40, BodyComplete: true},
			Response:    &ResponseMeta{Status: 200, BodyLength: 5},
		},
		Method:          "POST",
		Target:          "/tienda1/publico/anadir.jsp?nombre=Jam\xf3n",
		Proto:           "HTTP/1.1",
		Headers:         []Header{{"Host", "localhost:8080"}, {"Content-Type", "application/x-www-form-urlencoded"}, {"X-Note", "caf\xe9"}},
		Body:            []byte("a=1&b=\x00\xff\xfe"),
		ResponseHeaders: []Header{{"Content-Type", "text/plain"}},
		ResponseBody:    []byte("hello"),
	}
}

func frames(t *testing.T, parts ...func([]byte) ([]byte, error)) []byte {
	t.Helper()
	var b []byte
	for _, p := range parts {
		var err error
		if b, err = p(b); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	hello := Hello{Format: Version, Program: "caddy ids_copy", Version: "0.1.0"}
	missed := Missed{From: t0, To: t0.Add(3 * time.Minute), Count: 1240, Reason: ReasonNotConnected}
	cp := sample()
	stream := frames(t,
		func(b []byte) ([]byte, error) { return AppendHello(b, hello) },
		func(b []byte) ([]byte, error) { return AppendCopy(b, cp) },
		// A decision frame, which this version does not read, is skipped.
		func(b []byte) ([]byte, error) { return append(b, 0, 0, 0, 3, byte(TypeDecision), '{', '}'), nil },
		func(b []byte) ([]byte, error) { return AppendMissed(b, missed) },
	)

	r := NewReader(bytes.NewReader(stream), 1<<20)
	f, err := r.Next()
	if err != nil || f.Type != TypeHello || !reflect.DeepEqual(*f.Hello, hello) {
		t.Fatalf("hello: %+v, %v", f, err)
	}
	f, err = r.Next()
	if err != nil || f.Type != TypeCopy {
		t.Fatalf("copy: %+v, %v", f, err)
	}
	if !f.Copy.Meta.Time.Equal(cp.Meta.Time) {
		t.Errorf("time %v, want %v", f.Copy.Meta.Time, cp.Meta.Time)
	}
	f.Copy.Meta.Time = cp.Meta.Time
	if !reflect.DeepEqual(f.Copy, cp) {
		t.Errorf("copy:\n got %+v\nwant %+v", f.Copy, cp)
	}
	f, err = r.Next()
	if err != nil || f.Type != TypeDecision || f.Hello != nil || f.Copy != nil || f.Missed != nil {
		t.Fatalf("decision: %+v, %v", f, err)
	}
	f, err = r.Next()
	if err != nil || f.Type != TypeMissed || f.Missed.Count != 1240 || f.Missed.Reason != ReasonNotConnected || !f.Missed.To.Equal(missed.To) {
		t.Fatalf("missed: %+v, %v", f, err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("after the last frame: %v, want io.EOF", err)
	}
}

func TestCopyWithoutResponse(t *testing.T) {
	cp := sample()
	cp.Meta.Response, cp.ResponseHeaders, cp.ResponseBody = nil, nil, nil
	cp.Meta.TLS = nil
	b, err := AppendCopy(nil, cp)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewReader(bytes.NewReader(b), 1<<20).Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.Copy.Meta.Response != nil || f.Copy.ResponseHeaders != nil || f.Copy.Meta.TLS != nil {
		t.Errorf("%+v", f.Copy)
	}
}

func TestStreamEnds(t *testing.T) {
	if _, err := NewReader(bytes.NewReader(nil), 100).Next(); err != io.EOF {
		t.Errorf("empty stream: %v, want io.EOF", err)
	}
	b, _ := AppendHello(nil, Hello{Format: 1, Program: "test"})
	for _, cut := range []int{2, 4, 5, len(b) - 1} {
		if _, err := NewReader(bytes.NewReader(b[:cut]), 100).Next(); err != io.ErrUnexpectedEOF {
			t.Errorf("cut after %d bytes: %v, want io.ErrUnexpectedEOF", cut, err)
		}
	}
	if _, err := NewReader(bytes.NewReader([]byte{0, 0, 0, 0}), 100).Next(); err == nil {
		t.Error("no error for a frame of length 0")
	}
}

func TestTooLarge(t *testing.T) {
	// The length field claims 2 GiB; nothing more follows. The reader must
	// refuse it from the length alone.
	_, err := NewReader(bytes.NewReader([]byte{0x80, 0, 0, 0}), 16<<20).Next()
	var tooLarge *TooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Size != 1<<31 || tooLarge.Max != 16<<20 {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "2147483648 bytes is larger than the limit of 16777216") {
		t.Errorf("message: %v", err)
	}
}

// rawCopy builds a copy frame without checking it, so tests can break it.
func rawCopy(meta string, head []string, body []byte, respHead []string, respBody []byte, tail []byte) []byte {
	var content []byte
	content = appendBytes(content, []byte(meta))
	content = appendList(content, head)
	content = appendBytes(content, body)
	content = appendList(content, respHead)
	content = appendBytes(content, respBody)
	content = append(content, tail...)
	b := binary.BigEndian.AppendUint32(nil, uint32(1+len(content)))
	b = append(b, byte(TypeCopy))
	return append(b, content...)
}

func TestBrokenCopies(t *testing.T) {
	const okMeta = `{"id":"r1","time":"2026-10-26T14:02:03Z","duration_ms":1,"client":{},"connection":{},"server":{},"request":{"body_length":3,"body_complete":true},"response":{"status":200,"body_length":2}}`
	head := []string{"GET", "/", "HTTP/1.1", "Host", "a"}
	respHead := []string{"Content-Type", "text/plain"}
	with := func(old, new string) string { return strings.Replace(okMeta, old, new, 1) }

	if _, err := NewReader(bytes.NewReader(rawCopy(okMeta, head, []byte("abc"), respHead, []byte("ok"), nil)), 1<<20).Next(); err != nil {
		t.Fatalf("the unbroken frame: %v", err)
	}
	cases := []struct {
		name  string
		frame []byte
		want  string
	}{
		{"unknown field", rawCopy(with(`"id"`, `"idd":1,"id"`), head, []byte("abc"), respHead, []byte("ok"), nil), "unknown field"},
		{"bytes after the end", rawCopy(okMeta, head, []byte("abc"), respHead, []byte("ok"), []byte{1}), "1 bytes after the response body"},
		{"two items in the head", rawCopy(okMeta, head[:2], []byte("abc"), respHead, []byte("ok"), nil), "request head: 2 items"},
		{"a header without value", rawCopy(okMeta, head[:4], []byte("abc"), respHead, []byte("ok"), nil), "request head: 4 items"},
		{"odd response head", rawCopy(okMeta, head, []byte("abc"), respHead[:1], []byte("ok"), nil), "response head: 1 items"},
		{"body longer than its length", rawCopy(okMeta, head, []byte("abcd"), respHead, []byte("ok"), nil), "request body_length 3 is less than the 4 bytes copied"},
		{"response body longer than its length", rawCopy(okMeta, head, []byte("abc"), respHead, []byte("okk"), nil), "response body_length 2 is less than the 3 bytes copied"},
		{"response head without a response", rawCopy(with(`,"response":{"status":200,"body_length":2}`, ``), head, []byte("abc"), respHead, nil, nil), "without a response in the metadata"},
		{"bad client IP", rawCopy(with(`"client":{}`, `"client":{"ip":"999.1.1.1"}`), head, []byte("abc"), respHead, []byte("ok"), nil), "client"},
		{"bad port", rawCopy(with(`"server":{}`, `"server":{"port":70000}`), head, []byte("abc"), respHead, []byte("ok"), nil), "70000 is not a port number"},
		{"no time", rawCopy(with(`"time":"2026-10-26T14:02:03Z",`, ``), head, []byte("abc"), respHead, []byte("ok"), nil), "time is missing"},
		{"empty method", rawCopy(okMeta, []string{"", "/", "HTTP/1.1"}, []byte("abc"), respHead, []byte("ok"), nil), "the method is empty"},
		{"empty header name", rawCopy(okMeta, []string{"GET", "/", "HTTP/1.1", "", "x"}, []byte("abc"), respHead, []byte("ok"), nil), "header 1 has an empty name"},
		{"status 0", rawCopy(with(`"status":200`, `"status":0`), head, []byte("abc"), respHead, []byte("ok"), nil), "status 0"},
		{"control character in the application", rawCopy(with(`"id":"r1"`, `"id":"r1","application":"a\u0007b"`), head, []byte("abc"), respHead, []byte("ok"), nil), "application"},
		{"metadata over the limit", rawCopy(okMeta+strings.Repeat(" ", MaxMetaSize), head, []byte("abc"), respHead, []byte("ok"), nil), "more than the limit"},
	}
	for _, c := range cases {
		_, err := NewReader(bytes.NewReader(c.frame), 4<<20).Next()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.want)
		}
	}

	// A list whose count is larger than the frame could hold is refused
	// before anything is allocated for it.
	content := appendBytes(nil, []byte(okMeta))
	content = binary.BigEndian.AppendUint32(content, 1<<30)
	frame := binary.BigEndian.AppendUint32(nil, uint32(1+len(content)))
	frame = append(append(frame, byte(TypeCopy)), content...)
	if _, err := NewReader(bytes.NewReader(frame), 1<<20).Next(); err == nil || !strings.Contains(err.Error(), "items do not fit") {
		t.Errorf("huge item count: %v", err)
	}
}

func TestBrokenSmallFrames(t *testing.T) {
	frame := func(t Type, content string) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(1+len(content)))
		return append(append(b, byte(t)), content...)
	}
	cases := []struct {
		name  string
		frame []byte
		want  string
	}{
		{"hello without program", frame(TypeHello, `{"format":1}`), "program"},
		{"hello format 0", frame(TypeHello, `{"format":0,"program":"x"}`), "format must be 1 or more"},
		{"hello with two objects", frame(TypeHello, `{"format":1,"program":"x"}{}`), "unexpected content"},
		{"missed backwards", frame(TypeMissed, `{"from":"2026-10-26T14:05:00Z","to":"2026-10-26T14:02:00Z","count":3,"reason":"queue full"}`), "to may not be before from"},
		{"missed count 0", frame(TypeMissed, `{"from":"2026-10-26T14:02:00Z","to":"2026-10-26T14:05:00Z","count":0,"reason":"queue full"}`), "count must be 1 or more"},
		{"missed without reason", frame(TypeMissed, `{"from":"2026-10-26T14:02:00Z","to":"2026-10-26T14:05:00Z","count":2}`), "reason"},
	}
	for _, c := range cases {
		_, err := NewReader(bytes.NewReader(c.frame), 1<<20).Next()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.want)
		}
	}
}

func TestAppendRefusesBrokenFrames(t *testing.T) {
	cp := sample()
	cp.Method = ""
	if _, err := AppendCopy(nil, cp); err == nil {
		t.Error("a copy without a method was written")
	}
	cp = sample()
	cp.Meta.Request.BodyLength = 1
	if _, err := AppendCopy(nil, cp); err == nil {
		t.Error("a copy whose body is longer than its length was written")
	}
	if _, err := AppendMissed(nil, Missed{From: t0, To: t0, Reason: ReasonQueueFull}); err == nil {
		t.Error("a missed frame with count 0 was written")
	}
	if _, err := AppendHello(nil, Hello{Format: 1}); err == nil {
		t.Error("a hello frame without a program was written")
	}
}

// FuzzReadFrame feeds arbitrary bytes to the reader. It must never panic,
// and every copy it accepts must survive being written and read again
// unchanged.
func FuzzReadFrame(f *testing.F) {
	good, _ := AppendCopy(nil, sample())
	hello, _ := AppendHello(nil, Hello{Format: 1, Program: "seed"})
	missed, _ := AppendMissed(nil, Missed{From: t0, To: t0, Count: 1, Reason: ReasonQueueFull})
	f.Add(good)
	f.Add(append(hello, good...))
	f.Add(missed)
	f.Add([]byte{0, 0, 0, 1, 9})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data), 1<<16)
		for {
			fr, err := r.Next()
			if err != nil {
				return
			}
			if fr.Copy == nil {
				continue
			}
			again, err := AppendCopy(nil, fr.Copy)
			if err != nil {
				t.Fatalf("an accepted copy cannot be written again: %v", err)
			}
			back, err := NewReader(bytes.NewReader(again), 1<<20).Next()
			if err != nil {
				t.Fatalf("a written copy cannot be read again: %v", err)
			}
			back.Copy.Meta.Time = fr.Copy.Meta.Time
			if !reflect.DeepEqual(normal(back.Copy), normal(fr.Copy)) {
				t.Fatalf("the copy changed:\n%+v\n%+v", back.Copy, fr.Copy)
			}
		}
	})
}

// normal makes empty and nil slices equal, which the format does not
// distinguish.
func normal(c *Copy) Copy {
	n := *c
	if len(n.Body) == 0 {
		n.Body = nil
	}
	if len(n.ResponseBody) == 0 {
		n.ResponseBody = nil
	}
	return n
}
