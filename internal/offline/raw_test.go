package offline

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

func TestParseRaw(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		bodyCRLF bool
		want     httpmodel.Received
	}{
		{
			name: "line ends \\n, no body",
			text: "GET /search?q=1 HTTP/1.1\nHost: shop.example.com\nAccept: */*\n",
			want: httpmodel.Received{Method: "GET", Target: "/search?q=1", Version: "HTTP/1.1",
				Headers: hs("Host", "shop.example.com", "Accept", "*/*")},
		},
		{
			name: "line ends \\r\\n and a body",
			text: "POST /login HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\nuser=ab",
			want: httpmodel.Received{Method: "POST", Target: "/login", Version: "HTTP/1.1",
				Headers: hs("Host", "a", "Content-Length", "7"), Body: []byte("user=ab")},
		},
		{
			name: "no line end at all",
			text: "GET /",
			want: httpmodel.Received{Method: "GET", Target: "/"},
		},
		{
			name: "HTTP/0.9: a request line without a version",
			text: "GET /index.html\n",
			want: httpmodel.Received{Method: "GET", Target: "/index.html"},
		},
		{
			name: "empty lines before the request line are skipped",
			text: "\n\r\nGET / HTTP/1.0\n",
			want: httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.0"},
		},
		{
			name: "repeated headers keep their order and case",
			text: "GET / HTTP/1.1\ncookie: a=1\nHOST: x\nCookie: b=2\n",
			want: httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.1",
				Headers: hs("cookie", "a=1", "HOST", "x", "Cookie", "b=2")},
		},
		{
			name: "spaces and tabs around a value are not part of it; an empty value is kept",
			text: "GET / HTTP/1.1\nX-A:\t value with  inner spaces \t\nX-Empty:\nX-B:no-space\n",
			want: httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.1",
				Headers: hs("X-A", "value with  inner spaces", "X-Empty", "", "X-B", "no-space")},
		},
		{
			name: "a colon in the value stays in the value",
			text: "GET / HTTP/1.1\nReferer: http://x/a:b\n",
			want: httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.1",
				Headers: hs("Referer", "http://x/a:b")},
		},
		{
			name: "an empty line with nothing after it gives no body",
			text: "GET / HTTP/1.1\nHost: a\n\n",
			want: httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: hs("Host", "a")},
		},
		{
			name: "the body is kept byte for byte, its line ends too",
			text: "POST / HTTP/1.1\n\n\nline 1\r\nline 2\n\n",
			want: httpmodel.Received{Method: "POST", Target: "/", Version: "HTTP/1.1",
				Body: []byte("\nline 1\r\nline 2\n\n")},
		},
		{
			name:     "bodyCRLF turns each \\n of the body into \\r\\n, and leaves \\r\\n alone",
			text:     "POST / HTTP/1.1\nContent-Type: multipart/form-data; boundary=b\n\n--b\nContent-Disposition: form-data; name=\"a\"\r\n\n1\n--b--\n",
			bodyCRLF: true,
			want: httpmodel.Received{Method: "POST", Target: "/", Version: "HTTP/1.1",
				Headers: hs("Content-Type", "multipart/form-data; boundary=b"),
				Body:    []byte("--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b--\r\n")},
		},
		{
			name: "a wrong Content-Length is not corrected",
			text: "POST / HTTP/1.1\nContent-Length: 100\n\nabc",
			want: httpmodel.Received{Method: "POST", Target: "/", Version: "HTTP/1.1",
				Headers: hs("Content-Length", "100"), Body: []byte("abc")},
		},
		{
			name: "the version and the method are taken as written",
			text: "get /%2e%2e/etc/passwd HTTP/9.9\n",
			want: httpmodel.Received{Method: "get", Target: "/%2e%2e/etc/passwd", Version: "HTTP/9.9"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRaw(tt.text, tt.bodyCRLF)
			if err != nil {
				t.Fatalf("ParseRaw: %v", err)
			}
			if !sameReceived(got, tt.want) {
				t.Errorf("ParseRaw:\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseRawErrors(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"", "the request is empty"},
		{"\n\r\n\n", "the request is empty"},
		{"GET", "line 1: a request line is"},
		{"GET  / HTTP/1.1", "line 1: a request line is"},
		{"GET / HTTP/1.1 extra", "line 1: a request line is"},
		{" GET / HTTP/1.1", "line 1: a request line is"},
		{"\nGET / HTTP/1.1 ", "line 2: a request line is"},
		{"GET / HTTP/1.1\nHost a", "line 2: a header is a name, a colon and a value"},
		{"GET / HTTP/1.1\nHost: a\n: no name", "line 3: the header has no name"},
		{"GET / HTTP/1.1\nHost : a", "line 2: a header name can't contain spaces or tabs"},
		{"GET / HTTP/1.1\nX-A: 1\n folded: on", "line 3: a header name can't contain spaces or tabs"},
		{"GET / HTTP/1.1\nX-" + strings.Repeat("a", MaxRawLine) + ": 1", "line 2 is longer than"},
	}
	for _, tt := range tests {
		_, err := ParseRaw(tt.text, false)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("ParseRaw(%.40q): error %v, want one with %q", tt.text, err, tt.want)
		}
	}
}

func TestRawNotWritable(t *testing.T) {
	ok := httpmodel.Received{Method: "GET", Target: "/", Version: "HTTP/1.1"}
	tests := map[string]func(*httpmodel.Received){
		"empty method":                    func(r *httpmodel.Received) { r.Method = "" },
		"space in the target":             func(r *httpmodel.Received) { r.Target = "/a b" },
		"line break in the version":       func(r *httpmodel.Received) { r.Version = "HTTP/1.1\r\n" },
		"empty header name":               func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "", Value: "x"}} },
		"colon in a header name":          func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "a:b", Value: "x"}} },
		"space in a header name":          func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "a b", Value: "x"}} },
		"line break in a header value":    func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "A", Value: "x\ny"}} },
		"space before a header value":     func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "A", Value: " x"}} },
		"tab after a header value":        func(r *httpmodel.Received) { r.Headers = []httpmodel.Header{{Name: "A", Value: "x\t"}} },
		"body not UTF-8":                  func(r *httpmodel.Received) { r.Body = []byte{0xff, 0xfe} },
		"body with \\r\\n and a lone \\n": func(r *httpmodel.Received) { r.Body = []byte("a\r\nb\nc") },
		"body with a lone \\r":            func(r *httpmodel.Received) { r.Body = []byte("a\rb") },
		"body with \\r\\n and a lone \\r": func(r *httpmodel.Received) { r.Body = []byte("a\r\nb\r") },
	}
	for name, change := range tests {
		r := ok
		change(&r)
		if text, _, writable := Raw(r); writable {
			t.Errorf("%s: Raw gave %q, want not writable", name, text)
		}
	}
	if _, _, writable := Raw(ok); !writable {
		t.Error("Raw of a plain request: not writable")
	}
}

// TestRawRoundTrip writes every example request of the repository as raw
// text and reads it back (plan verification 2). Only the requests Raw
// reports as not writable may differ, and they are listed.
func TestRawRoundTrip(t *testing.T) {
	files, err := filepath.Glob("../../testdata/requests/*.json")
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob("../../testdata/requests/*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, more...)
	total, crlf := 0, 0
	var notWritable []string
	for _, file := range files {
		examples, err := LoadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, ex := range examples {
			total++
			rec := ex.Request.Received
			text, bodyCRLF, ok := Raw(rec)
			if !ok {
				notWritable = append(notWritable, ex.Name)
				continue
			}
			if bodyCRLF {
				crlf++
			}
			got, err := ParseRaw(text, bodyCRLF)
			if err != nil {
				t.Errorf("%s: ParseRaw of Raw's text: %v\n%s", ex.Name, err, text)
				continue
			}
			if !sameReceived(got, rec) {
				t.Errorf("%s: the round trip changed the request:\n got %+v\nwant %+v", ex.Name, got, rec)
			}
		}
	}
	t.Logf("%d example requests in %d files: %d written as text and read back the same (%d with \\r\\n body line ends), %d not writable", total, len(files), total-len(notWritable), crlf, len(notWritable))
	// Six have a header value that starts or ends with a space, which HTTP
	// servers remove (Go's included, so Caddy too), and one has a body
	// that is not UTF-8 text.
	want := []string{
		"CRS 920660-10: Request-Range with whitespace in value",
		"CRS 932180-14: restricted upload with trailing whitespace via header",
		"CRS 933110-32: PHP .php upload with trailing whitespace via header",
		"CRS 933110-35: PHP .phar upload with trailing whitespace via header",
		"CRS 944140-11: JSP upload with trailing whitespace via header",
		"CRS 944200-1: Argument test includes java serialization magic bytes, base64 encoded request",
		"injection variant 247 (cookie)",
	}
	slices.Sort(notWritable)
	if !slices.Equal(notWritable, want) {
		t.Errorf("not writable as text:\n got %q\nwant %q", notWritable, want)
	}
	if total < 6000 {
		t.Errorf("only %d example requests were found", total)
	}
}

func FuzzParseRaw(f *testing.F) {
	f.Add("GET / HTTP/1.1\nHost: a\n\nbody", false)
	f.Add("POST /x HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=b\r\n\r\n--b\nx\n--b--", true)
	f.Add("\n\nGET /\nA:\tb \n\n\r\n", false)
	f.Fuzz(func(t *testing.T, text string, bodyCRLF bool) {
		rec, err := ParseRaw(text, bodyCRLF)
		if err != nil {
			return
		}
		again, crlf, ok := Raw(rec)
		if !ok {
			return
		}
		back, err := ParseRaw(again, crlf)
		if err != nil {
			t.Fatalf("ParseRaw of Raw's text %q: %v", again, err)
		}
		if !sameReceived(back, rec) {
			t.Fatalf("round trip:\n got %+v\nwant %+v", back, rec)
		}
	})
}

// sameReceived compares the parts of a request that raw text holds.
func sameReceived(a, b httpmodel.Received) bool {
	return a.Method == b.Method && a.Target == b.Target && a.Version == b.Version &&
		slices.Equal(a.Headers, b.Headers) && bytes.Equal(a.Body, b.Body)
}

// hs makes a header list from names and values.
func hs(pairs ...string) []httpmodel.Header {
	var list []httpmodel.Header
	for i := 0; i+1 < len(pairs); i += 2 {
		list = append(list, httpmodel.Header{Name: pairs[i], Value: pairs[i+1]})
	}
	return list
}
