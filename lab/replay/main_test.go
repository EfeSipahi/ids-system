package main

import (
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// The request goes out as the example writes it: the order and case of the
// headers kept; Content-Length added only for a body without one; with
// -keepalive, the Connection header left out.
func TestRaw(t *testing.T) {
	req := httpmodel.New(httpmodel.Received{
		Method: "POST", Target: "/a?b=c", Version: "HTTP/1.1",
		Headers: []httpmodel.Header{{Name: "host", Value: "localhost:8080"}, {Name: "Cache-control", Value: "no-cache"}, {Name: "Connection", Value: "close"}},
		Body:    []byte("x=1"),
	})
	want := "POST /a?b=c HTTP/1.1\r\nhost: localhost:8080\r\nCache-control: no-cache\r\nConnection: close\r\nContent-Length: 3\r\n\r\nx=1"
	if got := string(raw(req, options{})); got != want {
		t.Errorf("raw:\n%q\nwant\n%q", got, want)
	}
	want = "POST /a?b=c HTTP/1.1\r\nhost: localhost:8080\r\nCache-control: no-cache\r\nContent-Length: 3\r\nX-Forwarded-For: 198.51.100.7\r\n\r\nx=1"
	if got := string(raw(req, options{keepalive: true, xff: "198.51.100.7"})); got != want {
		t.Errorf("keepalive and xff:\n%q\nwant\n%q", got, want)
	}
}
