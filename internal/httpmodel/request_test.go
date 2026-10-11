package httpmodel

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewSplitsTargetAndKeepsItRaw(t *testing.T) {
	r := New(Received{Method: "GET", Target: "/a%2Fb/c?q=merhaba%20dunya&x=1?2", Version: "HTTP/1.1"})

	if r.Received.Target != "/a%2Fb/c?q=merhaba%20dunya&x=1?2" {
		t.Errorf("received target was changed: %q", r.Received.Target)
	}
	if r.Parsed.Path != "/a%2Fb/c" || r.Parsed.RawQuery != "q=merhaba%20dunya&x=1?2" {
		t.Errorf("path = %q, raw query = %q", r.Parsed.Path, r.Parsed.RawQuery)
	}
	want := []Param{
		{Name: "q", Value: "merhaba dunya", RawName: "q", RawValue: "merhaba%20dunya", Origin: OriginQuery},
		{Name: "x", Value: "1?2", RawName: "x", RawValue: "1?2", Origin: OriginQuery},
	}
	if !reflect.DeepEqual(r.Parsed.Query, want) {
		t.Errorf("query = %+v\nwant    %+v", r.Parsed.Query, want)
	}
	if r.Status.Body != BodyEmpty || len(r.Status.Issues) != 0 {
		t.Errorf("status = %+v", r.Status)
	}
}

func TestRepeatedParametersAreKept(t *testing.T) {
	r := New(Received{Method: "GET", Target: "/arama?q=kitap&q=kalem&q=kitap"})

	var values []string
	for _, p := range r.Parsed.Query {
		if p.Name != "q" {
			t.Errorf("unexpected name %q", p.Name)
		}
		values = append(values, p.Value)
	}
	if want := []string{"kitap", "kalem", "kitap"}; !reflect.DeepEqual(values, want) {
		t.Errorf("values = %q, want %q", values, want)
	}
}

func TestParseParams(t *testing.T) {
	type pair struct{ name, value string }
	tests := []struct {
		raw       string
		want      []pair
		malformed int
	}{
		{"", nil, 0},
		{"a=1", []pair{{"a", "1"}}, 0},
		{"a=1&b=2", []pair{{"a", "1"}, {"b", "2"}}, 0},
		{"a", []pair{{"a", ""}}, 0},
		{"a=", []pair{{"a", ""}}, 0},
		{"=1", []pair{{"", "1"}}, 0},
		{"a=1&&b=2&", []pair{{"a", "1"}, {"b", "2"}}, 0},
		{"a=b=c", []pair{{"a", "b=c"}}, 0},
		{"a+b=c+d", []pair{{"a b", "c d"}}, 0},
		{"arg=..%2f..%2Fetc", []pair{{"arg", "../../etc"}}, 0},
		{"%61rg=x", []pair{{"arg", "x"}}, 0},
		// Decoding happens once: %252f becomes %2f, not "/".
		{"a=%252f", []pair{{"a", "%2f"}}, 0},
		{"a=%00b", []pair{{"a", "\x00b"}}, 0},
		{"a=%ff", []pair{{"a", "\xff"}}, 0},
		// Broken sequences stay as written.
		{"a=%zz", []pair{{"a", "%zz"}}, 1},
		{"a=%2", []pair{{"a", "%2"}}, 1},
		{"a=100%", []pair{{"a", "100%"}}, 1},
		{"%=%", []pair{{"%", "%"}}, 2},
		{"a=%2f%zz%2e", []pair{{"a", "/%zz."}}, 1},
	}
	for _, tt := range tests {
		params, malformed := parseParams(tt.raw, OriginQuery)
		var got []pair
		for _, p := range params {
			got = append(got, pair{p.Name, p.Value})
		}
		if !reflect.DeepEqual(got, tt.want) || malformed != tt.malformed {
			t.Errorf("parseParams(%q) = %q, malformed %d; want %q, malformed %d", tt.raw, got, malformed, tt.want, tt.malformed)
		}
	}
}

func TestMalformedEncodingIsReported(t *testing.T) {
	r := New(Received{Method: "GET", Target: "/x?a=%zz&b=%2"})

	if len(r.Status.Issues) != 1 || r.Status.Issues[0].Part != "query" ||
		!strings.Contains(r.Status.Issues[0].Message, "2 names or values") {
		t.Errorf("issues = %+v", r.Status.Issues)
	}
	if r.Parsed.Query[0].Value != "%zz" || r.Parsed.Query[1].Value != "%2" {
		t.Errorf("query = %+v", r.Parsed.Query)
	}
}

func TestFormBodyIsParsed(t *testing.T) {
	body := []byte("arg=..%2F..%2Fetc%2Fpasswd&foo=var&foo=two")
	r := New(Received{
		Method:  "POST",
		Target:  "/post?id=7",
		Headers: []Header{{"Host", "localhost"}, {"content-type", "Application/X-WWW-Form-Urlencoded; charset=UTF-8"}},
		Body:    body,
	})

	if r.Status.Body != BodyInspected || r.Status.BodyReason != "" {
		t.Errorf("status = %+v", r.Status)
	}
	want := []Param{
		{Name: "arg", Value: "../../etc/passwd", RawName: "arg", RawValue: "..%2F..%2Fetc%2Fpasswd", Origin: OriginBody},
		{Name: "foo", Value: "var", RawName: "foo", RawValue: "var", Origin: OriginBody},
		{Name: "foo", Value: "two", RawName: "foo", RawValue: "two", Origin: OriginBody},
	}
	if !reflect.DeepEqual(r.Parsed.Form, want) {
		t.Errorf("form = %+v\nwant   %+v", r.Parsed.Form, want)
	}
	if string(r.Received.Body) != "arg=..%2F..%2Fetc%2Fpasswd&foo=var&foo=two" {
		t.Errorf("received body was changed: %q", r.Received.Body)
	}

	// Args is the query first, then the body.
	var names []string
	for _, p := range r.Args() {
		names = append(names, p.Origin.String()+":"+p.Name)
	}
	if want := []string{"query:id", "body:arg", "body:foo", "body:foo"}; !reflect.DeepEqual(names, want) {
		t.Errorf("args = %q, want %q", names, want)
	}
}

// A body that cannot be parsed must be reported, and the rest of the
// request must still be parsed (M05, M17).
func TestBodyNotInspected(t *testing.T) {
	tests := []struct {
		name    string
		headers []Header
		reason  string
	}{
		{"json", []Header{{"Content-Type", "application/json"}}, `content type "application/json" is not parsed`},
		{"multipart", []Header{{"Content-Type", "multipart/form-data; boundary=x"}}, `content type "multipart/form-data" is not parsed`},
		{"no content type", nil, "no Content-Type header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(Received{Method: "POST", Target: "/api?q=../x", Headers: tt.headers, Body: []byte(`{"a":"../../etc"}`)})

			if r.Status.Body != BodyNotInspected || !strings.Contains(r.Status.BodyReason, tt.reason) {
				t.Errorf("status = %+v, want not inspected with reason containing %q", r.Status, tt.reason)
			}
			if len(r.Parsed.Form) != 0 {
				t.Errorf("form = %+v, want none", r.Parsed.Form)
			}
			if len(r.Parsed.Query) != 1 || r.Parsed.Query[0].Value != "../x" {
				t.Errorf("query = %+v, want it parsed anyway", r.Parsed.Query)
			}
			if string(r.Received.Body) != `{"a":"../../etc"}` {
				t.Errorf("received body = %q", r.Received.Body)
			}
		})
	}
}

// A request without a body is complete even if it names a content type.
func TestEmptyBodyIsNotIncomplete(t *testing.T) {
	r := New(Received{Method: "GET", Target: "/", Headers: []Header{{"Content-Type", "application/json"}}})
	if r.Status.Body != BodyEmpty || r.Status.BodyReason != "" || len(r.Status.Issues) != 0 {
		t.Errorf("status = %+v", r.Status)
	}
}

func TestHeaderValues(t *testing.T) {
	r := New(Received{
		Method: "GET",
		Target: "/",
		Headers: []Header{
			{"Host", "localhost"},
			{"X-Forwarded-For", "10.0.0.1"},
			{"x-forwarded-for", "10.0.0.2"},
		},
	})
	if got := r.HeaderValues("X-FORWARDED-FOR"); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("X-Forwarded-For = %q", got)
	}
	if got := r.HeaderValues("Cookie"); got != nil {
		t.Errorf("Cookie = %q, want none", got)
	}
}

func TestTwoContentTypeHeaders(t *testing.T) {
	r := New(Received{
		Method:  "POST",
		Target:  "/",
		Headers: []Header{{"Content-Type", "application/x-www-form-urlencoded"}, {"Content-Type", "application/json"}},
		Body:    []byte("a=1"),
	})
	if r.Status.Body != BodyInspected || len(r.Parsed.Form) != 1 {
		t.Errorf("status = %+v, form = %+v", r.Status, r.Parsed.Form)
	}
	if len(r.Status.Issues) != 1 || r.Status.Issues[0].Part != "headers" {
		t.Errorf("issues = %+v", r.Status.Issues)
	}
}
