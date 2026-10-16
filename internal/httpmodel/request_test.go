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
	if r.Parsed.DecodedPath != "/a/b/c" {
		t.Errorf("decoded path = %q", r.Parsed.DecodedPath)
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
	if !reflect.DeepEqual(r.Parsed.BodyArgs, want) {
		t.Errorf("form = %+v\nwant   %+v", r.Parsed.BodyArgs, want)
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
		{"plain text", []Header{{"Content-Type", "text/plain; charset=utf-8"}}, `content type "text/plain" is not parsed`},
		{"binary", []Header{{"Content-Type", "application/octet-stream"}}, `content type "application/octet-stream" is not parsed`},
		{"no content type", nil, "no Content-Type header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New(Received{Method: "POST", Target: "/api?q=../x", Headers: tt.headers, Body: []byte(`{"a":"../../etc"}`)})

			if r.Status.Body != BodyNotInspected || !strings.Contains(r.Status.BodyReason, tt.reason) {
				t.Errorf("status = %+v, want not inspected with reason containing %q", r.Status, tt.reason)
			}
			if len(r.Parsed.BodyArgs) != 0 {
				t.Errorf("form = %+v, want none", r.Parsed.BodyArgs)
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
	if r.Status.Body != BodyInspected || len(r.Parsed.BodyArgs) != 1 {
		t.Errorf("status = %+v, form = %+v", r.Status, r.Parsed.BodyArgs)
	}
	if len(r.Status.Issues) != 1 || r.Status.Issues[0].Part != "headers" {
		t.Errorf("issues = %+v", r.Status.Issues)
	}
}

func TestCookies(t *testing.T) {
	r := New(Received{
		Method: "GET",
		Target: "/",
		Headers: []Header{
			{"Cookie", "session=abc123; theme=dark;  path=/../x; flag; =orphan; a=b=c; enc=%2e%2e"},
			{"cookie", "second=1"},
		},
	})
	want := []Cookie{
		{"session", "abc123"},
		{"theme", "dark"},
		{"path", "/../x"},
		{"flag", ""},
		// "=orphan" has no name and is ignored.
		{"a", "b=c"},
		// Cookie values are not decoded.
		{"enc", "%2e%2e"},
		{"second", "1"},
	}
	if !reflect.DeepEqual(r.Parsed.Cookies, want) {
		t.Errorf("cookies = %+v\nwant      %+v", r.Parsed.Cookies, want)
	}
	if got := New(Received{Method: "GET", Target: "/"}).Parsed.Cookies; got != nil {
		t.Errorf("cookies without a header = %+v", got)
	}
}

func TestPathOfFullURL(t *testing.T) {
	tests := []struct{ target, path, query string }{
		{"/a/b?x=1", "/a/b", "x=1"},
		{"http://example.com/a/b?x=1", "/a/b", "x=1"},
		{"HTTPS://example.com:8443/a", "/a", ""},
		{"http://example.com", "/", ""},
		{"*", "*", ""},
		{"/redirect/http://other/", "/redirect/http://other/", ""},
	}
	for _, tt := range tests {
		r := New(Received{Method: "GET", Target: tt.target})
		if r.Parsed.Path != tt.path || r.Parsed.RawQuery != tt.query {
			t.Errorf("%s: path %q, query %q; want %q, %q", tt.target, r.Parsed.Path, r.Parsed.RawQuery, tt.path, tt.query)
		}
		if r.Received.Target != tt.target {
			t.Errorf("%s: the received target was changed", tt.target)
		}
	}
}

func bodyRequest(contentType, body string) *Request {
	return New(Received{Method: "POST", Target: "/", Headers: []Header{{"Content-Type", contentType}}, Body: []byte(body)})
}

func namesAndValues(params []Param) []string {
	var out []string
	for _, p := range params {
		out = append(out, p.Name+"="+p.Value)
	}
	return out
}

func TestJSONBody(t *testing.T) {
	r := bodyRequest("application/json; charset=utf-8", `{
		"user": {"name": "efe", "roles": ["admin", "dev"]},
		"count": 3, "price": 1.50, "big": 12345678901234567890,
		"ok": true, "none": null,
		"path": "..\/..\/etc\u002fpasswd",
		"a": 1, "a": 2,
		"empty": {}, "list": [[1], []]
	}`)
	want := []string{
		"json.user.name=efe", "json.user.roles.0=admin", "json.user.roles.1=dev",
		// A list also gives its length, after its elements.
		"json.user.roles=2",
		// Numbers keep the text they were written with.
		"json.count=3", "json.price=1.50", "json.big=12345678901234567890",
		"json.ok=true", "json.none=",
		// Escapes in strings are resolved.
		"json.path=../../etc/passwd",
		// A key that appears twice gives two values.
		"json.a=1", "json.a=2",
		// An empty list gives no length, and neither does an empty object.
		"json.list.0.0=1", "json.list.0=1", "json.list=2",
	}
	if got := namesAndValues(r.Parsed.BodyArgs); !reflect.DeepEqual(got, want) {
		t.Errorf("arguments = %q\nwant        %q", got, want)
	}
	if r.Status.Body != BodyInspected || r.Status.BodyFormat != "json" || r.Parsed.BodyArgs[0].Origin != OriginBody {
		t.Errorf("status = %+v", r.Status)
	}

	// A document that is only one value.
	if got := namesAndValues(bodyRequest("application/json", `"../x"`).Parsed.BodyArgs); !reflect.DeepEqual(got, []string{"json=../x"}) {
		t.Errorf("arguments = %q", got)
	}

	for _, contentType := range []string{"APPLICATION/JSON", "application/json; charset=utf-8", "application/jsonx"} {
		if r := bodyRequest(contentType, `{"a":"b"}`); r.Status.BodyFormat != "json" || len(r.Parsed.BodyArgs) != 1 {
			t.Errorf("%s: status = %+v", contentType, r.Status)
		}
	}
	// Other JSON types are left to the CRS rules 901360 and 901370, which
	// choose the reader with ctl:requestBodyProcessor. On its own the
	// request does not read them; asked to, it does.
	for _, contentType := range []string{"application/vnd.api+json", "application/x-amz-json-1.1"} {
		r := bodyRequest(contentType, `{"a":"b"}`)
		if r.Status.Body != BodyNotInspected || r.Status.BodyFormat != "" {
			t.Errorf("%s: status = %+v", contentType, r.Status)
		}
		if again := r.WithBodyFormat("json"); again.Status.BodyFormat != "json" || len(again.Parsed.BodyArgs) != 1 || r.Status.BodyFormat != "" {
			t.Errorf("%s as JSON: status = %+v, original %+v", contentType, again.Status, r.Status)
		}
	}
}

// The reader is chosen by the start of the type, as ModSecurity and Coraza
// do it, and the declared format is known without a body.
func TestBodyFormatChoice(t *testing.T) {
	for contentType, want := range map[string]string{
		"application/x-www-form-urlencoded":  "form",
		"application/x-www-form-urlencodedX": "form",
		"Multipart/Form-Data; boundary=x":    "multipart",
		"multipart/form-dataX; boundary=x":   "multipart",
		"text/xml":                           "xml",
		"application/soap+xml":               "xml",
		"text/plain":                         "",
		"application/x-www-form-urlencode":   "",
	} {
		r := New(Received{Method: "GET", Target: "/", Version: "HTTP/1.1", Headers: []Header{{Name: "Content-Type", Value: contentType}}})
		if got := r.DeclaredBodyFormat(); got != want {
			t.Errorf("%q: declared format %q, want %q", contentType, got, want)
		}
	}
	if got := New(Received{Method: "GET", Target: "/"}).DeclaredBodyFormat(); got != "" {
		t.Errorf("no Content-Type: %q", got)
	}
}

// A fragment is not part of path or query, but stays in the target.
func TestFragment(t *testing.T) {
	r := New(Received{Method: "GET", Target: "/a/b?x=1&y=2#top?z=3", Version: "HTTP/1.1"})
	if r.Parsed.Path != "/a/b" || r.Parsed.RawQuery != "x=1&y=2" || len(r.Parsed.Query) != 2 || r.Parsed.Query[1].Value != "2" {
		t.Errorf("parsed = %+v", r.Parsed)
	}
	if r := New(Received{Method: "GET", Target: "/a#b?c"}); r.Parsed.Path != "/a" || r.Parsed.RawQuery != "" {
		t.Errorf("parsed = %+v", r.Parsed)
	}
}

// A JSON document that breaks off or is not valid is read as far as it
// goes. The values before the fault are inspected and the status says that
// the rest was not.
func TestBrokenJSONBody(t *testing.T) {
	tests := []struct {
		body string
		want []string
	}{
		{`{"a": "../x", "b": `, []string{"json.a=../x"}},
		{`{"a": "../x", 'b': 1}`, []string{"json.a=../x"}},
		{`{"a": "../x"} trailing`, []string{"json.a=../x"}},
		{`{"a": "../x"}{"b": 1}`, []string{"json.a=../x"}},
		{`not json`, nil},
		{strings.Repeat("[", 100) + strings.Repeat("]", 100), nil},
	}
	for _, tt := range tests {
		r := bodyRequest("application/json", tt.body)
		if got := namesAndValues(r.Parsed.BodyArgs); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%.30s: arguments = %q, want %q", tt.body, got, tt.want)
		}
		if r.Status.Body != BodyPartlyInspected || !strings.Contains(r.Status.BodyReason, "the json body could not be read to its end") {
			t.Errorf("%.30s: status = %+v", tt.body, r.Status)
		}
		if r.Status.Body.Complete() {
			t.Errorf("%.30s: a partly inspected body counts as complete", tt.body)
		}
	}
}

func TestMultipartBody(t *testing.T) {
	body := "--XyZ\r\n" +
		"Content-Disposition: form-data; name=\"title\"\r\n\r\n" +
		"line one\r\nline two\r\n" +
		"--XyZ\r\n" +
		"Content-Disposition: form-data; name=\"upload\"; filename=\"..\\\\..\\\\boot.ini\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"the content of the file, which is not kept: ../../etc\r\n" +
		"--XyZ\r\n" +
		"Content-Disposition: form-data; name=\"title\"\r\n\r\n" +
		"again\r\n" +
		"--XyZ\r\n" +
		"Content-Disposition: form-data; name=\"empty\"; filename=\"\"\r\n\r\n\r\n" +
		"--XyZ--\r\n"
	r := bodyRequest("multipart/form-data; boundary=XyZ", body)

	if got, want := namesAndValues(r.Parsed.BodyArgs), []string{"title=line one\r\nline two", "title=again"}; !reflect.DeepEqual(got, want) {
		t.Errorf("arguments = %q, want %q", got, want)
	}
	// The file name keeps its path; Go's own helper would cut it off. The
	// size is that of the content, 53 bytes; the line break before the
	// next boundary belongs to the boundary.
	wantFiles := []File{{Field: "upload", Name: `..\..\boot.ini`, Size: 53}, {Field: "empty", Name: ""}}
	if !reflect.DeepEqual(r.Parsed.Files, wantFiles) {
		t.Errorf("files = %+v, want %+v", r.Parsed.Files, wantFiles)
	}
	if r.Status.Body != BodyInspected || r.Status.BodyFormat != "multipart" {
		t.Errorf("status = %+v", r.Status)
	}

	broken := []struct{ contentType, body, reason string }{
		{"multipart/form-data", body, "names no boundary"},
		{"multipart/form-data; boundary=XyZ", body[:len(body)-60], "could not be read to its end"},
		{"multipart/form-data; boundary=XyZ", "--XyZ\r\nContent-Disposition: form-data; name=\"a\r\n\r\nx\r\n--XyZ--\r\n", "Content-Disposition"},
	}
	for _, tt := range broken {
		r := bodyRequest(tt.contentType, tt.body)
		if r.Status.Body != BodyPartlyInspected || !strings.Contains(r.Status.BodyReason, tt.reason) {
			t.Errorf("%s: status = %+v, want partly inspected with %q", tt.contentType, r.Status, tt.reason)
		}
	}
	// What came before the break is kept.
	if r := bodyRequest("multipart/form-data; boundary=XyZ", body[:len(body)-60]); len(r.Parsed.BodyArgs) < 1 || r.Parsed.BodyArgs[0].Name != "title" {
		t.Errorf("arguments before the break = %+v", r.Parsed.BodyArgs)
	}
}

func TestXMLBody(t *testing.T) {
	r := bodyRequest("text/xml", `<?xml version="1.0" encoding="UTF-8"?>
<order id="42" path="../../etc">
  <item note="a &amp; b">  first &lt;b&gt;  </item>
  <item><![CDATA[../../raw <data>]]></item>
  <empty/>
  <!-- a comment is not content -->
</order>`)
	if want := []string{"first <b>", "../../raw <data>"}; !reflect.DeepEqual(r.Parsed.XMLText, want) {
		t.Errorf("text = %q, want %q", r.Parsed.XMLText, want)
	}
	if want := []string{"42", "../../etc", "a & b"}; !reflect.DeepEqual(r.Parsed.XMLAttributes, want) {
		t.Errorf("attributes = %q, want %q", r.Parsed.XMLAttributes, want)
	}
	if r.Status.Body != BodyInspected || r.Status.BodyFormat != "xml" || r.Parsed.BodyArgs != nil {
		t.Errorf("status = %+v, arguments = %+v", r.Status, r.Parsed.BodyArgs)
	}
	for _, contentType := range []string{"application/xml", "application/soap+xml; charset=utf-8"} {
		if r := bodyRequest(contentType, `<a>x</a>`); r.Status.BodyFormat != "xml" || len(r.Parsed.XMLText) != 1 {
			t.Errorf("%s: status = %+v", contentType, r.Status)
		}
	}

	// An entity that would pull in a file is not resolved: the document
	// cannot make the reader open anything.
	r = bodyRequest("application/xml", `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x; after</a>`)
	for _, piece := range r.Parsed.XMLText {
		if strings.Contains(piece, "root:") {
			t.Errorf("an external entity was loaded: %q", piece)
		}
	}

	r = bodyRequest("application/xml", `<a>before</a><b attr="x">unclosed <c`)
	if r.Status.Body != BodyPartlyInspected || len(r.Parsed.XMLText) == 0 || r.Parsed.XMLText[0] != "before" {
		t.Errorf("status = %+v, text = %q", r.Status, r.Parsed.XMLText)
	}
	r = bodyRequest("application/xml", `<?xml version="1.0" encoding="ISO-8859-1"?><a>x</a>`)
	if r.Status.Body != BodyPartlyInspected || !strings.Contains(r.Status.BodyReason, "ISO-8859-1") {
		t.Errorf("status = %+v", r.Status)
	}
}

func TestBodyOverTheLimit(t *testing.T) {
	big := "a=" + strings.Repeat("x", DefaultBodyLimit)
	r := bodyRequest("application/x-www-form-urlencoded", big)
	if r.Status.Body != BodyNotInspected || !strings.Contains(r.Status.BodyReason, "more than the limit") || r.Parsed.BodyArgs != nil {
		t.Errorf("status = %+v", r.Status)
	}
	if len(r.Received.Body) != len(big) {
		t.Error("the received body was cut")
	}
	// Exactly at the limit is still parsed.
	r = bodyRequest("application/x-www-form-urlencoded", big[:DefaultBodyLimit])
	if r.Status.Body != BodyInspected || len(r.Parsed.BodyArgs) != 1 {
		t.Errorf("status = %+v", r.Status)
	}
}

// The body parsers read what an attacker sends. No input may make them
// panic. Without -fuzz the seeds run as an ordinary test.
func FuzzBodyParsers(f *testing.F) {
	f.Add(`{"a": ["b", {"c": null}]}`, "B")
	f.Add("--B\r\nContent-Disposition: form-data; name=\"a\"; filename=\"x\"\r\n\r\ny\r\n--B--", "B")
	f.Add(`<a b="c">d<e/></a>`, "x")
	f.Add("[[[[", "")
	f.Fuzz(func(t *testing.T, body, boundary string) {
		for _, contentType := range []string{"application/json", "application/xml", "multipart/form-data; boundary=" + boundary, "application/x-www-form-urlencoded"} {
			r := bodyRequest(contentType, body)
			if body != "" && r.Status.Body == BodyEmpty {
				t.Errorf("%s: a body of %d bytes is reported as empty", contentType, len(body))
			}
			if r.Status.Body == BodyPartlyInspected && r.Status.BodyReason == "" {
				t.Errorf("%s: partly inspected without a reason", contentType)
			}
		}
	})
}

func TestDecodedPath(t *testing.T) {
	tests := []struct {
		target  string
		decoded string
		issue   bool
	}{
		{"/a/b", "/a/b", false},
		{"/bar%3Cscript%3E", "/bar<script>", false},
		// A plus sign in a path is a plus sign.
		{"/a+b%20c?q=a+b", "/a+b c", false},
		{"/a%252fb", "/a%2fb", false},
		{"/100%/x%zz", "/100%/x%zz", true},
	}
	for _, tt := range tests {
		r := New(Received{Method: "GET", Target: tt.target})
		if r.Parsed.DecodedPath != tt.decoded {
			t.Errorf("%s: decoded path = %q, want %q", tt.target, r.Parsed.DecodedPath, tt.decoded)
		}
		if got := len(r.Status.Issues) == 1 && r.Status.Issues[0].Part == "path"; got != tt.issue {
			t.Errorf("%s: issues = %+v", tt.target, r.Status.Issues)
		}
	}
}

// The header lines of multipart parts are kept as received, the way
// ModSecurity builds MULTIPART_PART_HEADERS, also when Go's reader rejects
// one of them.
func TestPartHeaderLines(t *testing.T) {
	body := "preamble\r\n" +
		"--b\r\n" +
		"Content-Disposition: form-data; name=\"note\"\r\n" +
		"content-type: text/plain;\r\n charset=utf-8\r\n" +
		"\r\n" +
		"--b is not a delimiter here, it is content\r\n" +
		"--b\r\n" +
		"Content-Disposition: form-data; name=\"_charset_\"\r\n" +
		"\r\n" +
		"utf-8\r\n" +
		"--b\r\n" +
		"Content\x0e-Disposition: form-data; name=\"bad\"\r\n" +
		"\r\n" +
		"x\r\n" +
		"--b--\r\n" +
		"Epilogue: not a header\r\n"
	r := bodyRequest("multipart/form-data; boundary=b", body)
	want := []PartHeader{
		{Part: "note", Line: `Content-Disposition: form-data; name="note"`},
		// A folded line is joined to the one before with one space.
		{Part: "note", Line: "content-type: text/plain; charset=utf-8"},
		{Part: "_charset_", Line: `Content-Disposition: form-data; name="_charset_"`},
		// The name of this part cannot be read.
		{Part: "", Line: "Content\x0e-Disposition: form-data; name=\"bad\""},
	}
	if !reflect.DeepEqual(r.Parsed.PartHeaders, want) {
		t.Errorf("part headers =\n%q\nwant\n%q", r.Parsed.PartHeaders, want)
	}
	// Go's reader stops at the bad header, the scan of the lines does not.
	if r.Status.Body != BodyPartlyInspected {
		t.Errorf("status = %+v", r.Status)
	}
	if got := bodyRequest("application/x-www-form-urlencoded", body).Parsed.PartHeaders; got != nil {
		t.Errorf("a form body has part headers: %q", got)
	}
}
