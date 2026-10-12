package offline

import (
	"reflect"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

func TestLoadFile(t *testing.T) {
	examples, err := LoadFile("../../testdata/requests/path-traversal.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(examples) != 6 {
		t.Fatalf("got %d examples, want 6", len(examples))
	}

	// A header value with backslashes arrives unchanged.
	first := examples[0]
	if got := first.Request.HeaderValues("FoobarHeader"); !reflect.DeepEqual(got, []string{`/../../../././..\ ../../etc/master.passwd`}) {
		t.Errorf("FoobarHeader = %q", got)
	}
	if !reflect.DeepEqual(first.ExpectIDs, []int{930110}) || first.NoExpectIDs != nil {
		t.Errorf("expectations = %v, %v", first.ExpectIDs, first.NoExpectIDs)
	}

	// The query string is parsed.
	query := examples[1].Request.Parsed.Query
	if len(query) != 1 || query[0].Name != "arg" || query[0].Value != "../../../etc/passwd" {
		t.Errorf("query = %+v", query)
	}

	// The form body is parsed and reported as inspected.
	post := examples[2].Request
	if post.Status.Body != httpmodel.BodyInspected || len(post.Parsed.BodyArgs) != 2 || post.Parsed.BodyArgs[0].Value != "../../../etc/passwd" {
		t.Errorf("status = %+v, form = %+v", post.Status, post.Parsed.BodyArgs)
	}

	// A missing version gets the default.
	normal := examples[4]
	if normal.Request.Received.Version != "HTTP/1.1" {
		t.Errorf("version = %q", normal.Request.Received.Version)
	}
	if !reflect.DeepEqual(normal.NoExpectIDs, []int{930100, 930110}) {
		t.Errorf("no_expect_ids = %v", normal.NoExpectIDs)
	}
	if got := examples[5].Request.Parsed.BodyArgs[1].Value; got != "gizli parola" {
		t.Errorf("parola = %q", got)
	}
}

func TestLoadKeepsRepeatedHeaders(t *testing.T) {
	src := `[{"method": "GET", "uri": "/", "headers": [["Cookie", "a=1"], ["cookie", "b=2"]]}]`
	examples, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []httpmodel.Header{{Name: "Cookie", Value: "a=1"}, {Name: "cookie", Value: "b=2"}}
	if got := examples[0].Request.Received.Headers; !reflect.DeepEqual(got, want) {
		t.Errorf("headers = %+v, want %+v", got, want)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		msg  string
	}{
		{"not json", `not json`, "invalid JSON"},
		{"not a list", `{"method": "GET", "uri": "/"}`, "invalid JSON"},
		{"content after list", `[] []`, "unexpected content after the list"},
		{"unknown field", `[{"method": "GET", "uri": "/", "expect_id": [1]}]`, `unknown field "expect_id"`},
		{"no method", `[{"name": "x", "uri": "/"}]`, `example 1 ("x"): method is missing`},
		{"no uri", `[{"method": "GET", "uri": "/"}, {"method": "GET"}]`, "example 2 (\"\"): uri is missing"},
		{"header with one item", `[{"method": "GET", "uri": "/", "headers": [["Host"]]}]`, "header 1 must be a [name, value] pair, found 1 items"},
		{"header with three items", `[{"method": "GET", "uri": "/", "headers": [["A", "b"], ["C", "d", "e"]]}]`, "header 2 must be a [name, value] pair, found 3 items"},
		{"header without name", `[{"method": "GET", "uri": "/", "headers": [["", "x"]]}]`, "header 1 has an empty name"},
		{"bad expect_log", `[{"method": "GET", "uri": "/", "expect_log": "a("}]`, "expect_log: error parsing regexp"},
		{"bad no_expect_log", `[{"method": "GET", "uri": "/", "no_expect_log": "["}]`, "no_expect_log: error parsing regexp"},
		{"bad body_base64", `[{"method": "POST", "uri": "/", "body_base64": "***"}]`, "body_base64: illegal base64 data"},
		{"two bodies", `[{"method": "POST", "uri": "/", "body": "a", "body_base64": "YQ=="}]`, "body and body_base64 are both set"},
		{"headers as object", `[{"method": "GET", "uri": "/", "headers": {"Host": "x"}}]`, "invalid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("error = %v, want one containing %q", err, tt.msg)
			}
		})
	}
}

// A body that is not text is given in base64, and a test may expect a
// pattern in the log text.
func TestLoadBinaryBodyAndLogExpectations(t *testing.T) {
	src := `[
		{"method": "POST", "uri": "/", "body_base64": "rO0ABQ==", "expect_log": "found within ARGS:x", "no_expect_log": "id \"9\""},
		{"method": "GET", "uri": "/"}
	]`
	examples, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	ex := examples[0]
	if got := string(ex.Request.Received.Body); got != "\xac\xed\x00\x05" {
		t.Errorf("body = %q", got)
	}
	if !ex.HasExpectation() || !ex.ExpectLog.MatchString("x found within ARGS:x: y") || !ex.NoExpectLog.MatchString(`[id "9"]`) {
		t.Errorf("expectations = %v, %v", ex.ExpectLog, ex.NoExpectLog)
	}
	if examples[1].HasExpectation() {
		t.Error("an example without expectations reports one")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile("does-not-exist.json"); err == nil {
		t.Error("no error for a missing file")
	}
}
