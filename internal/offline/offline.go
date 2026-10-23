// Package offline is the input adapter for requests stored in a file (M01).
// It reads a JSON list of example requests and turns each one into the
// common request of package httpmodel.
//
// The field names follow the CRS regression tests (uri, headers,
// expect_ids, no_expect_ids) so those tests can be converted directly.
package offline

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// Example is one request from a file, with what a test expects from it.
type Example struct {
	Name    string
	Request *httpmodel.Request

	// ExpectIDs are rule IDs that must match the request; NoExpectIDs are
	// rule IDs that must not. Both may be empty.
	ExpectIDs   []int
	NoExpectIDs []int

	// ExpectLog is a pattern that the log line of at least one match must
	// contain; NoExpectLog is one that no log line may contain. Either may
	// be nil. A log line names the rule and carries its message and data;
	// see engine.Match.LogLine.
	ExpectLog   *regexp.Regexp
	NoExpectLog *regexp.Regexp
}

// HasExpectation reports whether the example expects anything.
func (ex Example) HasExpectation() bool {
	return len(ex.ExpectIDs) > 0 || len(ex.NoExpectIDs) > 0 || ex.ExpectLog != nil || ex.NoExpectLog != nil
}

// fileExample is the JSON form of one example.
type fileExample struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	URI    string `json:"uri"`
	// Version left out means HTTP/1.1. An empty text means a request line
	// without a version, as an HTTP/0.9 client sends it.
	Version *string `json:"version"`

	// Headers is a list of [name, value] pairs. A list keeps the order and
	// lets the same header appear twice; a JSON object could do neither.
	Headers [][]string `json:"headers"`

	// Body is the body as text. BodyBase64 is for a body that is not
	// UTF-8 text, which JSON cannot hold: the same bytes in base64. Only
	// one of the two may be set.
	Body       string `json:"body"`
	BodyBase64 string `json:"body_base64"`

	// RemoteAddr and RemotePort are the address of the client, ServerAddr
	// and ServerPort the address the request was sent to. Each may be left
	// out.
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	ServerAddr  string `json:"server_addr"`
	ServerPort  int    `json:"server_port"`
	ExpectIDs   []int  `json:"expect_ids"`
	NoExpectIDs []int  `json:"no_expect_ids"`
	ExpectLog   string `json:"expect_log"`
	NoExpectLog string `json:"no_expect_log"`
}

const defaultVersion = "HTTP/1.1"

// LoadFile reads the examples in the file at path.
func LoadFile(path string) ([]Example, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	examples, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return examples, nil
}

// Load reads a JSON list of examples from r. A field it does not know is an
// error, so a misspelled name cannot quietly change what is tested.
func Load(r io.Reader) ([]Example, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var raw []fileExample
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("invalid JSON: unexpected content after the list")
	}

	examples := make([]Example, 0, len(raw))
	for i, fe := range raw {
		ex, err := fe.toExample()
		if err != nil {
			return nil, fmt.Errorf("example %d (%q): %w", i+1, fe.Name, err)
		}
		examples = append(examples, ex)
	}
	return examples, nil
}

func (fe fileExample) toExample() (Example, error) {
	if fe.Method == "" {
		return Example{}, errors.New("method is missing")
	}
	if fe.URI == "" {
		return Example{}, errors.New("uri is missing")
	}

	rec := httpmodel.Received{
		Method:     fe.Method,
		Target:     fe.URI,
		Version:    defaultVersion,
		RemoteAddr: fe.RemoteAddr,
		RemotePort: fe.RemotePort,
		LocalAddr:  fe.ServerAddr,
		LocalPort:  fe.ServerPort,
	}
	for _, addr := range []struct {
		field, ip, portField string
		port                 int
	}{
		{"remote_addr", fe.RemoteAddr, "remote_port", fe.RemotePort},
		{"server_addr", fe.ServerAddr, "server_port", fe.ServerPort},
	} {
		if addr.ip != "" {
			if _, err := netip.ParseAddr(addr.ip); err != nil {
				return Example{}, fmt.Errorf("%s: %w", addr.field, err)
			}
		}
		if addr.port < 0 || addr.port > 65535 {
			return Example{}, fmt.Errorf("%s %d is not a port number", addr.portField, addr.port)
		}
	}
	if fe.Version != nil {
		rec.Version = *fe.Version
	}
	for i, h := range fe.Headers {
		if len(h) != 2 {
			return Example{}, fmt.Errorf("header %d must be a [name, value] pair, found %d items", i+1, len(h))
		}
		if h[0] == "" {
			return Example{}, fmt.Errorf("header %d has an empty name", i+1)
		}
		rec.Headers = append(rec.Headers, httpmodel.Header{Name: h[0], Value: h[1]})
	}
	switch {
	case fe.Body != "" && fe.BodyBase64 != "":
		return Example{}, errors.New("body and body_base64 are both set")
	case fe.Body != "":
		rec.Body = []byte(fe.Body)
	case fe.BodyBase64 != "":
		body, err := base64.StdEncoding.DecodeString(fe.BodyBase64)
		if err != nil {
			return Example{}, fmt.Errorf("body_base64: %w", err)
		}
		rec.Body = body
	}

	ex := Example{
		Name:        fe.Name,
		Request:     httpmodel.New(rec),
		ExpectIDs:   fe.ExpectIDs,
		NoExpectIDs: fe.NoExpectIDs,
	}
	var err error
	if fe.ExpectLog != "" {
		if ex.ExpectLog, err = regexp.Compile(fe.ExpectLog); err != nil {
			return Example{}, fmt.Errorf("expect_log: %w", err)
		}
	}
	if fe.NoExpectLog != "" {
		if ex.NoExpectLog, err = regexp.Compile(fe.NoExpectLog); err != nil {
			return Example{}, fmt.Errorf("no_expect_log: %w", err)
		}
	}
	return ex, nil
}
