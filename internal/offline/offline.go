// Package offline is the input adapter for requests stored in a file (M01).
// It reads a JSON list of example requests and turns each one into the
// common request of package httpmodel.
//
// The field names follow the CRS regression tests (uri, headers,
// expect_ids, no_expect_ids) so those tests can be converted directly.
package offline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

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
}

// fileExample is the JSON form of one example.
type fileExample struct {
	Name    string `json:"name"`
	Method  string `json:"method"`
	URI     string `json:"uri"`
	Version string `json:"version"`

	// Headers is a list of [name, value] pairs. A list keeps the order and
	// lets the same header appear twice; a JSON object could do neither.
	Headers [][]string `json:"headers"`

	Body        string `json:"body"`
	ExpectIDs   []int  `json:"expect_ids"`
	NoExpectIDs []int  `json:"no_expect_ids"`
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
		Method:  fe.Method,
		Target:  fe.URI,
		Version: fe.Version,
	}
	if rec.Version == "" {
		rec.Version = defaultVersion
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
	if fe.Body != "" {
		rec.Body = []byte(fe.Body)
	}

	return Example{
		Name:        fe.Name,
		Request:     httpmodel.New(rec),
		ExpectIDs:   fe.ExpectIDs,
		NoExpectIDs: fe.NoExpectIDs,
	}, nil
}
