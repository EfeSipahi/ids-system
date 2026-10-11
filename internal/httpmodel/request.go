// Package httpmodel defines the common HTTP request that every detection
// layer reads (M03), split into three groups (M16):
//
//   - Received: what arrived, before any decoding.
//   - Parsed:   fields taken out of it, with decoded values.
//   - Status:   what could and could not be inspected (M05).
//
// A Request is built once with New and is read-only afterwards. Layers must
// not change it; a rule that needs a transformed value works on its own copy.
package httpmodel

import "strings"

// Header is one header line. Headers are kept as a list, not a map, so the
// order and repeated names survive.
type Header struct {
	Name  string
	Value string
}

// Received is the request as it was given to the IDS.
type Received struct {
	Method string

	// Target is the request target exactly as received, still
	// percent-encoded, for example "/get?arg=..%2f..%2fetc".
	Target string

	Version string
	Headers []Header
	Body    []byte
}

// Origin says which part of the request a parameter came from.
type Origin int

const (
	OriginQuery Origin = iota + 1 // the query string of the target
	OriginBody                    // a form-urlencoded body
)

func (o Origin) String() string {
	switch o {
	case OriginQuery:
		return "query"
	case OriginBody:
		return "body"
	}
	return "unknown"
}

// Param is one name=value pair.
type Param struct {
	// Name and Value are percent-decoded once, with "+" read as a space.
	Name  string
	Value string

	// RawName and RawValue are the same text as received.
	RawName  string
	RawValue string

	Origin Origin
}

// Parsed is the view of the request after splitting and decoding.
type Parsed struct {
	// Path and RawQuery are the two halves of Received.Target, split at
	// the first "?". Both are still percent-encoded.
	Path     string
	RawQuery string

	// Query and Form keep every pair in the order received. A name that
	// appears twice gives two entries.
	Query []Param
	Form  []Param
}

// BodyState says how far the body was inspected.
type BodyState int

const (
	// BodyEmpty: the request has no body. Nothing is missing.
	BodyEmpty BodyState = iota + 1
	// BodyInspected: the body was parsed into Parsed.Form.
	BodyInspected
	// BodyNotInspected: there is a body, but it was not parsed into
	// fields. Status.BodyReason says why.
	BodyNotInspected
)

func (b BodyState) String() string {
	switch b {
	case BodyEmpty:
		return "empty"
	case BodyInspected:
		return "inspected"
	case BodyNotInspected:
		return "not inspected"
	}
	return "unknown"
}

// Issue is something the parser noticed in one part of the request.
type Issue struct {
	Part    string // "query", "body" or "headers"
	Message string
}

// Status records the coverage of the parsed view. "Not inspected" is not an
// attack signal; it only means a clean result does not cover that part.
type Status struct {
	Body       BodyState
	BodyReason string
	Issues     []Issue
}

// Request is the common request with its three groups.
type Request struct {
	Received Received
	Parsed   Parsed
	Status   Status
}

// HeaderValues returns the values of every header called name, in the order
// received. Header names are compared without regard to case.
func (r *Request) HeaderValues(name string) []string {
	var values []string
	for _, h := range r.Received.Headers {
		if strings.EqualFold(h.Name, name) {
			values = append(values, h.Value)
		}
	}
	return values
}

// Args returns the query parameters followed by the form parameters.
func (r *Request) Args() []Param {
	args := make([]Param, 0, len(r.Parsed.Query)+len(r.Parsed.Form))
	args = append(args, r.Parsed.Query...)
	return append(args, r.Parsed.Form...)
}
