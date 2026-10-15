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

	// Version is the protocol of the request line, such as "HTTP/1.1". It
	// is empty for a request line without one, which a web server reads as
	// HTTP/0.9.
	Version string
	Headers []Header
	Body    []byte

	// RemoteAddr is the IP address of the client, such as "203.0.113.7"
	// or "::1", without a port. It is empty when it is not known.
	RemoteAddr string
}

// Origin says which part of the request a parameter came from.
type Origin int

const (
	OriginQuery Origin = iota + 1 // the query string of the target
	OriginBody                    // the request body
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

// Cookie is one name=value pair of a Cookie header. Cookie values are not
// percent-decoded; they are kept as sent.
type Cookie struct {
	Name  string
	Value string
}

// Parsed is the view of the request after splitting and decoding.
type Parsed struct {
	// Path and RawQuery are the two halves of Received.Target, split at
	// the first "?", without a fragment ("#..."). Both are still
	// percent-encoded. When the target is a
	// full URL, as a proxy request has it, Path starts after the host.
	Path     string
	RawQuery string

	// DecodedPath is Path with its percent-encoding resolved once. A "+"
	// stays a plus sign, because only in a query does it mean a space.
	DecodedPath string

	// Cookies holds the pairs of every Cookie header, in order.
	Cookies []Cookie

	// Query and BodyArgs keep every pair in the order received. A name
	// that appears twice gives two entries.
	//
	// BodyArgs holds what the body parser found: the fields of a form, the
	// values of a JSON document (named by their path, such as
	// "json.user.name" or "json.items.0"), or the text fields of a
	// multipart body.
	Query    []Param
	BodyArgs []Param

	// Files lists the files of a multipart body. Only their names are
	// kept; file contents are not read.
	Files []File

	// XMLText holds the text between the tags of an XML body, one entry
	// per piece, and XMLAttributes the values of all attributes.
	XMLText       []string
	XMLAttributes []string
}

// File is one uploaded file of a multipart body.
type File struct {
	Field string // the name of the form field
	Name  string // the file name as the client sent it, with any path
	Size  int    // the length of the content in bytes; the content is not kept
}

// BodyState says how far the body was inspected.
type BodyState int

const (
	// BodyEmpty: the request has no body. Nothing is missing.
	BodyEmpty BodyState = iota + 1
	// BodyInspected: the whole body was parsed.
	BodyInspected
	// BodyNotInspected: there is a body, but it was not parsed into
	// fields. Status.BodyReason says why.
	BodyNotInspected
	// BodyPartlyInspected: parsing stopped before the end of the body.
	// What was read up to that point is in Parsed; the rest was not
	// inspected. Status.BodyReason says why.
	BodyPartlyInspected
)

// Complete reports whether the whole body was inspected, or there was none.
func (b BodyState) Complete() bool {
	return b == BodyEmpty || b == BodyInspected
}

func (b BodyState) String() string {
	switch b {
	case BodyEmpty:
		return "empty"
	case BodyInspected:
		return "inspected"
	case BodyNotInspected:
		return "not inspected"
	case BodyPartlyInspected:
		return "partly inspected"
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
	Body BodyState
	// BodyFormat is the parser that was chosen from the Content-Type:
	// "form", "json", "multipart" or "xml". It is empty when there is no
	// body or no parser for it.
	BodyFormat string
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

// Args returns the query parameters followed by the body parameters.
func (r *Request) Args() []Param {
	args := make([]Param, 0, len(r.Parsed.Query)+len(r.Parsed.BodyArgs))
	args = append(args, r.Parsed.Query...)
	return append(args, r.Parsed.BodyArgs...)
}
