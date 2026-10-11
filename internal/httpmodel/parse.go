package httpmodel

import (
	"fmt"
	"strings"
)

const formContentType = "application/x-www-form-urlencoded"

// New builds the parsed view and the status for a received request.
//
// New never fails. Content it cannot parse stays available in Received and
// is reported in Status, so the parts that can be inspected still are.
func New(rec Received) *Request {
	r := &Request{Received: rec}

	r.Parsed.Path, r.Parsed.RawQuery, _ = strings.Cut(rec.Target, "?")

	var malformed int
	r.Parsed.Query, malformed = parseParams(r.Parsed.RawQuery, OriginQuery)
	r.noteMalformed("query", malformed)

	r.parseBody()
	return r
}

func (r *Request) parseBody() {
	if len(r.Received.Body) == 0 {
		r.Status.Body = BodyEmpty
		return
	}

	types := r.HeaderValues("Content-Type")
	if len(types) == 0 {
		r.Status.Body = BodyNotInspected
		r.Status.BodyReason = "the request has a body but no Content-Type header"
		return
	}
	if len(types) > 1 {
		r.Status.Issues = append(r.Status.Issues, Issue{
			Part:    "headers",
			Message: fmt.Sprintf("%d Content-Type headers; the first one is used", len(types)),
		})
	}

	if mediaType(types[0]) != formContentType {
		r.Status.Body = BodyNotInspected
		r.Status.BodyReason = fmt.Sprintf("content type %q is not parsed", mediaType(types[0]))
		return
	}

	var malformed int
	r.Parsed.Form, malformed = parseParams(string(r.Received.Body), OriginBody)
	r.noteMalformed("body", malformed)
	r.Status.Body = BodyInspected
}

func (r *Request) noteMalformed(part string, count int) {
	if count == 0 {
		return
	}
	r.Status.Issues = append(r.Status.Issues, Issue{
		Part:    part,
		Message: fmt.Sprintf("%d names or values contain malformed percent-encoding; it was kept as written", count),
	})
}

// mediaType returns the type part of a Content-Type value in lower case:
// "Application/JSON; charset=utf-8" gives "application/json".
func mediaType(contentType string) string {
	t, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(t))
}

// parseParams splits "a=1&b=2" into pairs and decodes each name and value.
// malformed counts the names and values with a broken percent sequence.
func parseParams(raw string, origin Origin) (params []Param, malformed int) {
	if raw == "" {
		return nil, 0
	}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, badName := decodeComponent(rawName)
		value, badValue := decodeComponent(rawValue)
		if badName {
			malformed++
		}
		if badValue {
			malformed++
		}
		params = append(params, Param{
			Name:     name,
			Value:    value,
			RawName:  rawName,
			RawValue: rawValue,
			Origin:   origin,
		})
	}
	return params, malformed
}

// decodeComponent decodes percent-encoding once and reads "+" as a space.
// A "%" that is not followed by two hex digits is kept as written and
// reported through malformed, so nothing an attacker sent is dropped.
func decodeComponent(s string) (decoded string, malformed bool) {
	if !strings.ContainsAny(s, "%+") {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case c == '%':
			malformed = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), malformed
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
