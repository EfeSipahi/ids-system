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
	return build(rec, "")
}

// WithBodyFormat returns a new request with the same received content, whose
// body is read with the given reader ("form", "multipart", "json" or
// "xml") whatever the Content-Type says. The request itself is not changed.
//
// It is for the rule ctl:requestBodyProcessor, with which CRS chooses the
// reader for some content types. An unknown format reads nothing.
func (r *Request) WithBodyFormat(format string) *Request {
	return build(r.Received, format)
}

func build(rec Received, forced string) *Request {
	r := &Request{Received: rec}

	// A fragment ("#...") is not part of the request for the server; it
	// cuts it off before reading path and query. It stays in Target.
	target, _, _ := strings.Cut(rec.Target, "#")
	r.Parsed.Path, r.Parsed.RawQuery, _ = strings.Cut(target, "?")
	r.Parsed.Path = withoutOrigin(r.Parsed.Path)
	var badPath bool
	r.Parsed.DecodedPath, badPath = decodePercent(r.Parsed.Path, false)
	if badPath {
		r.Status.Issues = append(r.Status.Issues, Issue{
			Part:    "path",
			Message: "the path contains malformed percent-encoding; it was kept as written",
		})
	}
	for _, header := range r.HeaderValues("Cookie") {
		r.Parsed.Cookies = append(r.Parsed.Cookies, parseCookies(header)...)
	}

	var malformed int
	r.Parsed.Query, malformed = parseParams(r.Parsed.RawQuery, OriginQuery)
	r.noteMalformed("query", malformed)

	r.parseBody(forced)
	return r
}

// DefaultBodyLimit is the largest body that is parsed. A larger body is
// kept as received and reported as not inspected.
const DefaultBodyLimit = 1 << 20

func (r *Request) parseBody(forced string) {
	body := r.Received.Body
	if len(body) == 0 {
		r.Status.Body = BodyEmpty
		return
	}

	types := r.HeaderValues("Content-Type")
	if len(types) == 0 && forced == "" {
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

	contentType := ""
	if len(types) > 0 {
		contentType = types[0]
	}
	media := mediaType(contentType)
	r.Status.BodyFormat = bodyFormat(media)
	if forced != "" {
		r.Status.BodyFormat = forced
	}
	switch r.Status.BodyFormat {
	case "form", "multipart", "json", "xml":
	default:
		r.Status.BodyFormat = ""
	}
	if r.Status.BodyFormat == "" {
		r.Status.Body = BodyNotInspected
		r.Status.BodyReason = fmt.Sprintf("content type %q is not parsed", media)
		return
	}
	if len(body) > DefaultBodyLimit {
		r.Status.Body = BodyNotInspected
		r.Status.BodyReason = fmt.Sprintf("the body has %d bytes, more than the limit of %d", len(body), DefaultBodyLimit)
		return
	}

	// Each parser returns an error when it had to stop early. What it
	// read before that stays in the parsed view.
	var err error
	switch r.Status.BodyFormat {
	case "form":
		var malformed int
		r.Parsed.BodyArgs, malformed = parseParams(string(body), OriginBody)
		r.noteMalformed("body", malformed)
	case "json":
		r.Parsed.BodyArgs, err = parseJSON(body)
	case "multipart":
		r.Parsed.BodyArgs, r.Parsed.Files, err = parseMultipart(body, contentType)
	case "xml":
		r.Parsed.XMLText, r.Parsed.XMLAttributes, err = parseXML(body)
	}
	if err != nil {
		r.Status.Body = BodyPartlyInspected
		r.Status.BodyReason = fmt.Sprintf("the %s body could not be read to its end: %v", r.Status.BodyFormat, err)
		return
	}
	r.Status.Body = BodyInspected
}

// DeclaredBodyFormat returns the body format that the first Content-Type
// header names, whether or not the request has a body: "form",
// "multipart", "json", "xml", or "" when there is no header or no parser
// for its type. ModSecurity and Coraza choose their body processor the same
// way, from the headers alone.
func (r *Request) DeclaredBodyFormat() string {
	types := r.HeaderValues("Content-Type")
	if len(types) == 0 {
		return ""
	}
	return bodyFormat(mediaType(types[0]))
}

// bodyFormat chooses a parser from the media type, or returns "" when there
// is none. Form and multipart are recognised by the start of the type, as
// ModSecurity and Coraza do: a type such as "multipart/form-dataX" still
// gets the multipart reader. JSON and XML are recognised as the two rules
// of the recommended ModSecurity and Coraza configuration do it (rules
// 200000 and 200001 of modsecurity.conf-recommended).
//
// Other JSON types, such as application/ld+json, are left to the CRS rules
// 901360 and 901370, which choose the JSON reader with
// ctl:requestBodyProcessor and also add the type to the allowed ones.
func bodyFormat(media string) string {
	switch {
	case strings.HasPrefix(media, formContentType):
		return "form"
	case strings.HasPrefix(media, "multipart/form-data"):
		return "multipart"
	case strings.HasPrefix(media, "application/json"):
		return "json"
	case strings.HasPrefix(media, "application/xml"),
		strings.HasPrefix(media, "application/soap+xml"),
		strings.HasPrefix(media, "text/xml"):
		return "xml"
	}
	return ""
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
	return decodePercent(s, true)
}

// decodePercent resolves %XX sequences once. With plusIsSpace set, a "+"
// becomes a space.
func decodePercent(s string, plusIsSpace bool) (decoded string, malformed bool) {
	if !strings.ContainsAny(s, "%+") {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+' && plusIsSpace:
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

// withoutOrigin removes "scheme://host" from the front of a path, for a
// target written as a full URL.
func withoutOrigin(path string) string {
	for _, scheme := range []string{"http://", "https://"} {
		if len(path) >= len(scheme) && strings.EqualFold(path[:len(scheme)], scheme) {
			rest := path[len(scheme):]
			if slash := strings.IndexByte(rest, '/'); slash >= 0 {
				return rest[slash:]
			}
			return "/"
		}
	}
	return path
}

// parseCookies splits a Cookie header value into its pairs, the way
// ModSecurity does for version 0 cookies: pairs are separated by ";", white
// space before a name is dropped, the name ends at the first "=", and a
// pair without a name is ignored. A name without "=" has an empty value.
func parseCookies(header string) []Cookie {
	var cookies []Cookie
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimLeft(pair, " \t\n\v\f\r")
		name, value, _ := strings.Cut(pair, "=")
		if name == "" {
			continue
		}
		cookies = append(cookies, Cookie{Name: name, Value: value})
	}
	return cookies
}
