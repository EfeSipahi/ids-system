package profile

import (
	"fmt"
	"mime"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// NoApplication is the name records and the dashboard use for requests
// that belong to no application.
const NoApplication = "none"

// The kinds of finding. Location says where, in CRS's names: ARGS_GET:id,
// ARGS_POST:json.user.name, REQUEST_COOKIES:sid, REQUEST_HEADERS:X-Key or
// REQUEST_FILENAME.
const (
	KindUnknownEndpoint = "unknown_endpoint" // no endpoint fits the path
	KindMethod          = "method"           // endpoints fit the path, but not with this method
	KindContentType     = "content_type"     // a body of a type the endpoint does not take
	KindUnknownParam    = "unknown_param"    // a parameter the endpoint does not name
	KindMissing         = "missing"          // a required parameter, cookie or header is not there
	KindRepeated        = "repeated"         // sent more than once without "repeat"
	KindWrongType       = "wrong_type"       // not an integer, a number or a boolean
	KindTooLong         = "too_long"
	KindTooShort        = "too_short"
	KindOutOfRange      = "out_of_range" // below min or above max
	KindPattern         = "pattern"      // does not match the pattern
	KindNotInList       = "not_in_list"  // not one of the enum values
	KindNoProfile       = "no_profile"   // with require_profile: no application has the host
)

// Finding is one thing the profile does not allow. Message never holds a
// value of the request (M11); Location names where, and the value can be
// seen in the request itself where the records keep it.
type Finding struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

// Result is what the profile layer found in one request.
type Result struct {
	// App is the request's application, or nil.
	App *App
	// Findings is empty when the request is what the profile allows.
	Findings []Finding
	// BodyChecked is false when the body could not be read to its end. Its
	// parameters were then not judged, so nothing is reported as missing
	// or unknown because of a body that wasn't read (M05).
	BodyChecked bool

	// SecretPath holds, for a path with secret {name} parts, which parts
	// of the path (counted from 0 after the first /) are secret, and
	// SecretValues their text, for masking (F8).
	SecretPath   []int
	SecretValues []string
}

// Alert reports whether the profile's findings make the request an alert:
// there are findings and the profile's mode is "alert" (F6).
func (r Result) Alert() bool {
	return r.App != nil && r.App.Profile.Mode == ModeAlert && len(r.Findings) > 0
}

// Check checks a request against the profile of app, or, when app is nil,
// only whether the set requires a profile.
func (s *Set) Check(req *httpmodel.Request, app *App) Result {
	if app == nil {
		res := Result{BodyChecked: req.Status.Body.Complete()}
		if s.require {
			res.Findings = []Finding{{Kind: KindNoProfile, Location: "REQUEST_HEADERS:Host", Message: "no application is configured for this host and path"}}
		}
		return res
	}
	return app.Check(req)
}

// Check checks a request against the application's profile.
func (a *App) Check(req *httpmodel.Request) Result {
	c := checker{p: a.Profile, req: req, res: Result{App: a, BodyChecked: req.Status.Body.Complete()}, seen: map[[2]string]bool{}}
	c.check()
	return c.res
}

type checker struct {
	p    *Profile
	req  *httpmodel.Request
	res  Result
	seen map[[2]string]bool // kind and location: one finding of each
}

func (c *checker) add(kind, location, message string) {
	key := [2]string{kind, location}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.res.Findings = append(c.res.Findings, Finding{Kind: kind, Location: location, Message: message})
}

func (c *checker) check() {
	path := c.req.Parsed.DecodedPath
	method := c.req.Received.Method
	c.checkHeaders(path, method)
	c.checkCookies()

	// The application resolves "." and ".." parts, so "/img/../admin.php"
	// is /admin.php there although it looks like a path below /img/. The
	// profile does not resolve them; such a path fits no endpoint.
	if hasDotPart(path) {
		c.add(KindUnknownEndpoint, "REQUEST_FILENAME", "the path has . or .. parts, which fit no endpoint")
		return
	}
	ep, values, allowed := c.p.find(method, path)
	if ep == nil {
		if len(allowed) > 0 {
			c.add(KindMethod, "REQUEST_METHOD", "this method is not allowed for the path; allowed: "+strings.Join(allowed, ", "))
		} else {
			c.add(KindUnknownEndpoint, "REQUEST_FILENAME", "no endpoint of the profile fits this path")
		}
		return
	}
	c.checkPath(ep, values)
	c.checkContentType(ep)
	c.checkParams(ep)
}

func hasDotPart(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

// find returns the endpoint for a request: the most specific one whose
// path fits and that takes the method, with the text of its {name} parts.
// When the path fits only endpoints of other methods, they are returned.
func (p *Profile) find(method, path string) (*endpoint, map[string]string, []string) {
	var best *endpoint
	var bestValues map[string]string
	var allowed []string
	for _, ep := range p.endpoints {
		values, ok := ep.pattern.match(path)
		if !ok {
			continue
		}
		if !slices.Contains(ep.methods, method) {
			for _, m := range ep.methods {
				if !slices.Contains(allowed, m) {
					allowed = append(allowed, m)
				}
			}
			continue
		}
		if best == nil || moreSpecific(ep, best) {
			best, bestValues = ep, values
		}
	}
	return best, bestValues, allowed
}

func moreSpecific(a, b *endpoint) bool {
	ak, al := a.pattern.rank()
	bk, bl := b.pattern.rank()
	if ak != bk {
		return ak > bk
	}
	if al != bl {
		return al > bl
	}
	return a.index < b.index
}

func (c *checker) checkPath(ep *endpoint, values map[string]string) {
	for _, name := range sortedKeys(ep.pathParams) {
		prm := ep.pathParams[name]
		c.checkValue(prm, "REQUEST_FILENAME:{"+name+"}", values[name])
	}
	// The secret parts are found in the path as received, part by part.
	// When the decoding changed the number of parts, the whole path is
	// treated as secret, which is the safe side.
	raw := strings.Split(strings.TrimPrefix(c.req.Parsed.Path, "/"), "/")
	same := len(raw) == len(strings.Split(strings.TrimPrefix(c.req.Parsed.DecodedPath, "/"), "/"))
	for i, pt := range ep.pattern.parts {
		if pt.name == "" || ep.pathParams[pt.name] == nil || !ep.pathParams[pt.name].secret {
			continue
		}
		if !same {
			c.res.SecretPath = []int{-1}
			c.res.SecretValues = append(c.res.SecretValues, values[pt.name])
			continue
		}
		c.res.SecretPath = append(c.res.SecretPath, i)
		c.res.SecretValues = append(c.res.SecretValues, values[pt.name], raw[i])
	}
}

func (c *checker) checkContentType(ep *endpoint) {
	if len(ep.contentTypes) == 0 || c.req.BodyLength() == 0 {
		return
	}
	ct := ""
	if v := c.req.HeaderValues("Content-Type"); len(v) > 0 {
		ct, _, _ = mime.ParseMediaType(v[0])
		if ct == "" {
			ct = strings.ToLower(strings.TrimSpace(strings.SplitN(v[0], ";", 2)[0]))
		}
	}
	if !slices.Contains(ep.contentTypes, ct) {
		c.add(KindContentType, "REQUEST_HEADERS:Content-Type", "the body's type is not one of: "+strings.Join(ep.contentTypes, ", "))
	}
}

// arg is one parameter of the request, with where it came from.
type arg struct {
	name     string // for JSON without the "json." in front
	value    string
	in       string // InQuery, InBody or InJSON
	location string
}

// requestArgs returns the parameters of a request: those of the query, and
// those of the body when it was read to its end.
func requestArgs(req *httpmodel.Request, bodyChecked bool) []arg {
	var out []arg
	for _, p := range req.Parsed.Query {
		out = append(out, arg{name: p.Name, value: p.Value, in: InQuery, location: "ARGS_GET:" + p.Name})
	}
	if !bodyChecked {
		return out
	}
	isJSON := req.Status.BodyFormat == "json"
	for _, p := range req.Parsed.BodyArgs {
		if isJSON {
			// A list that is not empty also gives its length under its
			// own name (see httpmodel's parseJSON). That entry is not a
			// field of the document, so it is not checked.
			if isListLength(p.Name, req.Parsed.BodyArgs) {
				continue
			}
			out = append(out, arg{name: strings.TrimPrefix(p.Name, "json."), value: p.Value, in: InJSON, location: "ARGS_POST:" + p.Name})
			continue
		}
		out = append(out, arg{name: p.Name, value: p.Value, in: InBody, location: "ARGS_POST:" + p.Name})
	}
	return out
}

func isListLength(name string, all []httpmodel.Param) bool {
	prefix := name + "."
	for _, p := range all {
		if strings.HasPrefix(p.Name, prefix) {
			return true
		}
	}
	return false
}

// takes reports whether the declared parameter is the request's arg.
func (prm *param) takes(a arg) bool {
	switch prm.in {
	case InArgs:
		return (a.in == InQuery || a.in == InBody) && a.name == prm.name
	case InQuery, InBody:
		return a.in == prm.in && a.name == prm.name
	case InJSON:
		if a.in != InJSON {
			return false
		}
		parts := strings.Split(a.name, ".")
		if len(parts) != len(prm.jsonPath) {
			return false
		}
		for i, want := range prm.jsonPath {
			if want == "*" {
				if _, err := strconv.Atoi(parts[i]); err != nil {
					return false
				}
			} else if parts[i] != want {
				return false
			}
		}
		return true
	}
	return false
}

func (c *checker) checkParams(ep *endpoint) {
	got := make([][]arg, len(ep.params))
	for _, a := range requestArgs(c.req, c.res.BodyChecked) {
		known := false
		for i, prm := range ep.params {
			if prm.takes(a) {
				got[i] = append(got[i], a)
				known = true
				break
			}
		}
		if !known && !ep.otherParams {
			c.add(KindUnknownParam, a.location, "the endpoint has no such parameter in the profile")
		}
	}
	for i, prm := range ep.params {
		values := got[i]
		if len(values) == 0 {
			// A parameter that may come in the body is not reported
			// missing when the body could not be read.
			if prm.required && (prm.in == InQuery || c.res.BodyChecked) {
				c.add(KindMissing, prm.location(), "required, but not sent")
			}
			continue
		}
		if len(values) > 1 && !prm.repeat && !(prm.in == InJSON && slices.Contains(prm.jsonPath, "*")) {
			c.add(KindRepeated, values[0].location, fmt.Sprintf("sent %d times; the profile allows it once", len(values)))
		}
		for _, a := range values {
			c.checkValue(prm, a.location, a.value)
		}
	}
}

func (prm *param) location() string {
	switch prm.in {
	case InQuery:
		return "ARGS_GET:" + prm.name
	case InBody:
		return "ARGS_POST:" + prm.name
	case InJSON:
		return "ARGS_POST:json." + prm.name
	}
	return "ARGS:" + prm.name
}

func (c *checker) checkCookies() {
	for _, prm := range c.p.cookies {
		var values []string
		for _, ck := range c.req.Parsed.Cookies {
			if ck.Name == prm.name {
				values = append(values, ck.Value)
			}
		}
		c.checkNamed(prm, "REQUEST_COOKIES:"+prm.name, values)
	}
}

func (c *checker) checkHeaders(path, method string) {
	for _, h := range c.p.headers {
		if len(h.methods) > 0 && !slices.Contains(h.methods, method) {
			continue
		}
		if len(h.paths) > 0 && !slices.ContainsFunc(h.paths, func(p pattern) bool { _, ok := p.match(path); return ok }) {
			continue
		}
		c.checkNamed(&h.param, "REQUEST_HEADERS:"+h.name, c.req.HeaderValues(h.name))
	}
}

// checkNamed checks the values of a cookie or a header.
func (c *checker) checkNamed(prm *param, location string, values []string) {
	switch {
	case len(values) == 0:
		if prm.required {
			c.add(KindMissing, location, "required, but not sent")
		}
		return
	case len(values) > 1 && !prm.repeat:
		c.add(KindRepeated, location, fmt.Sprintf("sent %d times; the profile allows it once", len(values)))
	}
	for _, v := range values {
		c.checkValue(prm, location, v)
	}
}

var numberText = regexp.MustCompile(`\A-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?\z`)

// parseInteger reads a whole number written in digits with an optional
// "-", as a profile's type integer takes it.
func parseInteger(v string) (int64, bool) {
	i, err := strconv.ParseInt(v, 10, 64)
	return i, err == nil && !strings.HasPrefix(v, "+")
}

// checkValue checks one value against a parameter's type and limits.
func (c *checker) checkValue(prm *param, location, v string) {
	switch prm.kind {
	case TypeInteger, TypeNumber:
		var n float64
		if prm.kind == TypeInteger {
			i, ok := parseInteger(v)
			if !ok {
				c.add(KindWrongType, location, "not an integer")
				return
			}
			n = float64(i)
		} else {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || !numberText.MatchString(v) {
				c.add(KindWrongType, location, "not a number")
				return
			}
			n = f
		}
		if prm.min != nil && n < *prm.min {
			c.add(KindOutOfRange, location, "below the minimum "+strconv.FormatFloat(*prm.min, 'f', -1, 64))
		}
		if prm.max != nil && n > *prm.max {
			c.add(KindOutOfRange, location, "above the maximum "+strconv.FormatFloat(*prm.max, 'f', -1, 64))
		}
	case TypeBoolean:
		if v != "true" && v != "false" && v != "1" && v != "0" {
			c.add(KindWrongType, location, "not true, false, 1 or 0")
		}
	case TypeEnum:
		if !slices.Contains(prm.values, v) {
			c.add(KindNotInList, location, "not one of the allowed values")
		}
	default:
		if prm.maxLen != nil && len(v) > *prm.maxLen {
			c.add(KindTooLong, location, fmt.Sprintf("longer than %d bytes", *prm.maxLen))
		}
		if prm.minLen != nil && len(v) < *prm.minLen {
			c.add(KindTooShort, location, fmt.Sprintf("shorter than %d bytes", *prm.minLen))
		}
		if prm.re != nil && !prm.re.MatchString(v) {
			c.add(KindPattern, location, "does not match the pattern")
		}
	}
}

// SecretArgs returns the profile's secret parameters as CRS names them in
// ARGS: the name, or "json." and the dotted path for a JSON field, where *
// stands for a list index (F8). SecretHeaders returns its secret headers.
// Cookies are not listed, because records never hold a cookie's value.
func (p *Profile) SecretArgs() []string {
	var names []string
	for _, ep := range p.endpoints {
		for _, prm := range ep.params {
			name := prm.name
			if prm.in == InJSON {
				name = "json." + name
			}
			if prm.secret && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// SecretHeaders returns the names of the profile's secret headers.
func (p *Profile) SecretHeaders() []string {
	var names []string
	for _, h := range p.headers {
		if h.secret && !slices.Contains(names, h.name) {
			names = append(names, h.name)
		}
	}
	return names
}
