package profile

import (
	"mime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// Survey lists the endpoints and parameters of a set of requests, as a
// start for writing a profile by hand (F4g). It keeps no value of a
// request: for each parameter only where it came from, how often it was
// sent, its greatest length and whether every value was an integer.
//
// JSON fields are named as in a profile, with * for a list index:
// items.*.id. Paths are kept as received, decoded once. A path with a token in it,
// such as /reset/8f2c..., is listed as it is; such a survey is for one's
// own data, like -show-values.
type Survey struct {
	endpoints map[[2]string]*SurveyEndpoint
	cookies   map[string]*SurveyParam
}

// SurveyEndpoint is one method and path, with what its requests sent.
type SurveyEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Count  int    `json:"count"`
	// BodyNotRead counts the requests whose body was not read to its end;
	// their body parameters are not counted.
	BodyNotRead int `json:"body_not_read,omitempty"`
	// ContentTypes are the media types of the bodies, without parameters.
	ContentTypes []string      `json:"content_types,omitempty"`
	Params       []SurveyParam `json:"params"`

	params map[[2]string]*SurveyParam
}

// SurveyParam is one parameter or cookie.
type SurveyParam struct {
	Name string `json:"name"`
	// In is query, body or json, as in a profile, or cookie.
	In string `json:"in"`
	// Count is the number of requests that sent it.
	Count int `json:"count"`
	// Repeated is true when a request sent it more than once.
	Repeated bool `json:"repeated,omitempty"`
	// MaxLength is the greatest length in bytes after decoding.
	MaxLength  int  `json:"max_length"`
	AllInteger bool `json:"all_integer"`
}

// NewSurvey returns an empty survey.
func NewSurvey() *Survey {
	return &Survey{endpoints: map[[2]string]*SurveyEndpoint{}, cookies: map[string]*SurveyParam{}}
}

// Add counts one request.
func (s *Survey) Add(req *httpmodel.Request) {
	key := [2]string{req.Received.Method, req.Parsed.DecodedPath}
	ep := s.endpoints[key]
	if ep == nil {
		ep = &SurveyEndpoint{Method: key[0], Path: key[1], params: map[[2]string]*SurveyParam{}}
		s.endpoints[key] = ep
	}
	ep.Count++
	bodyRead := req.Status.Body.Complete()
	if !bodyRead {
		ep.BodyNotRead++
	}
	if len(req.Received.Body) > 0 {
		if v := req.HeaderValues("Content-Type"); len(v) > 0 {
			if ct, _, err := mime.ParseMediaType(v[0]); err == nil && !slices.Contains(ep.ContentTypes, ct) {
				ep.ContentTypes = append(ep.ContentTypes, ct)
			}
		}
	}

	sent := map[[2]string]int{}
	for _, a := range requestArgs(req, bodyRead) {
		name := a.name
		if a.in == InJSON {
			name = starIndexes(name)
		}
		k := [2]string{a.in, name}
		p := ep.params[k]
		if p == nil {
			p = &SurveyParam{Name: name, In: a.in, AllInteger: true}
			ep.params[k] = p
		}
		sent[k]++
		p.see(a.value)
	}
	for k, n := range sent {
		ep.params[k].Count++
		if n > 1 {
			ep.params[k].Repeated = true
		}
	}

	seen := map[string]int{}
	for _, c := range req.Parsed.Cookies {
		p := s.cookies[c.Name]
		if p == nil {
			p = &SurveyParam{Name: c.Name, In: "cookie", AllInteger: true}
			s.cookies[c.Name] = p
		}
		seen[c.Name]++
		p.see(c.Value)
	}
	for name, n := range seen {
		s.cookies[name].Count++
		if n > 1 {
			s.cookies[name].Repeated = true
		}
	}
}

func (p *SurveyParam) see(v string) {
	p.MaxLength = max(p.MaxLength, len(v))
	if _, ok := parseInteger(v); !ok {
		p.AllInteger = false
	}
}

// starIndexes writes the list indexes of a dotted JSON path as *, as a
// profile names them. An object key made of digits looks the same and is
// written as * too.
func starIndexes(name string) string {
	parts := strings.Split(name, ".")
	for i, part := range parts {
		if _, err := strconv.Atoi(part); err == nil {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, ".")
}

// Endpoints returns the endpoints sorted by path and method, each with its
// parameters sorted by place and name.
func (s *Survey) Endpoints() []SurveyEndpoint {
	out := make([]SurveyEndpoint, 0, len(s.endpoints))
	for _, ep := range s.endpoints {
		e := *ep
		e.Params = make([]SurveyParam, 0, len(ep.params))
		for _, p := range ep.params {
			e.Params = append(e.Params, *p)
		}
		sort.Slice(e.Params, func(i, j int) bool {
			a, b := e.Params[i], e.Params[j]
			if a.In != b.In {
				return a.In > b.In // query, json, body
			}
			return a.Name < b.Name
		})
		sort.Strings(e.ContentTypes)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Cookies returns the cookies sorted by name.
func (s *Survey) Cookies() []SurveyParam {
	out := make([]SurveyParam, 0, len(s.cookies))
	for _, p := range s.cookies {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
