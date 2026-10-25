// Package profile reads hand-written application profiles and checks
// requests against them (A04; decisions F1–F11 of the main plan, section
// 11.25).
//
// A profile is a JSON file that describes one application:
//
//   - what its normal requests look like: endpoints, parameters, cookies
//     and headers, as an allow list (F4);
//   - which CRS checks are wrong for it: rule exceptions (F5), applied to
//     its requests only, on the one shared rule set;
//   - its paranoia level (F11) and whether its findings are alerts (F6).
//
// The format is described in docs/profile-format.md. Reading is strict: an
// unknown field, a type that does not exist or an exception that would
// switch detection off stops the start, with a message that says what to
// change (F7).
package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Modes of a profile (F6).
const (
	// ModeMonitor records the profile's findings; they are not alerts.
	ModeMonitor = "monitor"
	// ModeAlert makes a request with a profile finding an alert.
	ModeAlert = "alert"
)

// The places a parameter can come from (F4e).
const (
	InArgs  = "args"  // the query or a form body: the default
	InQuery = "query" // the query only
	InBody  = "body"  // a form body only, normal or multipart
	InJSON  = "json"  // a field of a JSON body, by its dotted path
)

// The value types (F4c).
const (
	TypeString  = "string"
	TypeInteger = "integer"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeEnum    = "enum"
)

// The JSON form of a profile file. Every struct is read with unknown fields
// refused, so a misspelled field is an error, not a silent default.
type fileJSON struct {
	Note          string           `json:"note"`
	Mode          string           `json:"mode"`
	ParanoiaLevel int              `json:"paranoia_level"`
	Endpoints     []endpointJSON   `json:"endpoints"`
	Cookies       map[string]value `json:"cookies"`
	Headers       []headerJSON     `json:"headers"`
	Exceptions    []Exception      `json:"exceptions"`
}

type endpointJSON struct {
	Note        string           `json:"note"`
	Method      string           `json:"method"`
	Methods     []string         `json:"methods"`
	Path        string           `json:"path"`
	ContentType []string         `json:"content_type"`
	OtherParams string           `json:"other_params"`
	Params      map[string]value `json:"params"`
	PathParams  map[string]value `json:"path_params"`
}

type headerJSON struct {
	Name    string   `json:"name"`
	Paths   []string `json:"paths"`
	Methods []string `json:"methods"`
	value
}

// value is what a parameter, a cookie, a path part or a header may be.
type value struct {
	Note      string   `json:"note"`
	In        string   `json:"in"`
	Type      string   `json:"type"`
	Required  bool     `json:"required"`
	Repeat    bool     `json:"repeat"`
	Secret    bool     `json:"secret"`
	MinLength *int     `json:"min_length"`
	MaxLength *int     `json:"max_length"`
	Min       *float64 `json:"min"`
	Max       *float64 `json:"max"`
	Pattern   string   `json:"pattern"`
	Values    []string `json:"values"`
}

// Exception is one rule exception of a profile (F5). It has exactly one
// kind: a CRS setting (Setting and Value), a rule that skips variables
// (Rule and Skip), or a rule that is off (Rule and Off). Reason is always
// required: the dashboard shows it next to the exception.
type Exception struct {
	Note    string   `json:"note,omitempty"`
	Setting string   `json:"setting,omitempty"`
	Value   *string  `json:"value,omitempty"`
	Rule    int      `json:"rule,omitempty"`
	Skip    []string `json:"skip,omitempty"`
	Off     bool     `json:"off,omitempty"`
	Reason  string   `json:"reason"`
}

// Profile is a profile file, read and checked.
type Profile struct {
	// Path is the file the profile was read from.
	Path string
	// Mode is ModeMonitor or ModeAlert.
	Mode string
	// ParanoiaLevel is the application's own level, or 0 for the level of
	// the configuration.
	ParanoiaLevel int
	// Exceptions are the rule exceptions as written. They are checked
	// against the rules by NewSet, which needs the loaded rule set.
	Exceptions []Exception

	endpoints []*endpoint
	cookies   []*param
	headers   []*headerRule
}

type endpoint struct {
	index        int // its place in the file, for error texts and order
	methods      []string
	pattern      pattern
	contentTypes []string
	otherParams  bool // other parameters are allowed
	params       []*param
	pathParams   map[string]*param
}

type headerRule struct {
	paths   []pattern // empty: every path
	methods []string  // empty: every method
	param
}

type param struct {
	name     string
	in       string
	jsonPath []string // the dotted path of a JSON field, split
	kind     string
	required bool
	repeat   bool
	secret   bool
	minLen   *int
	maxLen   *int
	min, max *float64
	re       *regexp.Regexp
	values   []string
}

// Load reads one profile file and checks everything that can be checked
// without the rules. The exceptions are checked by NewSet.
func Load(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f fileJSON
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: invalid profile: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: invalid profile: unexpected content after the profile", path)
	}
	p, err := build(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	return p, nil
}

func build(f fileJSON) (*Profile, error) {
	p := &Profile{Mode: f.Mode, ParanoiaLevel: f.ParanoiaLevel, Exceptions: f.Exceptions}
	switch p.Mode {
	case "":
		p.Mode = ModeMonitor
	case ModeMonitor, ModeAlert:
	default:
		return nil, fmt.Errorf("mode %q is not one of %s, %s", f.Mode, ModeMonitor, ModeAlert)
	}
	if p.ParanoiaLevel < 0 || p.ParanoiaLevel > 4 {
		return nil, fmt.Errorf("paranoia_level %d is not supported; it must be 1 to 4, or left out for the level of the configuration", p.ParanoiaLevel)
	}

	seen := map[string]int{}
	for i, e := range f.Endpoints {
		ep, err := buildEndpoint(i, e)
		if err != nil {
			return nil, fmt.Errorf("endpoints[%d]: %w", i, err)
		}
		for _, m := range ep.methods {
			key := m + " " + ep.pattern.key()
			if prev, dup := seen[key]; dup {
				return nil, fmt.Errorf("endpoints[%d]: %s %s is already endpoints[%d]", i, m, e.Path, prev)
			}
			seen[key] = i
		}
		p.endpoints = append(p.endpoints, ep)
	}

	for _, name := range sortedKeys(f.Cookies) {
		v := f.Cookies[name]
		if v.In != "" {
			return nil, fmt.Errorf("cookies.%s: a cookie has no \"in\"", name)
		}
		c, err := buildParam(name, v)
		if err != nil {
			return nil, fmt.Errorf("cookies.%s: %w", name, err)
		}
		p.cookies = append(p.cookies, c)
	}

	for i, h := range f.Headers {
		rule, err := buildHeader(h)
		if err != nil {
			return nil, fmt.Errorf("headers[%d]: %w", i, err)
		}
		p.headers = append(p.headers, rule)
	}

	for i, ex := range f.Exceptions {
		if err := checkExceptionForm(ex); err != nil {
			return nil, fmt.Errorf("exceptions[%d]: %w", i, err)
		}
	}
	return p, nil
}

func buildEndpoint(i int, e endpointJSON) (*endpoint, error) {
	ep := &endpoint{index: i}
	switch {
	case e.Method != "" && len(e.Methods) > 0:
		return nil, errors.New("give either method or methods, not both")
	case e.Method != "":
		ep.methods = []string{e.Method}
	case len(e.Methods) > 0:
		ep.methods = slices.Clone(e.Methods)
	default:
		return nil, errors.New("method is missing")
	}
	for _, m := range ep.methods {
		if !isMethod(m) {
			return nil, fmt.Errorf("method %q is not an HTTP method in upper case, such as GET", m)
		}
	}
	pat, err := parsePattern(e.Path)
	if err != nil {
		return nil, fmt.Errorf("path %q: %w", e.Path, err)
	}
	ep.pattern = pat

	for _, ct := range e.ContentType {
		if ct == "" || ct != strings.ToLower(ct) || strings.ContainsAny(ct, "; \t") {
			return nil, fmt.Errorf("content_type %q: write the media type in lower case without parameters, such as application/json", ct)
		}
	}
	ep.contentTypes = e.ContentType

	switch e.OtherParams {
	case "", "finding":
	case "allow":
		ep.otherParams = true
	default:
		return nil, fmt.Errorf("other_params %q is not one of finding, allow", e.OtherParams)
	}

	for _, name := range sortedKeys(e.Params) {
		prm, err := buildParam(name, e.Params[name])
		if err != nil {
			return nil, fmt.Errorf("params.%s: %w", name, err)
		}
		ep.params = append(ep.params, prm)
	}

	names := pat.paramNames()
	ep.pathParams = map[string]*param{}
	for _, name := range sortedKeys(e.PathParams) {
		if !slices.Contains(names, name) {
			return nil, fmt.Errorf("path_params.%s: the path has no {%s}", name, name)
		}
		v := e.PathParams[name]
		if v.In != "" || v.Required || v.Repeat {
			return nil, fmt.Errorf("path_params.%s: a path part has no in, required or repeat", name)
		}
		prm, err := buildParam(name, v)
		if err != nil {
			return nil, fmt.Errorf("path_params.%s: %w", name, err)
		}
		ep.pathParams[name] = prm
	}
	return ep, nil
}

func buildHeader(h headerJSON) (*headerRule, error) {
	if !isToken(h.Name) {
		return nil, fmt.Errorf("name %q is not a header name", h.Name)
	}
	if h.In != "" {
		return nil, errors.New("a header has no \"in\"")
	}
	rule := &headerRule{methods: h.Methods}
	for _, m := range h.Methods {
		if !isMethod(m) {
			return nil, fmt.Errorf("method %q is not an HTTP method in upper case, such as GET", m)
		}
	}
	for _, s := range h.Paths {
		pat, err := parsePattern(s)
		if err != nil {
			return nil, fmt.Errorf("paths: %q: %w", s, err)
		}
		if len(pat.paramNames()) > 0 {
			return nil, fmt.Errorf("paths: %q: use * for a part that changes; {name} is for endpoints", s)
		}
		rule.paths = append(rule.paths, pat)
	}
	prm, err := buildParam(h.Name, h.value)
	if err != nil {
		return nil, err
	}
	rule.param = *prm
	return rule, nil
}

func buildParam(name string, v value) (*param, error) {
	p := &param{name: name, in: v.In, kind: v.Type, required: v.Required, repeat: v.Repeat, secret: v.Secret,
		minLen: v.MinLength, maxLen: v.MaxLength, min: v.Min, max: v.Max, values: v.Values}
	if name == "" {
		return nil, errors.New("the name is empty")
	}
	switch p.in {
	case "":
		p.in = InArgs
	case InArgs, InQuery, InBody:
	case InJSON:
		p.jsonPath = strings.Split(name, ".")
		if slices.Contains(p.jsonPath, "") {
			return nil, fmt.Errorf("%q is not a dotted path such as user.name or items.*.id", name)
		}
	default:
		return nil, fmt.Errorf("in %q is not one of %s, %s, %s, %s", v.In, InArgs, InQuery, InBody, InJSON)
	}

	switch p.kind {
	case "":
		p.kind = TypeString
	case TypeString, TypeInteger, TypeNumber, TypeBoolean, TypeEnum:
	default:
		return nil, fmt.Errorf("type %q is not one of %s, %s, %s, %s, %s", v.Type, TypeString, TypeInteger, TypeNumber, TypeBoolean, TypeEnum)
	}
	isString, isNumber := p.kind == TypeString, p.kind == TypeInteger || p.kind == TypeNumber
	switch {
	case (p.minLen != nil || p.maxLen != nil) && !isString:
		return nil, errors.New("min_length and max_length are for type string")
	case (p.min != nil || p.max != nil) && !isNumber:
		return nil, errors.New("min and max are for types integer and number")
	case v.Pattern != "" && !isString:
		return nil, errors.New("pattern is for type string")
	case len(p.values) > 0 && p.kind != TypeEnum:
		return nil, errors.New("values are for type enum")
	case p.kind == TypeEnum && len(p.values) == 0:
		return nil, errors.New("type enum needs values")
	case p.minLen != nil && *p.minLen < 0, p.maxLen != nil && *p.maxLen < 0:
		return nil, errors.New("a length cannot be below 0")
	case p.minLen != nil && p.maxLen != nil && *p.minLen > *p.maxLen:
		return nil, errors.New("min_length is above max_length")
	case p.min != nil && p.max != nil && *p.min > *p.max:
		return nil, errors.New("min is above max")
	case p.min != nil && (math.IsNaN(*p.min) || math.IsInf(*p.min, 0)), p.max != nil && (math.IsNaN(*p.max) || math.IsInf(*p.max, 0)):
		return nil, errors.New("min and max must be finite numbers")
	}
	if v.Pattern != "" {
		// The pattern must match the whole value. Go's regular
		// expressions run in time linear in the value, so no pattern can
		// make a check slow.
		re, err := regexp.Compile(`\A(?:` + v.Pattern + `)\z`)
		if err != nil {
			return nil, fmt.Errorf("pattern: %v", err)
		}
		p.re = re
	}
	return p, nil
}

// checkExceptionForm checks the parts of an exception that do not need the
// rules: that it has one kind and a reason.
func checkExceptionForm(ex Exception) error {
	kinds := 0
	if ex.Setting != "" {
		kinds++
	}
	if len(ex.Skip) > 0 {
		kinds++
	}
	if ex.Off {
		kinds++
	}
	switch {
	case strings.TrimSpace(ex.Reason) == "":
		return errors.New("reason is missing; say why this exception is right for the application")
	case kinds == 0:
		return errors.New("give one of: setting with value, rule with skip, rule with off")
	case kinds > 1:
		return errors.New("give only one of: setting with value, rule with skip, rule with off; write two exceptions instead")
	case ex.Setting != "" && ex.Value == nil:
		return fmt.Errorf("setting %s has no value", ex.Setting)
	case ex.Setting != "" && ex.Rule != 0:
		return errors.New("a setting exception names no rule")
	case ex.Setting == "" && ex.Value != nil:
		return errors.New("value belongs to a setting")
	case ex.Setting == "" && ex.Rule <= 0:
		return errors.New("rule is missing")
	}
	return nil
}

func isMethod(s string) bool {
	return isToken(s) && s == strings.ToUpper(s)
}

// isToken reports whether s is an HTTP token, as header names and methods
// are (RFC 9110, section 5.6.2).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
