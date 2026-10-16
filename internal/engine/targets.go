package engine

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// collection identifies where a variable's values come from.
type collection int

const (
	colArgs collection = iota + 1
	colArgsNames
	colArgsGet
	colArgsGetNames
	colArgsPost
	colArgsPostNames
	colRequestHeaders
	colRequestHeadersNames
	colRequestMethod
	colRequestProtocol
	colRequestLine
	colRequestURI
	colQueryString
	colRequestBody
	colMatchedVar
	colMatchedVarName
	colRemoteAddr
	colArgsCombinedSize
	colFilesCombinedSize
	colRequestBodyLength
	colReqbodyProcessor
	colMultipartPartHeaders
	colRequestCookies
	colRequestCookiesNames
	colRequestURIRaw
	colRequestFilename
	colRequestBasename
	colFiles
	colFilesNames
	colXML
	colMatchedVars
	colTX
)

// collections maps a variable name to its source. single is true for a
// variable that has exactly one value and takes no selector.
var collections = map[string]struct {
	col    collection
	single bool
}{
	"ARGS":                   {col: colArgs},
	"ARGS_NAMES":             {col: colArgsNames},
	"ARGS_GET":               {col: colArgsGet},
	"ARGS_GET_NAMES":         {col: colArgsGetNames},
	"ARGS_POST":              {col: colArgsPost},
	"ARGS_POST_NAMES":        {col: colArgsPostNames},
	"REQUEST_HEADERS":        {col: colRequestHeaders},
	"REQUEST_HEADERS_NAMES":  {col: colRequestHeadersNames},
	"REQUEST_METHOD":         {col: colRequestMethod, single: true},
	"REQUEST_PROTOCOL":       {col: colRequestProtocol, single: true},
	"REQUEST_LINE":           {col: colRequestLine, single: true},
	"REQUEST_URI":            {col: colRequestURI, single: true},
	"QUERY_STRING":           {col: colQueryString, single: true},
	"REQUEST_BODY":           {col: colRequestBody, single: true},
	"MATCHED_VAR":            {col: colMatchedVar, single: true},
	"MATCHED_VAR_NAME":       {col: colMatchedVarName, single: true},
	"REMOTE_ADDR":            {col: colRemoteAddr, single: true},
	"ARGS_COMBINED_SIZE":     {col: colArgsCombinedSize, single: true},
	"FILES_COMBINED_SIZE":    {col: colFilesCombinedSize, single: true},
	"REQUEST_BODY_LENGTH":    {col: colRequestBodyLength, single: true},
	"REQBODY_PROCESSOR":      {col: colReqbodyProcessor, single: true},
	"MULTIPART_PART_HEADERS": {col: colMultipartPartHeaders},
	"REQUEST_COOKIES":        {col: colRequestCookies},
	"REQUEST_COOKIES_NAMES":  {col: colRequestCookiesNames},
	"REQUEST_URI_RAW":        {col: colRequestURIRaw, single: true},
	"REQUEST_FILENAME":       {col: colRequestFilename, single: true},
	"REQUEST_BASENAME":       {col: colRequestBasename, single: true},
	"FILES":                  {col: colFiles},
	"FILES_NAMES":            {col: colFilesNames},
	"XML":                    {col: colXML},
	"MATCHED_VARS":           {col: colMatchedVars},
	"TX":                     {col: colTX},
}

// target is one compiled entry of a rule's variable list.
type target struct {
	col      collection
	name     string // the collection name, such as "ARGS"
	selector string // "" for the whole collection
	// re is set when the selector is a regular expression, written as
	// /.../ in the rule. It then selects every key the pattern matches.
	re    *regexp.Regexp
	count bool // "&": the number of values, not the values
}

// matches reports whether the target selects the entry with this key.
// Names are compared without regard to case, as ModSecurity does.
func (t target) matches(key string) bool {
	switch {
	case t.re != nil:
		return t.re.MatchString(key)
	case t.selector == "":
		return true
	}
	return strings.EqualFold(t.selector, key)
}

// The two XML selectors that are understood. CRS uses no others in the
// rules of Phase 1.
const (
	xmlAllText       = "/*"   // the text between tags
	xmlAllAttributes = "//@*" // the values of attributes
)

func compileTarget(v seclang.Variable) (target, error) {
	info, ok := collections[v.Collection]
	if !ok {
		return target{}, fmt.Errorf("variable %s is not supported", v.Collection)
	}
	t := target{col: info.col, name: v.Collection, selector: v.Selector, count: v.Count}
	switch {
	case info.single && v.Selector != "":
		return target{}, fmt.Errorf("variable %s takes no selector", v.Collection)
	case info.col == colTX && v.Selector == "":
		return target{}, errors.New("variable TX without a variable name is not supported")
	case info.col == colXML && v.Selector != xmlAllText && v.Selector != xmlAllAttributes:
		return target{}, fmt.Errorf("variable %s: only XML:%s and XML:%s are supported", v, xmlAllText, xmlAllAttributes)
	}
	if v.Regex {
		// ModSecurity compiles these selectors without regard to case
		// and lets "." match a newline.
		re, err := regexp.Compile("(?is)" + v.Selector)
		if err != nil {
			return target{}, fmt.Errorf("variable %s: %w", v, err)
		}
		t.re = re
	}
	return t, nil
}

// namedValue is one value a rule tests, with the name reported for it,
// such as "ARGS:q" or "REQUEST_HEADERS:User-Agent".
type namedValue struct {
	name  string
	value string
}

// collect returns the values of a rule's variable list for this request, in
// the order the variables are written.
//
// The list it returns is only valid until the next call: its memory is
// reused.
func (tx *transaction) collect(r, first *rule) []namedValue {
	out := tx.collected[:0]
	for _, t := range r.targets {
		if tx.removedForRequest(first, t) {
			continue
		}
		values := tx.namedValuesOf(t)
		if t.count {
			name := "&" + t.name
			if t.selector != "" {
				name += ":" + t.selector
			}
			out = append(out, namedValue{name: name, value: strconv.Itoa(len(values))})
			continue
		}
		for _, v := range values {
			if len(r.excludes) == 0 || !excluded(r.excludes, t, v.key) {
				out = append(out, v.namedValue)
			}
		}
	}
	tx.collected = out
	return out
}

// keyedValue is a value with its key and its full name.
type keyedValue struct {
	key string
	namedValue
}

// targetKey identifies what a target selects, so that two rules naming
// the same thing share the values.
type targetKey struct {
	col      collection
	selector string
	re       *regexp.Regexp
}

// namedValuesOf returns the entries a target selects, with their names.
// The entries of the request itself are built once per request; the ones
// that change while the rules run (TX, the matched values, the chosen body
// reader) are built every time.
func (tx *transaction) namedValuesOf(t target) []keyedValue {
	key := targetKey{col: t.col, selector: strings.ToLower(t.selector), re: t.re}
	if cached, ok := tx.valueCache[key]; ok {
		return cached
	}
	values := tx.valuesOf(t)
	out := make([]keyedValue, len(values))
	for i, v := range values {
		out[i] = keyedValue{key: v.key, namedValue: namedValue{name: t.name + v.suffix(), value: v.value}}
	}
	switch t.col {
	case colTX, colMatchedVars, colMatchedVar, colMatchedVarName, colReqbodyProcessor:
	default:
		if tx.valueCache == nil {
			tx.valueCache = map[targetKey][]keyedValue{}
		}
		tx.valueCache[key] = out
	}
	return out
}

// keyValue is one entry of a collection before it is named.
type keyValue struct {
	key   string // "" for a variable that is not a collection
	value string
}

func (kv keyValue) suffix() string {
	if kv.key == "" {
		return ""
	}
	return ":" + kv.key
}

// valuesOf returns the entries a target selects.
func (tx *transaction) valuesOf(t target) []keyValue {
	var out []keyValue
	add := func(key, value string) {
		if t.matches(key) {
			out = append(out, keyValue{key: key, value: value})
		}
	}
	req := tx.req
	switch t.col {
	case colArgs:
		for _, p := range req.Parsed.Query {
			add(p.Name, p.Value)
		}
		for _, p := range req.Parsed.BodyArgs {
			add(p.Name, p.Value)
		}
	case colArgsNames:
		// The value of a "names" variable is the name itself.
		for _, p := range req.Parsed.Query {
			add(p.Name, p.Name)
		}
		for _, p := range req.Parsed.BodyArgs {
			add(p.Name, p.Name)
		}
	case colArgsGet:
		for _, p := range req.Parsed.Query {
			add(p.Name, p.Value)
		}
	case colArgsGetNames:
		for _, p := range req.Parsed.Query {
			add(p.Name, p.Name)
		}
	case colArgsPost:
		for _, p := range req.Parsed.BodyArgs {
			add(p.Name, p.Value)
		}
	case colArgsPostNames:
		for _, p := range req.Parsed.BodyArgs {
			add(p.Name, p.Name)
		}
	case colRequestHeaders:
		for _, h := range req.Received.Headers {
			add(h.Name, h.Value)
		}
	case colRequestHeadersNames:
		for _, h := range req.Received.Headers {
			add(h.Name, h.Name)
		}
	case colRequestMethod:
		out = append(out, keyValue{value: req.Received.Method})
	case colRequestProtocol:
		// A request line without a version is HTTP/0.9.
		version := req.Received.Version
		if version == "" {
			version = "HTTP/0.9"
		}
		out = append(out, keyValue{value: version})
	case colRequestLine:
		// The first line of the request as it was sent.
		line := req.Received.Method + " " + req.Received.Target
		if req.Received.Version != "" {
			line += " " + req.Received.Version
		}
		out = append(out, keyValue{value: line})
	case colRequestURI:
		// Path and query string as sent, without the scheme and host
		// that a request to a proxy puts in front.
		uri := req.Parsed.Path
		if target, _, _ := strings.Cut(req.Received.Target, "#"); strings.Contains(target, "?") {
			uri += "?" + req.Parsed.RawQuery
		}
		out = append(out, keyValue{value: uri})
	case colQueryString:
		out = append(out, keyValue{value: req.Parsed.RawQuery})
	case colRequestBody:
		if body := rawBody(req); body != "" {
			out = append(out, keyValue{value: body})
		}
	case colMatchedVar:
		out = append(out, keyValue{value: tx.matchedVar})
	case colMatchedVarName:
		out = append(out, keyValue{value: tx.matchedVarName})
	case colRemoteAddr:
		out = append(out, keyValue{value: req.Received.RemoteAddr})
	case colArgsCombinedSize:
		// The lengths of all names and values of ARGS, added up.
		size := 0
		for _, p := range req.Args() {
			size += len(p.Name) + len(p.Value)
		}
		out = append(out, keyValue{value: strconv.Itoa(size)})
	case colFilesCombinedSize:
		// The sizes of the uploaded files, added up. Coraza also counts
		// the text fields of the form; ModSecurity, which this follows,
		// counts files only.
		size := 0
		for _, f := range req.Parsed.Files {
			size += f.Size
		}
		out = append(out, keyValue{value: strconv.Itoa(size)})
	case colRequestBodyLength:
		out = append(out, keyValue{value: strconv.Itoa(len(req.Received.Body))})
	case colMultipartPartHeaders:
		// The key is the name of the part, the value one header line.
		for _, h := range req.Parsed.PartHeaders {
			add(h.Part, h.Line)
		}
	case colReqbodyProcessor:
		format := req.DeclaredBodyFormat()
		if tx.bodyFormat != "" {
			format = tx.bodyFormat
		}
		out = append(out, keyValue{value: bodyProcessors[format]})
	case colRequestCookies:
		for _, c := range req.Parsed.Cookies {
			add(c.Name, c.Value)
		}
	case colRequestCookiesNames:
		for _, c := range req.Parsed.Cookies {
			add(c.Name, c.Name)
		}
	case colRequestURIRaw:
		out = append(out, keyValue{value: req.Received.Target})
	case colRequestFilename:
		// The path with its percent-encoding resolved, as Coraza and
		// ModSecurity v3 provide it. ModSecurity v2 gives the path as
		// sent.
		out = append(out, keyValue{value: req.Parsed.DecodedPath})
	case colRequestBasename:
		out = append(out, keyValue{value: basename(req.Parsed.DecodedPath)})
	case colFiles:
		for _, f := range req.Parsed.Files {
			add(f.Field, f.Name)
		}
	case colFilesNames:
		for _, f := range req.Parsed.Files {
			add(f.Field, f.Field)
		}
	case colXML:
		values := req.Parsed.XMLText
		if t.selector == xmlAllAttributes {
			values = req.Parsed.XMLAttributes
		}
		for _, v := range values {
			out = append(out, keyValue{key: t.selector, value: v})
		}
	case colMatchedVars:
		// What the earlier rules of this chain matched. The key is the
		// full name of the variable that matched, such as "ARGS:q".
		for _, m := range tx.matchedVars {
			add(m.name, m.value)
		}
	case colTX:
		if t.re == nil {
			if value, ok := tx.vars[strings.ToLower(t.selector)]; ok {
				out = append(out, keyValue{key: t.selector, value: value})
			}
			break
		}
		// A pattern selects every TX variable whose name it matches.
		// They are taken in the order of their names, so that a request
		// always gives the same result.
		var names []string
		for name := range tx.vars {
			if t.re.MatchString(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			out = append(out, keyValue{key: name, value: tx.vars[name]})
		}
	}
	return out
}

// bodyProcessors gives the name ModSecurity uses for each body reader, as
// REQBODY_PROCESSOR shows it. Like ModSecurity, the engine knows it from the
// Content-Type header before the body is read, and it is set even when the
// request has no body. A type without a reader gives "".
var bodyProcessors = map[string]string{
	"form":      "URLENCODED",
	"multipart": "MULTIPART",
	"json":      "JSON",
	"xml":       "XML",
}

// bodyFormats is bodyProcessors the other way round.
var bodyFormats = map[string]string{
	"URLENCODED": "form",
	"MULTIPART":  "multipart",
	"JSON":       "json",
	"XML":        "xml",
}

// rawBody returns the body as one text for the REQUEST_BODY variable, or ""
// when the variable has no value.
//
// ModSecurity fills REQUEST_BODY for a form body, and CRS rule 901340 asks
// for it whenever no body reader was chosen, which is the case for a body
// of a type the engine does not parse, such as text/plain. A JSON, XML or
// multipart body is not given as one text; the rules see its parts.
func rawBody(req *httpmodel.Request) string {
	switch req.Status.BodyFormat {
	case "", "form":
		return string(req.Received.Body)
	}
	return ""
}

// removedForRequest reports whether a ctl:ruleRemoveTargetByTag action that
// ran earlier in this request took the target away from this rule.
func (tx *transaction) removedForRequest(first *rule, t target) bool {
	for _, removal := range tx.removedTargets {
		if removal.target.col != t.col || !removal.target.matches(t.selector) {
			continue
		}
		for _, tag := range first.tags {
			if removal.tag.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

// basename returns what follows the last "/" of a path, and of that what
// follows the last "\".
func basename(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		path = path[i+1:]
	}
	return path
}

// excluded reports whether a "!" entry of the rule removes this value. An
// exclusion applies to the variable it names: !REQUEST_COOKIES:x leaves
// REQUEST_COOKIES_NAMES alone.
func excluded(excludes []target, t target, key string) bool {
	for _, ex := range excludes {
		if ex.col == t.col && ex.matches(key) {
			return true
		}
	}
	return false
}
