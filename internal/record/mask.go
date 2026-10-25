package record

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// Masked stands in for a value that is not written because it is a secret.
const Masked = "[masked]"

// builtinSecretNames are parts of parameter names whose values are secrets:
// passwords, session identifiers, tokens and card data, the kinds of data
// the OWASP Logging Cheat Sheet says not to log. A name matches when it
// contains one of them, in any case, so "user_password" and "PHPSESSID"
// match. Masking a harmless value by mistake only loses a detail; writing
// a password down cannot be undone.
var builtinSecretNames = []string{
	"pass", "pwd", "secret", "token", "session", "sessid", "auth",
	"csrf", "xsrf", "apikey", "api_key", "api-key", "access_key",
	"private_key", "card", "cvv",
}

// secretHeaders are the headers whose values are never written, not even
// with full_requests: they carry passwords and session cookies.
var secretHeaders = []string{"authorization", "cookie", "proxy-authorization"}

func isSecretHeader(name string) bool {
	return slices.Contains(secretHeaders, strings.ToLower(name))
}

// Maximum lengths of what is written. A longer text is cut and ends in
// "…". They keep a record small and limit how much of a payload is kept.
const (
	maxMatched     = 200
	maxMessage     = 512
	maxPath        = 2048
	maxQuery       = 2048
	maxUserAgent   = 512
	maxReferer     = 1024
	maxHost        = 255
	maxContentType = 256
	maxHeaderName  = 128
	maxHeaders     = 64
	maxCookies     = 32
	maxHeaderValue = 8192
	maxBody        = 64 << 10
)

// maxProfileFindings is the most profile findings a record keeps. A request
// with a thousand unknown parameters gets the first ones and a count of the
// rest.
const maxProfileFindings = 64

// minSecretLength is the shortest secret that is removed from any text,
// such as a User-Agent or a matched value. A shorter value, such as "1",
// would mask unrelated text wherever it appears. It is still masked in its
// own place, and in a whole text (see wholeLocation), which holds every
// parameter: a three-digit card code in the matched query string, say.
const minSecretLength = 4

// masker decides what counts as a secret.
type masker struct {
	names []string // parts of secret parameter names, lower case
	// args and headers come from an application's profile (F8): whole
	// parameter names as ARGS has them, where a * part is a list index,
	// and header names, all in lower case.
	args    []string
	headers []string
	key     []byte // the key of the cookie hashes
}

func newMasker(extra []string, key []byte) masker {
	m := masker{key: key}
	for _, name := range append(slices.Clone(builtinSecretNames), extra...) {
		m.names = append(m.names, strings.ToLower(strings.TrimSpace(name)))
	}
	return m
}

// forProfile returns the masker for the requests of an application: this
// one, plus the parameters and headers its profile marks as secret.
func (m masker) forProfile(p *profile.Profile) masker {
	m.args, m.headers = nil, nil
	for _, name := range p.SecretArgs() {
		m.args = append(m.args, strings.ToLower(name))
	}
	for _, name := range p.SecretHeaders() {
		m.headers = append(m.headers, strings.ToLower(name))
	}
	return m
}

// secretName reports whether a parameter with this name holds a secret.
func (m masker) secretName(name string) bool {
	lower := strings.ToLower(name)
	for _, part := range m.names {
		if strings.Contains(lower, part) {
			return true
		}
	}
	for _, arg := range m.args {
		if argMatches(arg, lower) {
			return true
		}
	}
	return false
}

// argMatches reports whether an ARGS name is a profile's secret parameter,
// such as "json.items.0.cvc" for "json.items.*.cvc".
func argMatches(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	want, got := strings.Split(pattern, "."), strings.Split(name, ".")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] == "*" {
			if _, err := strconv.Atoi(got[i]); err != nil {
				return false
			}
		} else if want[i] != got[i] {
			return false
		}
	}
	return true
}

// secretHeader reports whether a header's value is never written.
func (m masker) secretHeader(name string) bool {
	return isSecretHeader(name) || slices.Contains(m.headers, strings.ToLower(name))
}

// secretLocation reports whether a match location, such as "ARGS:password"
// or "REQUEST_COOKIES:sid", is a place that holds a secret.
func (m masker) secretLocation(location string) bool {
	collection, key, _ := strings.Cut(location, ":")
	switch strings.ToUpper(collection) {
	case "REQUEST_COOKIES":
		return true
	case "REQUEST_HEADERS":
		return m.secretHeader(key)
	case "ARGS", "ARGS_GET", "ARGS_POST":
		return m.secretName(key)
	}
	return false
}

// cookieHash returns a short keyed hash of a cookie value. The same value
// gives the same hash, so the requests of one session can be linked, but
// without the key the value cannot be found from the hash, not even by
// trying likely values.
func (m masker) cookieHash(value string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

// secrets are the secret values of one request, to be removed from every
// text that is written.
type secrets struct {
	replacer *strings.Replacer // values of at least minSecretLength
	whole    *strings.Replacer // every value, also shorter ones
}

// collect finds the secret values of a request: the values of parameters
// with a secret name, also in the query of a Referer, every cookie value,
// the values of the secret headers, and more, such as a path's secret
// parts. Each is kept as received, decoded, and in lower case, the forms a
// rule's transformations most often produce.
func (m masker) collect(req *httpmodel.Request, more ...string) secrets {
	var values, short []string
	add := func(vs ...string) {
		for _, v := range vs {
			switch {
			case len(v) >= minSecretLength:
				values = append(values, v, strings.ToLower(v))
			case v != "":
				short = append(short, v, strings.ToLower(v))
			}
		}
	}
	for _, p := range req.Args() {
		if m.secretName(p.Name) {
			add(p.RawValue, p.Value)
		}
	}
	for _, c := range req.Parsed.Cookies {
		add(c.Value)
		if decoded, err := url.QueryUnescape(c.Value); err == nil {
			add(decoded)
		}
	}
	// A Referer is the URL of another page, whose query can hold its own
	// tokens, such as a password reset link.
	for _, referer := range req.HeaderValues("Referer") {
		_, query, _ := strings.Cut(referer, "?")
		query, _, _ = strings.Cut(query, "#")
		for _, pair := range strings.Split(query, "&") {
			rawName, rawValue, _ := strings.Cut(pair, "=")
			name, err := url.QueryUnescape(rawName)
			if err != nil {
				name = rawName
			}
			if m.secretName(name) {
				add(rawValue)
				if value, err := url.QueryUnescape(rawValue); err == nil {
					add(value)
				}
			}
		}
	}
	add(more...)
	for _, h := range req.Received.Headers {
		if m.secretHeader(h.Name) {
			add(h.Value)
			// "Basic dXNlcjpwYXNz": the credentials alone.
			if _, credentials, ok := strings.Cut(h.Value, " "); ok {
				add(strings.TrimSpace(credentials))
			}
		}
	}
	s := secrets{replacer: replacer(values)}
	s.whole = s.replacer
	if len(short) > 0 {
		s.whole = replacer(append(values, short...))
	}
	return s
}

// replacer replaces each value by Masked, or is nil when there is none.
func replacer(values []string) *strings.Replacer {
	if len(values) == 0 {
		return nil
	}
	// Longest first, so that a secret that contains another is replaced
	// as a whole. The replacer makes one pass, so "[masked]" is never
	// itself searched again.
	values = slices.Clone(values)
	slices.SortFunc(values, func(a, b string) int { return len(b) - len(a) })
	values = slices.Compact(values)
	pairs := make([]string, 0, 2*len(values))
	for _, v := range values {
		pairs = append(pairs, v, Masked)
	}
	return strings.NewReplacer(pairs...)
}

// clean replaces every secret value of at least minSecretLength in text.
func (s secrets) clean(text string) string {
	if s.replacer == nil {
		return text
	}
	return s.replacer.Replace(text)
}

// cleanWhole replaces every secret value in a whole text, the short ones
// too.
func (s secrets) cleanWhole(text string) string {
	if s.whole == nil {
		return text
	}
	return s.whole.Replace(text)
}

// wholeLocation reports whether a match location holds a whole text with
// all the parameters, such as QUERY_STRING or REQUEST_BODY, rather than one
// value.
func wholeLocation(location string) bool {
	collection, _, _ := strings.Cut(location, ":")
	switch strings.ToUpper(collection) {
	case "QUERY_STRING", "REQUEST_BODY", "REQUEST_LINE", "REQUEST_URI", "REQUEST_URI_RAW", "FULL_REQUEST", "XML":
		return true
	}
	return false
}

// text prepares one piece of request content for a record: secrets
// removed, cut to max bytes, and control characters and invalid bytes
// written as escapes.
func (s secrets) text(t string, max int) string {
	return result.Printable(cut(s.clean(t), max))
}

// wholeText is text for a whole text (see wholeLocation).
func (s secrets) wholeText(t string, max int) string {
	return result.Printable(cut(s.cleanWhole(t), max))
}

// cut returns s whole when it is at most max bytes long. Otherwise it
// returns the first max bytes, without splitting a character, and "…".
func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && end > max-utf8.UTFMax && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}

// maskPath replaces the secret parts of a raw path, counted from 0 after
// the first "/", with Masked. A part -1 masks the whole path.
func maskPath(path string, parts []int) string {
	if len(parts) == 0 {
		return path
	}
	if parts[0] < 0 {
		return Masked
	}
	prefix, rest := "", path
	if strings.HasPrefix(path, "/") {
		prefix, rest = "/", path[1:]
	}
	segments := strings.Split(rest, "/")
	for _, i := range parts {
		if i < len(segments) {
			segments[i] = Masked
		}
	}
	return prefix + strings.Join(segments, "/")
}

// maskQuery replaces the value of every parameter with a secret name in a
// raw query string, such as "user=ali&password=x" → "user=ali&password=
// [masked]". Everything else is kept as received.
func (m masker) maskQuery(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := strings.Split(raw, "&")
	for i, pair := range pairs {
		rawName, _, hasValue := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil {
			name = rawName
		}
		if hasValue && m.secretName(name) {
			pairs[i] = rawName + "=" + Masked
		}
	}
	return strings.Join(pairs, "&")
}

// maskJSON returns a JSON body with the value of every secret field, named
// as ARGS names it ("json.user.password"), replaced by Masked. A JSON
// string may spell a value with escapes, such as \u0070 for "p", so the
// body as received can hold a secret that the clean-up pass, which knows
// the decoded value, would not find there. A body with a secret field is
// therefore written again, compact; one without is returned as received.
// When the body stops being valid JSON after a secret field, the rest is
// left out.
func (m masker) maskJSON(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	writeString := func(s string) {
		enc.Encode(s)
		out.Truncate(out.Len() - 1) // the newline Encode adds
	}
	found := false

	// skip reads the rest of a value whose first token has been read.
	skip := func(tok json.Token) error {
		if _, ok := tok.(json.Delim); !ok {
			return nil
		}
		for depth := 1; depth > 0; {
			t, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := t.(json.Delim); ok {
				if d == '{' || d == '[' {
					depth++
				} else {
					depth--
				}
			}
		}
		return nil
	}
	var walk func(tok json.Token, path string, depth int) error
	walk = func(tok json.Token, path string, depth int) error {
		if depth > 0 && m.secretName(path) {
			found = true
			writeString(Masked)
			return skip(tok)
		}
		switch v := tok.(type) {
		case string:
			writeString(v)
		case json.Number:
			out.WriteString(v.String())
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case nil:
			out.WriteString("null")
		case json.Delim:
			if depth >= maxJSONDepth {
				return errors.New("too deep")
			}
			out.WriteByte(byte(v))
			for index := 0; dec.More(); index++ {
				if index > 0 {
					out.WriteByte(',')
				}
				child := path + "." + strconv.Itoa(index)
				if v == '{' {
					key, err := dec.Token()
					if err != nil {
						return err
					}
					child = path + "." + key.(string)
					writeString(key.(string))
					out.WriteByte(':')
				}
				next, err := dec.Token()
				if err != nil {
					return err
				}
				if err := walk(next, child, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			out.WriteByte(byte(end.(json.Delim)))
		}
		return nil
	}

	tok, err := dec.Token()
	if err == nil {
		err = walk(tok, "json", 0)
	}
	switch {
	case !found:
		return string(body)
	case err != nil:
		return out.String() + "…"
	}
	return out.String()
}

// maxJSONDepth is the deepest JSON nesting that maskJSON reads, as the
// request parser.
const maxJSONDepth = 64

// maskURL masks the secret parameters of the query of a URL, such as a
// Referer header.
func (m masker) maskURL(u string) string {
	base, query, ok := strings.Cut(u, "?")
	if !ok {
		return u
	}
	return base + "?" + m.maskQuery(query)
}
