package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// collection identifies where a variable's values come from.
type collection int

const (
	colArgs collection = iota + 1
	colRequestHeaders
	colRequestURIRaw
	colTX
)

// target is one compiled entry of a rule's variable list.
type target struct {
	col      collection
	name     string // the collection name, such as "ARGS"
	selector string // "" for the whole collection
	count    bool   // "&": the number of values, not the values
}

// notProvided are variables the engine knows but cannot fill yet. A rule
// that names one still runs on its other variables, and the gap is reported
// in the rule's status.
var notProvided = map[string]bool{
	"FILES": true, // multipart bodies are not parsed
	"XML":   true, // XML bodies are not parsed
}

// errNotProvided marks a variable from notProvided.
var errNotProvided = errors.New("variable is not provided")

func compileTarget(v seclang.Variable) (target, error) {
	t := target{name: v.Collection, selector: v.Selector, count: v.Count}
	switch v.Collection {
	case "ARGS":
		t.col = colArgs
	case "REQUEST_HEADERS":
		t.col = colRequestHeaders
	case "TX":
		t.col = colTX
		if v.Selector == "" {
			return target{}, errors.New("variable TX without a variable name is not supported")
		}
	case "REQUEST_URI_RAW":
		t.col = colRequestURIRaw
		if v.Selector != "" {
			return target{}, fmt.Errorf("variable %s takes no selector", v.Collection)
		}
	default:
		if notProvided[v.Collection] {
			return target{}, errNotProvided
		}
		return target{}, fmt.Errorf("variable %s is not supported", v.Collection)
	}
	if v.Regex {
		return target{}, fmt.Errorf("variable %s: regular expression selectors are not supported", v)
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
func (tx *transaction) collect(r *rule) []namedValue {
	var out []namedValue
	for _, t := range r.targets {
		values := tx.valuesOf(t)
		if t.count {
			name := "&" + t.name
			if t.selector != "" {
				name += ":" + t.selector
			}
			out = append(out, namedValue{name: name, value: strconv.Itoa(len(values))})
			continue
		}
		for _, v := range values {
			if !excluded(r.excludes, t, v.key) {
				out = append(out, namedValue{name: t.name + v.suffix(), value: v.value})
			}
		}
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

// valuesOf returns the entries a target selects. Selectors are compared
// without regard to case, as ModSecurity does.
func (tx *transaction) valuesOf(t target) []keyValue {
	var out []keyValue
	add := func(key, value string) {
		if t.selector == "" || strings.EqualFold(t.selector, key) {
			out = append(out, keyValue{key: key, value: value})
		}
	}
	switch t.col {
	case colArgs:
		for _, p := range tx.req.Parsed.Query {
			add(p.Name, p.Value)
		}
		for _, p := range tx.req.Parsed.Form {
			add(p.Name, p.Value)
		}
	case colRequestHeaders:
		for _, h := range tx.req.Received.Headers {
			add(h.Name, h.Value)
		}
	case colRequestURIRaw:
		out = append(out, keyValue{value: tx.req.Received.Target})
	case colTX:
		if value, ok := tx.vars[strings.ToLower(t.selector)]; ok {
			out = append(out, keyValue{key: t.selector, value: value})
		}
	}
	return out
}

// excluded reports whether a "!" entry of the rule removes this value.
func excluded(excludes []target, t target, key string) bool {
	for _, ex := range excludes {
		if ex.col == t.col && (ex.selector == "" || strings.EqualFold(ex.selector, key)) {
			return true
		}
	}
	return false
}
