package profile

import (
	"errors"
	"fmt"
	"strings"
)

// pattern is an endpoint path (F4d):
//
//	/tienda1/publico/anadir.jsp   exactly this path
//	/item/{id}                    one path part of any text, named id
//	/tienda1/imagenes/*           everything below /tienda1/imagenes/
//
// Paths are compared with the request's path decoded once, as the
// application sees it. "." and ".." are not resolved: a path that uses them
// matches no endpoint and is reported as unknown, which is the safe side,
// because a profile's exceptions never depend on the path.
type pattern struct {
	text  string
	parts []part
	rest  bool // the path ends with "/*"
}

// part is one path part: literal text, or a {name} that takes any text.
type part struct {
	literal string
	name    string
}

func parsePattern(s string) (pattern, error) {
	if !strings.HasPrefix(s, "/") {
		return pattern{}, errors.New("a path starts with /")
	}
	p := pattern{text: s}
	parts := strings.Split(s[1:], "/")
	if parts[len(parts)-1] == "*" {
		p.rest = true
		parts = parts[:len(parts)-1]
	}
	seen := map[string]bool{}
	for _, text := range parts {
		switch {
		case text == "*" || strings.Contains(text, "*"):
			return pattern{}, errors.New("* may only be the whole last part, as in /images/*")
		case strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}"):
			name := text[1 : len(text)-1]
			if !isName(name) {
				return pattern{}, fmt.Errorf("{%s} is not a name of letters, digits and _", name)
			}
			if seen[name] {
				return pattern{}, fmt.Errorf("{%s} is used twice", name)
			}
			seen[name] = true
			p.parts = append(p.parts, part{name: name})
		case strings.ContainsAny(text, "{}"):
			return pattern{}, errors.New("{name} must be a whole path part, as in /item/{id}")
		default:
			p.parts = append(p.parts, part{literal: text})
		}
	}
	return p, nil
}

// match reports whether path fits the pattern, with the text of each
// {name} part.
func (p pattern) match(path string) (map[string]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	if p.rest {
		if len(parts) <= len(p.parts) {
			return nil, false
		}
		parts = parts[:len(p.parts)]
	} else if len(parts) != len(p.parts) {
		return nil, false
	}
	var values map[string]string
	for i, pt := range p.parts {
		if pt.name == "" {
			if parts[i] != pt.literal {
				return nil, false
			}
			continue
		}
		if values == nil {
			values = map[string]string{}
		}
		values[pt.name] = parts[i]
	}
	return values, true
}

// rank orders patterns from the most to the least specific: an exact path
// first, then one with {name} parts, then one ending in *; within each,
// the one with more literal parts first.
func (p pattern) rank() (kind, literals int) {
	for _, pt := range p.parts {
		if pt.name == "" {
			literals++
		}
	}
	switch {
	case p.rest:
		return 0, literals
	case len(p.paramNames()) > 0:
		return 1, literals
	}
	return 2, literals
}

// key is the pattern with its {name} parts made equal, so that two
// patterns that match the same paths have the same key.
func (p pattern) key() string {
	var b strings.Builder
	for _, pt := range p.parts {
		b.WriteByte('/')
		if pt.name != "" {
			b.WriteString("{}")
		} else {
			b.WriteString(pt.literal)
		}
	}
	if p.rest {
		b.WriteString("/*")
	}
	return b.String()
}

func (p pattern) paramNames() []string {
	var names []string
	for _, pt := range p.parts {
		if pt.name != "" {
			names = append(names, pt.name)
		}
	}
	return names
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
