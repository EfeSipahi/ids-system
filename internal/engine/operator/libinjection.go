package operator

import "github.com/corazawaf/libinjection-go"

// detectSQLi and detectXSS are the operators @detectSQLi and @detectXSS.
// They do not match a pattern. They hand the value to libinjection, a
// library that splits it into tokens the way a database or a browser would
// and recognises the token sequences of an injection.
//
// The library is github.com/corazawaf/libinjection-go, a Go port of the C
// library that ModSecurity uses.
//
// @detectSQLi captures the "fingerprint", a short code for the token
// sequence that was recognised, such as "s&1" for a string, a logical
// operator and a number.
type detectSQLi struct{}

func (detectSQLi) Match(value string, _ func(string) string) Result {
	found, fingerprint := libinjection.IsSQLi(value)
	if !found {
		return Result{}
	}
	return Result{Matched: true, Captures: []string{fingerprint}}
}

type detectXSS struct{}

func (detectXSS) Match(value string, _ func(string) string) Result {
	return Result{Matched: libinjection.IsXSS(value)}
}
