package operator

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// validateURLEncoding is @validateUrlEncoding: it matches a value whose
// percent-encoding is broken, that is, a "%" not followed by two hex digits.
// "a%41b" is fine; "a%4" and "a%zz" match. A value without "%" never
// matches.
//
// This is validate_url_encoding of ModSecurity v2 (apache2/re_operators.c);
// Coraza's operator gives the same results.
type validateURLEncoding struct{}

func (validateURLEncoding) Match(value string, _ func(string) string) Result {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isHexDigit(value[i+1]) || !isHexDigit(value[i+2]) {
			return Result{Matched: true}
		}
		i += 2
	}
	return Result{}
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// validateUTF8 is @validateUtf8Encoding: it matches a value that is not
// valid UTF-8. That covers a missing or wrong continuation byte, an
// overlong form such as 0xc0 0xaf for "/", a surrogate (U+D800 to U+DFFF),
// and anything above U+10FFFF.
//
// This follows Coraza, which uses Go's own check. ModSecurity v2 accepts one
// more kind of value: the four-byte forms starting with 0xf4 0x90 to 0xf4
// 0xbf, which stand for numbers above U+10FFFF and are not UTF-8 (RFC 3629).
type validateUTF8 struct{}

func (validateUTF8) Match(value string, _ func(string) string) Result {
	return Result{Matched: !utf8.ValidString(value)}
}

// ipMatch is @ipMatch: it matches a value that is an IP address inside one
// of the listed addresses or networks.
//
//	@ipMatch 127.0.0.1,::1,10.0.0.0/8
//
// Entries are separated by commas; spaces around them are ignored. A value
// that is not an IP address never matches. An entry that is neither an
// address nor a network stops the rules from loading, so that a mistyped
// exception is not silently dropped.
type ipMatch struct {
	prefixes []netip.Prefix
}

func newIPMatch(argument string) (Operator, error) {
	if hasMacro(argument) {
		return nil, errors.New("an argument containing a macro is not supported")
	}
	var o ipMatch
	for _, entry := range strings.Split(argument, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address or network", entry)
			}
			o.prefixes = append(o.prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or network", entry)
		}
		o.prefixes = append(o.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(o.prefixes) == 0 {
		return nil, errors.New("no address is given")
	}
	return o, nil
}

func (o ipMatch) Match(value string, _ func(string) string) Result {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return Result{}
	}
	addr = addr.Unmap() // "::ffff:127.0.0.1" is 127.0.0.1
	for _, p := range o.prefixes {
		if p.Contains(addr) {
			return Result{Matched: true}
		}
	}
	return Result{}
}
