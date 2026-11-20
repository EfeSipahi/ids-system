package offline

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// Raw HTTP text is how a person writes a request in the dashboard's test
// tab (decision S3, docs/development-plan-test-tab.md): the request line,
// the headers, an empty line, and the body.
//
//	POST /login HTTP/1.1
//	Host: shop.example.com
//	Content-Type: application/x-www-form-urlencoded
//
//	user=admin&pwd=1' OR '1'='1
//
// A browser's text box gives line ends as "\n" and turns "\r\n" into "\n",
// so the text carries the body's line ends apart: bodyCRLF true means each
// "\n" of the body stands for "\r\n", as a multipart body needs. The line
// ends of the request line and the headers do not reach the engine, so
// both "\r\n" and "\n" are accepted there.

// MaxRawLine is the longest request line or header line ParseRaw reads,
// in bytes. The whole text is limited by its caller.
const MaxRawLine = 1 << 20

// ParseRaw reads a request written as raw HTTP text. The request line is
// the method, the target and the version, separated by single spaces; a
// line without a version is HTTP/0.9. Empty lines before it are skipped.
// Each header is "Name: value" on its own line; the spaces and tabs around
// the value are not part of it, as HTTP servers read it (RFC 9112, section
// 5). The headers end at the first empty line, and everything after it is
// the body. Text without an empty line has no body. Nothing is added or
// corrected: a wrong Content-Length stays wrong, as a client may send it.
func ParseRaw(text string, bodyCRLF bool) (httpmodel.Received, error) {
	var rec httpmodel.Received
	rest := text
	lineNo := 0
	// next returns the next line without its line end, and whether the
	// text had one more line.
	next := func() (string, bool) {
		if rest == "" {
			return "", false
		}
		lineNo++
		line := rest
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		return strings.TrimSuffix(line, "\r"), true
	}

	line, ok := next()
	for ok && line == "" {
		line, ok = next()
	}
	if !ok {
		return rec, errors.New("the request is empty: write a request line such as GET / HTTP/1.1")
	}
	if len(line) > MaxRawLine {
		return rec, fmt.Errorf("line %d is longer than %d bytes", lineNo, MaxRawLine)
	}
	parts := strings.Split(line, " ")
	if (len(parts) != 2 && len(parts) != 3) || slices.Contains(parts, "") {
		return rec, fmt.Errorf("line %d: a request line is a method, a target and a version, separated by single spaces, such as GET /search?q=1 HTTP/1.1", lineNo)
	}
	rec.Method, rec.Target = parts[0], parts[1]
	if len(parts) == 3 {
		rec.Version = parts[2]
	}

	for {
		line, ok = next()
		if !ok || line == "" {
			break
		}
		if len(line) > MaxRawLine {
			return rec, fmt.Errorf("line %d is longer than %d bytes", lineNo, MaxRawLine)
		}
		colon := strings.IndexByte(line, ':')
		switch {
		case colon < 0:
			return rec, fmt.Errorf("line %d: a header is a name, a colon and a value, such as Accept: */*; an empty line ends the headers", lineNo)
		case colon == 0:
			return rec, fmt.Errorf("line %d: the header has no name before its colon", lineNo)
		case strings.ContainsAny(line[:colon], " \t"):
			return rec, fmt.Errorf("line %d: a header name can't contain spaces or tabs", lineNo)
		}
		rec.Headers = append(rec.Headers, httpmodel.Header{
			Name:  line[:colon],
			Value: strings.Trim(line[colon+1:], " \t"),
		})
	}

	if ok && rest != "" {
		body := rest
		if bodyCRLF {
			body = toCRLF(body)
		}
		rec.Body = []byte(body)
	}
	return rec, nil
}

// Raw writes the request line, the headers and the body of rec as raw
// HTTP text, the way ParseRaw reads it back, with "\n" line ends. bodyCRLF
// says whether the body's line ends are "\r\n". ok is false when the text
// can't hold the request exactly:
//   - a part of the request line is empty or holds a space or a line
//     break;
//   - a header name is empty or holds a colon, a space, a tab or a line
//     break; a header value holds a line break, or starts or ends with a
//     space or a tab;
//   - the body is not UTF-8 text, or mixes "\r\n" with a lone "\n" or
//     "\r".
//
// The client's and the server's addresses are not part of the text.
func Raw(rec httpmodel.Received) (text string, bodyCRLF bool, ok bool) {
	var b strings.Builder
	line := []string{rec.Method, rec.Target}
	if rec.Version != "" {
		line = append(line, rec.Version)
	}
	for _, p := range line {
		if p == "" || strings.ContainsAny(p, " \r\n") {
			return "", false, false
		}
	}
	b.WriteString(strings.Join(line, " "))
	b.WriteByte('\n')
	for _, h := range rec.Headers {
		if h.Name == "" || strings.ContainsAny(h.Name, ": \t\r\n") || strings.ContainsAny(h.Value, "\r\n") ||
			strings.TrimLeft(h.Value, " \t") != h.Value || strings.TrimRight(h.Value, " \t") != h.Value {
			return "", false, false
		}
		b.WriteString(h.Name + ": " + h.Value + "\n")
	}
	body := string(rec.Body)
	if !utf8.ValidString(body) {
		return "", false, false
	}
	if strings.Contains(body, "\r") {
		plain := strings.ReplaceAll(body, "\r\n", "\n")
		if strings.Contains(plain, "\r") || toCRLF(plain) != body {
			return "", false, false
		}
		body, bodyCRLF = plain, true
	}
	if body != "" {
		b.WriteByte('\n')
		b.WriteString(body)
	}
	return b.String(), bodyCRLF, true
}

// toCRLF turns every "\n" that has no "\r" before it into "\r\n".
func toCRLF(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + strings.Count(s, "\n"))
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			b.WriteByte('\r')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
