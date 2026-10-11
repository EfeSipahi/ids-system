package seclang

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// logicalLine is one directive's full text after continuation lines have
// been joined. line is the number of its first physical line.
type logicalLine struct {
	text string
	line int
}

// readLogicalLines joins lines that end with a backslash, then drops blank
// lines and comments. Joining happens first, so a comment that ends with a
// backslash also swallows the next line, as it does in ModSecurity.
func readLogicalLines(r io.Reader) ([]logicalLine, error) {
	br := bufio.NewReader(r)
	var (
		lines      []logicalLine
		buf        strings.Builder
		start      int
		lineNo     int
		continuing bool
	)
	for {
		s, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		if s != "" {
			lineNo++
			if !continuing {
				start = lineNo
				buf.Reset()
			}
			s = strings.TrimRight(s, "\r\n")
			if strings.HasSuffix(s, `\`) {
				buf.WriteString(s[:len(s)-1])
				continuing = true
			} else {
				buf.WriteString(s)
				continuing = false
				text := strings.TrimSpace(buf.String())
				if text != "" && !strings.HasPrefix(text, "#") {
					lines = append(lines, logicalLine{text: text, line: start})
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	if continuing {
		text := strings.TrimSpace(buf.String())
		if text != "" && !strings.HasPrefix(text, "#") {
			return lines, &lineError{line: start, msg: "file ends in the middle of a continued line"}
		}
	}
	return lines, nil
}

// lineError is an error that knows its line but not its file. The parser
// turns it into an *Error.
type lineError struct {
	line int
	msg  string
}

func (e *lineError) Error() string { return e.msg }

// splitArgs splits the text after a directive name into its arguments.
// An argument is either a bare word or a double-quoted string. Inside
// quotes, \" stands for a quote character; every other backslash is kept
// as written, because regular expressions depend on it.
func splitArgs(s string) ([]string, error) {
	var args []string
	i := 0
	for {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i == len(s) {
			return args, nil
		}
		if s[i] != '"' {
			start := i
			for i < len(s) && !isSpace(s[i]) {
				i++
			}
			args = append(args, s[start:i])
			continue
		}

		i++ // opening quote
		var b strings.Builder
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				if s[i+1] == '"' {
					b.WriteByte('"')
				} else {
					b.WriteByte('\\')
					b.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			i++
			if c == '"' {
				closed = true
				break
			}
			b.WriteByte(c)
		}
		if !closed {
			return nil, errors.New("missing closing double quote")
		}
		if i < len(s) && !isSpace(s[i]) {
			return nil, errors.New("unexpected text directly after closing double quote")
		}
		args = append(args, b.String())
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t'
}
