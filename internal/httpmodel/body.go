package httpmodel

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
)

// maxJSONDepth is how deep objects and arrays may be nested.
const maxJSONDepth = 64

// parseJSON turns a JSON document into parameters. Every value that is not
// an object or array becomes one parameter, named by its path:
//
//	{"user": {"name": "efe"}, "tags": ["a", "b"]}
//
// gives json.user.name=efe, json.tags.0=a, json.tags.1=b, json.tags=2. A
// list that is not empty also gives its length, under the name of the list,
// after its elements; this is what Coraza does. It means the name of every
// key is also a parameter name, as in ModSecurity, which names list
// elements after their list. Some CRS rules look for a pattern at the end
// of a parameter name. A key that appears twice gives two parameters. Numbers keep the text they were
// written with, true and false become those words, and null is empty.
//
// On a syntax error the parameters read so far are returned with the error.
//
// Limit: Go's JSON reader replaces a byte that is not valid UTF-8 inside a
// string with the replacement character, so such a byte does not reach the
// rules unchanged.
func parseJSON(body []byte) ([]Param, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var params []Param
	add := func(path, value string) {
		params = append(params, Param{Name: path, Value: value, RawName: path, RawValue: value, Origin: OriginBody})
	}

	// walk reads one value whose first token has already been read.
	var walk func(tok json.Token, path string, depth int) error
	walk = func(tok json.Token, path string, depth int) error {
		switch v := tok.(type) {
		case string:
			add(path, v)
		case json.Number:
			add(path, v.String())
		case bool:
			add(path, strconv.FormatBool(v))
		case nil:
			add(path, "")
		case json.Delim:
			if depth >= maxJSONDepth {
				return fmt.Errorf("nesting is deeper than %d levels", maxJSONDepth)
			}
			index := 0
			for dec.More() {
				child := path + "." + strconv.Itoa(index)
				if v == '{' {
					key, err := dec.Token()
					if err != nil {
						return err
					}
					child = path + "." + key.(string)
				}
				next, err := dec.Token()
				if err != nil {
					return err
				}
				if err := walk(next, child, depth+1); err != nil {
					return err
				}
				index++
			}
			// The closing bracket.
			if _, err := dec.Token(); err != nil {
				return err
			}
			if v == '[' && index > 0 {
				// The length of the list, under the name of the list.
				add(path, strconv.Itoa(index))
			}
		}
		return nil
	}

	// A document that stops in the middle makes the reader report a bare
	// "EOF", which says little; give it a clearer text.
	early := func(err error) error {
		if err == io.EOF {
			return errors.New("the document ends early")
		}
		return err
	}

	tok, err := dec.Token()
	if err != nil {
		return nil, early(err)
	}
	if err := walk(tok, "json", 0); err != nil {
		return params, early(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return params, errors.New("there is more text after the JSON document")
	}
	return params, nil
}

// parseMultipart reads a multipart/form-data body. A part with a file name
// is a file: its field name and file name are kept and its content is
// skipped. Every other part is a text field and becomes a parameter.
//
// The file name is taken from the Content-Disposition header as the client
// wrote it. Go's own helper would cut it down to its last path element,
// which would hide exactly what a path traversal attempt looks like.
func parseMultipart(body []byte, contentType string) ([]Param, []File, error) {
	_, typeParams, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, nil, fmt.Errorf("Content-Type: %w", err)
	}
	boundary := typeParams["boundary"]
	if boundary == "" {
		return nil, nil, errors.New("the Content-Type names no boundary")
	}

	var (
		params []Param
		files  []File
	)
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return params, files, nil
		}
		if err != nil {
			return params, files, err
		}
		_, disposition, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			return params, files, fmt.Errorf("Content-Disposition of a part: %w", err)
		}
		field := disposition["name"]
		if filename, isFile := disposition["filename"]; isFile {
			size, err := io.Copy(io.Discard, part)
			files = append(files, File{Field: field, Name: filename, Size: int(size)})
			if err != nil {
				return params, files, err
			}
			continue
		}
		content, err := io.ReadAll(part)
		value := string(content)
		params = append(params, Param{Name: field, Value: value, RawName: field, RawValue: value, Origin: OriginBody})
		if err != nil {
			return params, files, err
		}
	}
}

// partHeaderLines collects the header lines of every part of a multipart
// body, the way ModSecurity v2 builds MULTIPART_PART_HEADERS
// (apache2/msc_multipart.c): each line as received, without its line
// break; a line that starts with a space or tab continues the one before
// and is joined to it with one space.
//
// It reads the body on its own, line by line, because Go's multipart
// reader rejects header lines with characters it does not allow and
// rewrites the others. One difference from ModSecurity, which stops with an
// error at a header name with a character outside 33 to 126: such a line is
// kept, so that CRS rule 922130, which looks for exactly that, can find it.
func partHeaderLines(body []byte, contentType string) []PartHeader {
	_, typeParams, err := mime.ParseMediaType(contentType)
	if err != nil || typeParams["boundary"] == "" {
		return nil
	}
	delimiter := "--" + typeParams["boundary"]

	var (
		out      []PartHeader
		part     []string // the header lines of the current part
		inHeader bool
	)
	finish := func() {
		name := ""
		for _, line := range part {
			header, value, _ := strings.Cut(line, ":")
			if strings.EqualFold(strings.TrimSpace(header), "Content-Disposition") {
				if _, params, err := mime.ParseMediaType(value); err == nil {
					name = params["name"]
				}
			}
		}
		for _, line := range part {
			out = append(out, PartHeader{Part: name, Line: line})
		}
		part = nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if rest, ok := strings.CutPrefix(line, delimiter); ok {
			if inHeader {
				finish()
			}
			if strings.HasPrefix(rest, "--") {
				return out // the closing delimiter
			}
			inHeader = true
			continue
		}
		if !inHeader {
			continue // part content, or text before the first delimiter
		}
		switch {
		case line == "":
			finish()
			inHeader = false
		case (line[0] == ' ' || line[0] == '\t') && len(part) > 0:
			part[len(part)-1] += " " + strings.TrimLeft(line, " \t")
		default:
			part = append(part, line)
		}
	}
	if inHeader {
		finish()
	}
	return out
}

// parseXML collects the text between tags and the values of attributes. It
// does not build a document tree and does not load anything the document
// refers to, such as external entities.
//
// The reader is forgiving, like the one in Coraza: tags that HTML leaves
// open are closed for it and HTML entity names are known. On an error the
// pieces read so far are returned with the error.
func parseXML(body []byte) (text, attributes []string, err error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return text, attributes, nil
		}
		if err != nil {
			return text, attributes, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			for _, attr := range t.Attr {
				attributes = append(attributes, attr.Value)
			}
		case xml.CharData:
			if piece := strings.TrimSpace(string(t)); piece != "" {
				text = append(text, piece)
			}
		}
	}
}
