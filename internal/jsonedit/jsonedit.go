// Package jsonedit changes JSON files the way a person would: an object
// keeps its keys in the order they were written, and the file is written
// back as json.MarshalIndent writes it, with two spaces. The dashboard uses
// it to change one setting of a configuration or a profile and leave the
// rest of the file as it was (W12 of docs/development-plan-dashboard-control.md).
package jsonedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Kind is the kind of a Value.
type Kind int

const (
	Scalar Kind = iota // a string, a number, true, false or null
	Object
	Array
)

// Value is a JSON value. An Object has Keys and Vals in the same order; an
// Array has Items; a Scalar holds its JSON text in Raw.
type Value struct {
	Kind  Kind
	Keys  []string
	Vals  []*Value
	Items []*Value
	Raw   []byte
}

// Parse reads one JSON value.
func Parse(data []byte) (*Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parse(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected content after the value")
	}
	return v, nil
}

func parse(dec *json.Decoder) (*Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v := &Value{Kind: Object}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("an object key is %v", kt)
				}
				val, err := parse(dec)
				if err != nil {
					return nil, err
				}
				v.Keys, v.Vals = append(v.Keys, key), append(v.Vals, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		case '[':
			v := &Value{Kind: Array, Items: []*Value{}}
			for dec.More() {
				item, err := parse(dec)
				if err != nil {
					return nil, err
				}
				v.Items = append(v.Items, item)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		raw, err := encode(tok)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: Scalar, Raw: raw}, nil
	}
}

// encode writes a scalar as JSON, without escaping <, > and &.
func encode(x any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(x); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// From makes a Value of x, as json.Marshal would write it: a struct's
// fields in their order.
func From(x any) (*Value, error) {
	data, err := encode(x)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Must is From for a value that always encodes, such as a string or a
// number.
func Must(x any) *Value {
	v, err := From(x)
	if err != nil {
		panic(err)
	}
	return v
}

// Get returns the value of key in an object, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for i, k := range v.Keys {
		if k == key {
			return v.Vals[i]
		}
	}
	return nil
}

// Set gives key the value val in an object: in its place when the key is
// there, else at the end.
func (v *Value) Set(key string, val *Value) {
	for i, k := range v.Keys {
		if k == key {
			v.Vals[i] = val
			return
		}
	}
	v.Keys, v.Vals = append(v.Keys, key), append(v.Vals, val)
}

// SetAfter is Set for a new key, which goes after the first of after that
// the object has, or at the end.
func (v *Value) SetAfter(key string, val *Value, after ...string) {
	if v.Get(key) != nil {
		v.Set(key, val)
		return
	}
	for _, a := range after {
		for i, k := range v.Keys {
			if k == a {
				v.Keys = append(v.Keys[:i+1], append([]string{key}, v.Keys[i+1:]...)...)
				v.Vals = append(v.Vals[:i+1], append([]*Value{val}, v.Vals[i+1:]...)...)
				return
			}
		}
	}
	v.Set(key, val)
}

// Delete takes key out of an object.
func (v *Value) Delete(key string) {
	for i, k := range v.Keys {
		if k == key {
			v.Keys = append(v.Keys[:i], v.Keys[i+1:]...)
			v.Vals = append(v.Vals[:i], v.Vals[i+1:]...)
			return
		}
	}
}

// Decode reads v into dst, as json.Unmarshal would.
func (v *Value) Decode(dst any) error {
	return json.Unmarshal(v.Marshal(), dst)
}

// Marshal writes v as json.MarshalIndent with two spaces writes it, with a
// newline at the end.
func (v *Value) Marshal() []byte {
	var b strings.Builder
	v.write(&b, "")
	b.WriteString("\n")
	return []byte(b.String())
}

func (v *Value) write(b *strings.Builder, indent string) {
	inner := indent + "  "
	switch v.Kind {
	case Object:
		if len(v.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range v.Keys {
			key, _ := encode(k)
			b.WriteString(inner)
			b.Write(key)
			b.WriteString(": ")
			v.Vals[i].write(b, inner)
			if i < len(v.Keys)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "}")
	case Array:
		if len(v.Items) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, item := range v.Items {
			b.WriteString(inner)
			item.write(b, inner)
			if i < len(v.Items)-1 {
				b.WriteString(",")
			}
			b.WriteString("\n")
		}
		b.WriteString(indent + "]")
	default:
		b.Write(v.Raw)
	}
}
