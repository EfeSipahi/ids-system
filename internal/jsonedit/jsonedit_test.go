package jsonedit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A file written as json.MarshalIndent writes it, as the shop's
// configuration and profile are, is the same byte for byte when read and
// written back. A file laid out by hand keeps its content, keys and order,
// not its layout.
func TestRoundTrip(t *testing.T) {
	for path, same := range map[string]bool{"../../configs/csic-shop.json": true, "../../profiles/csic-shop.json": true, "../../configs/crs-first-engine.json": false, "../../testdata/crs-tests.json": false} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		got := v.Marshal()
		if same && !bytes.Equal(got, data) {
			t.Errorf("%s: written back differently:\n%s", path, got)
		}
		var a, b any
		json.Unmarshal(data, &a)
		json.Unmarshal(got, &b)
		if ja, _ := json.Marshal(a); string(ja) != func() string { jb, _ := json.Marshal(b); return string(jb) }() {
			t.Errorf("%s: the content changed", path)
		}
	}
}

func TestEdits(t *testing.T) {
	v, err := Parse([]byte(`{"b": 1, "a": {"x": [1, 2.50, "<&>"]}, "c": null}`))
	if err != nil {
		t.Fatal(err)
	}
	v.Set("b", Must(2))
	v.SetAfter("n", Must("new"), "zz", "a")
	v.Delete("c")
	v.Get("a").Set("y", Must([]string{}))
	want := "{\n  \"b\": 2,\n  \"a\": {\n    \"x\": [\n      1,\n      2.50,\n      \"<&>\"\n    ],\n    \"y\": []\n  },\n  \"n\": \"new\"\n}\n"
	if got := string(v.Marshal()); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	var back map[string]any
	if err := v.Decode(&back); err != nil || back["n"] != "new" {
		t.Errorf("decode: %v %v", back, err)
	}
	// The same as the standard library writes it.
	std, _ := json.MarshalIndent(map[string]any{"k": []any{}, "o": map[string]any{}}, "", "  ")
	w, _ := From(map[string]any{"k": []any{}, "o": map[string]any{}})
	if strings.TrimSpace(string(w.Marshal())) != string(std) {
		t.Errorf("%s\n%s", w.Marshal(), std)
	}
	for _, bad := range []string{`{"a": 1} x`, `{"a": }`, `[1,`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}
