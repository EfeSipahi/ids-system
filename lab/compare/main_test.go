package main

import (
	"reflect"
	"testing"
)

// Records are compared as multisets: order does not count, repeats do.
func TestDiff(t *testing.T) {
	a, b := diff([]string{"x", "y", "y", "z"}, []string{"y", "x", "z", "w"})
	if !reflect.DeepEqual(a, []string{"y"}) || !reflect.DeepEqual(b, []string{"w"}) {
		t.Errorf("only in a %v, only in b %v", a, b)
	}
	if a, b := diff([]string{"x", "y"}, []string{"y", "x"}); a != nil || b != nil {
		t.Errorf("the same multiset: %v, %v", a, b)
	}
}
