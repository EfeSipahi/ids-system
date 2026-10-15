package transform

import "strconv"

// Length replaces the value by its length in bytes, written as a number.
// A rule uses it to compare the size of a value with a limit:
//
//	"hello"  becomes  "5"
//	"é"      becomes  "2", because it takes two bytes in UTF-8
func Length(s string) string {
	return strconv.Itoa(len(s))
}
