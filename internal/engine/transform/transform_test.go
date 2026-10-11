package transform

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

type testCase struct {
	in   string
	want string
}

func runCases(t *testing.T, name string, fn func(string) string, cases []testCase) {
	t.Helper()
	for _, tt := range cases {
		if got := fn(tt.in); got != tt.want {
			t.Errorf("%s(%q) = %q, want %q", name, tt.in, got, tt.want)
		}
	}
}

func TestRemoveNulls(t *testing.T) {
	runCases(t, "RemoveNulls", RemoveNulls, []testCase{
		{"", ""},
		{"abc", "abc"},
		{"..\x00/", "../"},
		{"\x00\x00a\x00", "a"},
		{"\x00", ""},
	})
}

func TestURLDecodeUni(t *testing.T) {
	runCases(t, "URLDecodeUni", URLDecodeUni, []testCase{
		{"", ""},
		{"abc", "abc"},
		{"..%2f..%2Fetc", "../../etc"},
		{"a+b", "a b"},
		{"%00", "\x00"},
		{"%ff", "\xff"},
		// Decoding happens once.
		{"%252e", "%2e"},
		// %uXXXX: only the low byte is used.
		{"%u002e%U002E%u002f", "../"},
		{"%u2215", "\x15"},
		{"%u1234", "\x34"},
		// Codes in the best-fit table become the ASCII look-alike.
		{"%u2019 OR 1=1", "' OR 1=1"},
		{"%u00abscript%u00bb", "<script>"},
		{"%u00e9", "e"},
		// Full-width forms ff01 to ff5e get 0x20 added.
		{"%uff0e%uFF0E%uff0f", "../"},
		{"%uff01", "!"},
		{"%uff5e", "~"},
		{"%uff00", "\x00"},
		{"%uff5f", "\x5f"},
		// Broken sequences are kept as written.
		{"%", "%"},
		{"%2", "%2"},
		{"%zz", "%zz"},
		{"100%", "100%"},
		{"%u", "%u"},
		{"%u00", "%u00"},
		{"%u002", "%u002"},
		{"%uzzzz", "%uzzzz"},
		{"%u00g1", "%u00g1"},
		// After a broken %u, decoding continues with what follows.
		{"%u%2f", "%u/"},
		{"%%2f", "%/"},
	})
}

func TestUTF8ToUnicode(t *testing.T) {
	runCases(t, "UTF8ToUnicode", UTF8ToUnicode, []testCase{
		{"", ""},
		{"abc/../", "abc/../"},
		{"é", "%u00e9"},
		{"aéb", "a%u00e9b"},
		{"şğı", "%u015f%u011f%u0131"},
		{"．．／", "%uff0e%uff0e%uff0f"},
		// Above U+FFFF only the first four hex digits are kept.
		{"😀", "%u1f60"},
		{"\x7f", "\x7f"},
		{"a\x00b", "a\x00b"},
		// Bytes that do not start a valid sequence are copied.
		{"\x80", "\x80"},
		{"\xff", "\xff"},
		{"\xc3", "\xc3"},
		{"\xc3(", "\xc3("},
		{"\xe2\x88", "\xe2\x88"},
		{"\xf0\x9f\x98", "\xf0\x9f\x98"},
		{"\xc3\xa9\xc3", "%u00e9\xc3"},
		// Overlong forms of "/" are not decoded.
		{"\xc0\xaf", "\xc0\xaf"},
		{"\xe0\x80\xaf", "\xe0\x80\xaf"},
		{"\xf0\x80\x80\xaf", "\xf0\x80\x80\xaf"},
		// Surrogates and lead bytes from 0xf5 are not decoded.
		{"\xed\xa0\x80", "\xed\xa0\x80"},
		{"\xf5\x80\x80\x80", "\xf5\x80\x80\x80"},
		// Above U+10FFFF is still written, as ModSecurity v2 does.
		{"\xf4\x90\x80\x80", "%u1100"},
	})
}

func TestCmdLine(t *testing.T) {
	runCases(t, "CmdLine", CmdLine, []testCase{
		{"", ""},
		{"abc", "abc"},
		{"ABC xyz", "abc xyz"},
		{`C^md  /c "dir"`, "cmd/c dir"},
		{`w'h'o^am\i`, "whoami"},
		{"cat /etc/passwd", "cat/etc/passwd"},
		{"a ;,\t\r\n b", "a b"},
		{"a (b", "a(b"},
		// A deleted character between the space and the slash does not
		// protect the space.
		{`a "/b`, "a/b"},
		{" / ", "/ "},
		{"  ", " "},
		{"a  ", "a "},
		{"//", "//"},
		// Only ASCII letters change case.
		{"\xc3\x89A", "\xc3\x89a"},
		// Backslashes are deleted, so a Windows traversal loses its
		// separators at this step.
		{`..\..\win.ini`, "....win.ini"},
		{"a\x00B", "a\x00b"},
	})
}

func TestNormalizePathWin(t *testing.T) {
	runCases(t, "NormalizePathWin", NormalizePathWin, []testCase{
		{"", ""},
		{"/etc/passwd", "/etc/passwd"},
		{`C:\Windows\.\System32\..\win.ini`, "C:/Windows/win.ini"},
		{"/etc//./passwd", "/etc/passwd"},
		{"/a/b/../../c", "/c"},
		{"a/./b", "a/b"},
		{"a/b/", "a/b/"},
		{"/app/x/../.env", "/app/.env"},
		// A path cannot climb above its start.
		{"../../etc/passwd", "../../etc/passwd"},
		{"/../etc", "/etc"},
		{"a/../../b", "../b"},
		// Windows ignores dots and spaces at the end of a file name, so
		// they are removed. ModSecurity removes the whole segment here.
		{"abc..", "abc"},
		{"a/win.ini..", "a/win.ini"},
		{"a/win.ini. /b", "a/win.ini/b"},
		// The name of a data stream is cut off; a drive letter is kept.
		{"web.config::$DATA", "web.config"},
		{`C:\boot.ini:x`, "C:/boot.ini"},
		{`a\\\b`, "a/b"},
		// As in Coraza, a lone slash is doubled.
		{"/", "//"},
	})
}

// One readable example or two for each of the transformations that the
// SQL injection and XSS rules use. The thorough check is the comparison
// with the two reference files further down.
func TestSQLiAndXSSTransformations(t *testing.T) {
	runCases(t, "ReplaceComments", ReplaceComments, []testCase{
		{"UNION/**/SELECT", "UNION SELECT"},
		{"a/* never closed", "a "},
		{"a */ b", "a */ b"},
	})
	runCases(t, "RemoveCommentsChar", RemoveCommentsChar, []testCase{
		{"1/*x*/OR--1#", "1xOR1"},
		{"<!--a-->", "a"},
	})
	runCases(t, "RemoveWhitespace", RemoveWhitespace, []testCase{
		{" j a\tv\na\xa0 ", "java"},
	})
	runCases(t, "CompressWhitespace", CompressWhitespace, []testCase{
		{"a \t\n b\tc ", "a b c "},
	})
	runCases(t, "Lowercase", Lowercase, []testCase{
		{"SeLeCT É", "select É"},
	})
	runCases(t, "JSDecode", JSDecode, []testCase{
		{`\x3cscript\x3e`, "<script>"},
		{`\u003c\uff1c\74`, "<<<"},
		{`a\'b\n`, "a'b\n"},
		{`end\`, `end\`},
	})
	runCases(t, "CSSDecode", CSSDecode, []testCase{
		{`ja\76 ascript`, "javascript"},
		{`\6a\00006a\ff4a`, "jjj"},
		{`a\\b\`, `a\b`},
	})
	runCases(t, "HTMLEntityDecode", HTMLEntityDecode, []testCase{
		{"&lt;script&gt;", "<script>"},
		{"javascript&colon;alert&#40;1&#x29", "javascript:alert(1)"},
		// lt is one of the old names that count without a semicolon,
		// even directly before letters. ModSecurity leaves this alone.
		{"&LTscript&GT", "<script>"},
		// Names are case-sensitive, and most need their semicolon.
		{"&COLON; &colon &unknown; & &#", "&COLON; &colon &unknown; & &#"},
		{"&#233;", "é"},
	})
}

func TestLookupAndResolve(t *testing.T) {
	for _, name := range []string{"utf8toUnicode", "URLDECODEUNI", "removenulls", "cmdLine", "normalizePathWin"} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("Lookup(%q) failed", name)
		}
	}
	if tr, _ := Lookup("urldecodeuni"); tr.Name != "urlDecodeUni" {
		t.Errorf("canonical name = %q", tr.Name)
	}
	for _, name := range []string{"", "none", "sha1", "md5"} {
		if _, ok := Lookup(name); ok {
			t.Errorf("Lookup(%q) succeeded", name)
		}
	}

	names := func(chain []Transformation) string {
		var out []string
		for _, tr := range chain {
			out = append(out, tr.Name)
		}
		return strings.Join(out, ",")
	}
	tests := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"none"}, ""},
		{[]string{"none", "utf8toUnicode", "urlDecodeUni", "removeNulls", "cmdLine"}, "utf8toUnicode,urlDecodeUni,removeNulls,cmdLine"},
		// none discards what came before it, such as inherited defaults.
		{[]string{"cmdLine", "NONE", "removeNulls"}, "removeNulls"},
		{[]string{"removeNulls", "removeNulls"}, "removeNulls,removeNulls"},
	}
	for _, tt := range tests {
		chain, err := Resolve(tt.in)
		if err != nil {
			t.Errorf("Resolve(%q): %v", tt.in, err)
			continue
		}
		if got := names(chain); got != tt.want {
			t.Errorf("Resolve(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}

	if _, err := Resolve([]string{"none", "urlDecodeUni", "sha1"}); err == nil || !strings.Contains(err.Error(), `"sha1" is not supported`) {
		t.Errorf("Resolve with sha1: error = %v", err)
	}
}

// The transformation list of rule 930110, applied one step after another.
// The value after every step is what multiMatch makes the rule test.
func TestRule930110Chain(t *testing.T) {
	chain, err := Resolve([]string{"none", "utf8toUnicode", "urlDecodeUni", "removeNulls", "cmdLine"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		in    string
		steps []string
	}{
		{"..%2f..%2fetc%2fpasswd", []string{"..%2f..%2fetc%2fpasswd", "../../etc/passwd", "../../etc/passwd", "../../etc/passwd"}},
		{"．．／etc", []string{"%uff0e%uff0e%uff0fetc", "../etc", "../etc", "../etc"}},
		{"..%00/etc", []string{"..%00/etc", "..\x00/etc", "../etc", "../etc"}},
		{"..%5c..%5cWIN", []string{"..%5c..%5cWIN", `..\..\WIN`, `..\..\WIN`, "....win"}},
		{"kitap", []string{"kitap", "kitap", "kitap", "kitap"}},
	}
	for _, tt := range tests {
		value := tt.in
		for i, tr := range chain {
			value = tr.Apply(value)
			if value != tt.steps[i] {
				t.Errorf("%q after %s = %q, want %q", tt.in, tr.Name, value, tt.steps[i])
			}
		}
	}
}

// followCoraza names the transformations that are compared with Coraza. All
// others are compared with ModSecurity v2.
var followCoraza = map[string]bool{"normalizePathWin": true, "htmlEntityDecode": true}

// TestAgainstModSecurityV2 compares the transformations with results
// recorded from the ModSecurity v2 C code. The header of the data file says
// how it was produced.
func TestAgainstModSecurityV2(t *testing.T) {
	counts := compareWithVectors(t, "testdata/modsecurity_v2_vectors.txt", "ModSecurity")
	for _, tr := range registry {
		if want := !followCoraza[tr.Name]; want && counts[tr.Name] < 800 {
			t.Errorf("only %d reference cases for %s", counts[tr.Name], tr.Name)
		} else if !want && counts[tr.Name] > 0 {
			t.Errorf("%s follows Coraza but has ModSecurity reference cases", tr.Name)
		}
	}
}

// TestAgainstCorazaV3 does the same for the two transformations that follow
// Coraza, with results recorded from Coraza's Go code.
func TestAgainstCorazaV3(t *testing.T) {
	counts := compareWithVectors(t, "testdata/coraza_v3_vectors.txt", "Coraza")
	if len(counts) != len(followCoraza) {
		t.Errorf("reference cases for %d transformations, want %d", len(counts), len(followCoraza))
	}
	for name := range followCoraza {
		if counts[name] < 800 {
			t.Errorf("only %d reference cases for %s", counts[name], name)
		}
	}
}

// compareWithVectors runs every case of a reference file and returns the
// number of cases per transformation.
func compareWithVectors(t *testing.T, file, source string) map[string]int {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	unhex := func(s string) string {
		if s == "-" {
			return ""
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad hex %q: %v", s, err)
		}
		return string(b)
	}

	counts := map[string]int{}
	failures := 0
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			t.Fatalf("line %d: want 3 fields, found %d", line, len(fields))
		}
		tr, ok := Lookup(fields[0])
		if !ok {
			t.Fatalf("line %d: unknown transformation %q", line, fields[0])
		}
		in, want := unhex(fields[1]), unhex(fields[2])
		counts[tr.Name]++
		if got := tr.Apply(in); got != want {
			failures++
			if failures <= 20 {
				t.Errorf("line %d: %s(%q) = %q, %s gives %q", line, tr.Name, in, got, source, want)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if failures > 20 {
		t.Errorf("%d more differences not shown", failures-20)
	}
	return counts
}

// FuzzTransformations checks properties that must hold for any input,
// including that no input makes a transformation panic. Without -fuzz the
// seed inputs run as an ordinary test.
func FuzzTransformations(f *testing.F) {
	for _, seed := range []string{"", "..%2f", "%u", "%uff0", "%", "\xc3", "\xf0\x9f\x98", "a \"/(", "\x00", "%u00%2", "+%+"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := RemoveNulls(s); strings.Contains(got, "\x00") || len(got) > len(s) {
			t.Errorf("RemoveNulls(%q) = %q", s, got)
		}
		if got := URLDecodeUni(s); len(got) > len(s) {
			t.Errorf("URLDecodeUni(%q) = %q is longer than its input", s, got)
		}
		if got := UTF8ToUnicode(s); len(got) < len(s) {
			t.Errorf("UTF8ToUnicode(%q) = %q is shorter than its input", s, got)
		}
		// One more byte is possible: a lone slash is doubled.
		if got := NormalizePathWin(s); len(got) > len(s)+1 || strings.Contains(got, `\`) {
			t.Errorf("NormalizePathWin(%q) = %q", s, got)
		}
		if got := HTMLEntityDecode(s); !strings.Contains(s, "&") && got != s {
			t.Errorf("HTMLEntityDecode(%q) = %q, but the input has no ampersand", s, got)
		}
		got := CmdLine(s)
		if strings.ContainsAny(got, "\"'\\^,;\t\r\n") || strings.Contains(got, "  ") || strings.Contains(got, " /") || strings.Contains(got, " (") || len(got) > len(s) {
			t.Errorf("CmdLine(%q) = %q", s, got)
		}
		for i := 0; i < len(got); i++ {
			if got[i] >= 'A' && got[i] <= 'Z' {
				t.Errorf("CmdLine(%q) = %q contains an upper-case letter", s, got)
				break
			}
		}
		if again := CmdLine(got); again != got {
			t.Errorf("CmdLine is not stable: %q then %q", got, again)
		}
	})
}
