package operator

import (
	"bufio"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/seclang"
)

func mustNew(t *testing.T, name, argument string, negated bool) Operator {
	t.Helper()
	op, err := New(name, argument, negated, "")
	if err != nil {
		t.Fatalf("New(%q, %q): %v", name, argument, err)
	}
	return op
}

func TestRx(t *testing.T) {
	tests := []struct {
		pattern  string
		value    string
		matched  bool
		captures []string
	}{
		{`abc`, "xxabcxx", true, []string{"abc"}},
		{`abc`, "ABC", false, nil},
		{`(?i)abc`, "xABCx", true, []string{"ABC"}},
		{`^abc$`, "abc", true, []string{"abc"}},
		{`^abc$`, "abc\n", false, nil},
		// "." matches a newline.
		{`a.c`, "a\nc", true, []string{"a\nc"}},
		{`^(\w+)=(\d+)$`, "id=42", true, []string{"id=42", "id", "42"}},
		// A group that took no part in the match is empty.
		{`(a)|(b)`, "b", true, []string{"b", "", "b"}},
		// Only TX.0 to TX.9 exist.
		{`(1)(2)(3)(4)(5)(6)(7)(8)(9)(a)(b)`, "123456789ab", true, []string{"123456789ab", "1", "2", "3", "4", "5", "6", "7", "8", "9"}},
		{``, "anything", true, []string{""}},
		{`\x00`, "a\x00b", true, []string{"\x00"}},
		// An invalid byte is one character for ".".
		{`^a.b$`, "a\xffb", true, []string{"a\xffb"}},
	}
	for _, tt := range tests {
		got := mustNew(t, "rx", tt.pattern, false).Match(tt.value, nil)
		if got.Matched != tt.matched || !reflect.DeepEqual(got.Captures, tt.captures) {
			t.Errorf("@rx %s on %q = %+v, want matched %v with %q", tt.pattern, tt.value, got, tt.matched, tt.captures)
		}
	}
}

func TestRxRejectsWhatItCannotRun(t *testing.T) {
	tests := []struct {
		pattern string
		msg     string
	}{
		{`(unclosed`, "missing closing )"},
		{`(a)\1`, "invalid escape sequence"},
		{`a(?=b)`, "invalid or unsupported Perl syntax"},
		{`^%{tx.allowed}$`, "macro is not supported"},
	}
	for _, tt := range tests {
		_, err := New("rx", tt.pattern, false, "")
		if err == nil || !strings.Contains(err.Error(), tt.msg) || !strings.HasPrefix(err.Error(), "@rx: ") {
			t.Errorf("New(rx, %q): error = %v, want one containing %q", tt.pattern, err, tt.msg)
		}
	}
}

// The values in want were produced by C's atoi for the same inputs.
func TestParseInt(t *testing.T) {
	inputs := []string{"", "0", "5", "12abc", "abc", "  42", "\t\n\v\f\r 7", "-5", "+7", "- 5", "--5", "+-5", "007", "1e3", "0x10", "3.9", "-0", "12 34", " -12x", "2147483647", "-2147483648"}
	want := []int64{0, 0, 5, 12, 0, 42, 7, -5, 7, 0, 0, 0, 7, 1, 0, 3, 0, 12, -12, 2147483647, -2147483648}
	for i, in := range inputs {
		if got := ParseInt(in); got != want[i] {
			t.Errorf("ParseInt(%q) = %d, want %d", in, got, want[i])
		}
	}

	// Out of range values stop at the limits.
	limits := []struct {
		in   string
		want int64
	}{
		{"9223372036854775807", math.MaxInt64},
		{"9223372036854775808", math.MaxInt64},
		{"99999999999999999999999", math.MaxInt64},
		{"-9223372036854775808", math.MinInt64},
		{"-9223372036854775809", math.MinInt64},
		{"-99999999999999999999999", math.MinInt64},
	}
	for _, tt := range limits {
		if got := ParseInt(tt.in); got != tt.want {
			t.Errorf("ParseInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestNumeric(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		value    string
		want     bool
	}{
		{"eq", "0", "0", true},
		{"eq", "0", "", true}, // an empty value counts as 0
		{"eq", "0", "abc", true},
		{"eq", "0", "1", false},
		{"eq", "100", "100", true},
		{"eq", "1", " 1x", true},
		{"lt", "1", "0", true},
		{"lt", "1", "1", false},
		{"lt", "2", "1", true},
		{"lt", "2", "-3", true},
		{"ge", "5", "5", true},
		{"ge", "5", "10", true},
		{"ge", "5", "4", false},
		// Numbers are compared as numbers, not as text.
		{"lt", "10", "9", true},
		{"ge", "9", "10", true},
	}
	for _, tt := range tests {
		if got := mustNew(t, tt.name, tt.argument, false).Match(tt.value, nil); got.Matched != tt.want || got.Captures != nil {
			t.Errorf("%q @%s %s = %+v, want %v", tt.value, tt.name, tt.argument, got, tt.want)
		}
	}
}

func TestNumericWithMacro(t *testing.T) {
	op := mustNew(t, "ge", "%{tx.inbound_anomaly_score_threshold}", false)

	expandTo := func(threshold string) func(string) string {
		return func(text string) string {
			if text != "%{tx.inbound_anomaly_score_threshold}" {
				t.Errorf("expand called with %q", text)
			}
			return threshold
		}
	}
	// The same prepared operator gives different answers as the request's
	// own threshold changes.
	if !op.Match("5", expandTo("5")).Matched {
		t.Error("5 @ge 5 did not match")
	}
	if op.Match("5", expandTo("10")).Matched {
		t.Error("5 @ge 10 matched")
	}

	// Without a macro, expand is not used at all.
	called := false
	mustNew(t, "eq", "1", false).Match("1", func(s string) string { called = true; return s })
	if called {
		t.Error("expand was called for an argument without a macro")
	}
}

func TestNegation(t *testing.T) {
	op := mustNew(t, "rx", `(?:URLENCODED|MULTIPART|XML|JSON)`, true)
	if got := op.Match("", nil); !got.Matched || got.Captures != nil {
		t.Errorf("!@rx on an empty value = %+v, want a match without captures", got)
	}
	if got := op.Match("URLENCODED", nil); got.Matched || got.Captures != nil {
		t.Errorf("!@rx on URLENCODED = %+v, want no match", got)
	}

	lt := mustNew(t, "lt", "%{tx.sampling_percentage}", true)
	expand := func(string) string { return "100" }
	if lt.Match("42", expand).Matched || !lt.Match("100", expand).Matched {
		t.Error("!@lt gave the wrong answer")
	}
}

func TestNewAndSupported(t *testing.T) {
	for _, name := range []string{"rx", "RX", "eq", "Lt", "ge"} {
		if !Supported(name) {
			t.Errorf("Supported(%q) = false", name)
		}
		if _, err := New(name, "1", false, ""); err != nil {
			t.Errorf("New(%q): %v", name, err)
		}
	}
	for _, name := range []string{"within", "gt", "le", "unconditionalMatch", ""} {
		if Supported(name) {
			t.Errorf("Supported(%q) = true", name)
		}
		if _, err := New(name, "x", false, ""); err == nil || !strings.Contains(err.Error(), "is not supported") {
			t.Errorf("New(%q): error = %v", name, err)
		}
	}
}

// Every operator in the four files of the first engine that is supported
// must also accept its argument. This compiles the real CRS patterns.
func TestOperatorsOfFirstEngineFiles(t *testing.T) {
	files := []string{
		"crs-setup.conf.example",
		"rules/REQUEST-901-INITIALIZATION.conf",
		"rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
		"rules/REQUEST-949-BLOCKING-EVALUATION.conf",
	}
	built := map[string]int{}
	unsupported := map[string]bool{}
	for _, file := range files {
		directives, err := seclang.ParseFile("../../../coreruleset-4.30.0/" + file)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range directives {
			if d.Kind != seclang.KindRule {
				continue
			}
			name := d.Operator.Name
			if !Supported(name) {
				unsupported[name] = true
				continue
			}
			if _, err := New(name, d.Operator.Argument, d.Operator.Negated, filepath.Dir(d.Pos.File)); err != nil {
				t.Errorf("%s: %v", d.Pos, err)
				continue
			}
			built[strings.ToLower(name)]++
		}
	}
	// Counted independently of this code, with a script over the same files.
	want := map[string]int{"rx": 7, "eq": 28, "lt": 18, "ge": 18, "pmfromfile": 4}
	if !reflect.DeepEqual(built, want) {
		t.Errorf("operators built = %v, want %v", built, want)
	}
	// These belong to rules the first engine excludes.
	wantUnsupported := map[string]bool{"unconditionalMatch": true}
	if !reflect.DeepEqual(unsupported, wantUnsupported) {
		t.Errorf("unsupported operators = %v, want %v", unsupported, wantUnsupported)
	}
}

func rulePattern(t *testing.T, id int) string {
	t.Helper()
	directives, err := seclang.ParseFile("../../../coreruleset-4.30.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range directives {
		if d.ID == id {
			return d.Operator.Argument
		}
	}
	t.Fatalf("rule %d not found", id)
	return ""
}

// TestRxAgainstPythonRe runs the real patterns of 930100 and 930110 on
// inputs whose results were recorded from an independent regex engine. The
// header of the data file says how it was produced.
func TestRxAgainstPythonRe(t *testing.T) {
	ops := map[string]Operator{
		"930100": mustNew(t, "rx", rulePattern(t, 930100), false),
		"930110": mustNew(t, "rx", rulePattern(t, 930110), false),
	}

	f, err := os.Open("testdata/rx_930_vectors.txt")
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

	cases := map[string]int{}
	matches := map[string]int{}
	failures := 0
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 || ops[fields[0]] == nil {
			t.Fatalf("line %d: bad line %q", line, text)
		}
		in := unhex(fields[1])
		wantMatch := fields[2] != "nomatch"
		wantText := ""
		if wantMatch {
			wantText = unhex(fields[2])
			matches[fields[0]]++
		}
		cases[fields[0]]++

		got := ops[fields[0]].Match(in, nil)
		gotText := ""
		if got.Matched {
			gotText = got.Captures[0]
		}
		if got.Matched != wantMatch || gotText != wantText {
			failures++
			if failures <= 20 {
				t.Errorf("line %d: rule %s on %q: matched %v with %q, reference says %v with %q", line, fields[0], in, got.Matched, gotText, wantMatch, wantText)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if failures > 20 {
		t.Errorf("%d more differences not shown", failures-20)
	}
	for id := range ops {
		if cases[id] < 2000 || matches[id] < 10 {
			t.Errorf("rule %s: %d reference cases with %d matches", id, cases[id], matches[id])
		}
	}
}

// One prepared operator is used by many goroutines, as M21 requires. Run
// with -race to let the race detector watch.
func TestOperatorsAreSafeForConcurrentUse(t *testing.T) {
	re := mustNew(t, "rx", rulePattern(t, 930110), false)
	ge := mustNew(t, "ge", "%{tx.threshold}", false)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// Even goroutines act as an attack request, odd ones as a
			// normal request with its own threshold.
			value, wantRx := "/get?a=../../etc", true
			threshold, wantGe := "5", true
			if g%2 == 1 {
				value, wantRx = "/get?q=kitap", false
				threshold, wantGe = "99", false
			}
			expand := func(string) string { return threshold }
			for i := 0; i < 500; i++ {
				if re.Match(value, nil).Matched != wantRx {
					t.Errorf("goroutine %d: @rx gave the wrong answer", g)
					return
				}
				if ge.Match("5", expand).Matched != wantGe {
					t.Errorf("goroutine %d: @ge gave the wrong answer", g)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestPm(t *testing.T) {
	op := mustNew(t, "pm", "document.cookie .innerHTML <!-- abc abcdef cde", false)
	tests := []struct {
		value   string
		matched bool
		capture string
	}{
		{"x = document.cookie;", true, "document.cookie"},
		{"el.INNERHTML = 1", true, ".INNERHTML"},
		{"<!-- hi", true, "<!--"},
		{"document.cooki", false, ""},
		{"", false, ""},
		// The match that ends first is reported.
		{"zzabcdefzz", true, "abc"},
		{"abcde", true, "abc"},
		// A phrase can start inside a failed attempt at another one.
		{"abcd-ab-cde", true, "abc"},
		{"ab-cde", true, "cde"},
		{"docudocument.cookie", true, "document.cookie"},
		{"a\x00bc ABC", true, "ABC"},
	}
	for _, tt := range tests {
		got := op.Match(tt.value, nil)
		capture := ""
		if got.Matched {
			capture = got.Captures[0]
		}
		if got.Matched != tt.matched || capture != tt.capture {
			t.Errorf("@pm on %q = %v %q, want %v %q", tt.value, got.Matched, capture, tt.matched, tt.capture)
		}
	}

	for _, argument := range []string{"", "   ", "a |41| b"} {
		if _, err := New("pm", argument, false, ""); err == nil {
			t.Errorf("New(pm, %q): no error", argument)
		}
	}
}

// The automaton must agree with the plain way of searching: look for each
// phrase in turn.
func TestPmAgainstPlainSearch(t *testing.T) {
	phrases := []string{"a", "ab", "bab", "bc", "bca", "c", "caa", "/etc/passwd", "etc/", ".env", "..", "xyzzy"}
	alphabet := "abc/.etpswdnvxyz"
	state := uint32(12345)
	random := func(n int) int {
		state = state*1664525 + 1013904223
		return int(state>>16) % n
	}
	for size := 1; size <= len(phrases); size++ {
		subset := phrases[:size]
		op := buildPm(subset)
		for i := 0; i < 400; i++ {
			value := make([]byte, random(14))
			for j := range value {
				value[j] = alphabet[random(len(alphabet))]
			}
			want := false
			for _, p := range subset {
				if strings.Contains(string(value), p) {
					want = true
				}
			}
			got := op.Match(string(value), nil)
			if got.Matched != want {
				t.Fatalf("phrases %q on %q: matched %v, want %v", subset, value, got.Matched, want)
			}
			if got.Matched && !containsString(subset, got.Captures[0]) {
				t.Fatalf("phrases %q on %q: capture %q is not a phrase", subset, value, got.Captures[0])
			}
		}
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestPmFromFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "words.data"), []byte("# a comment\n\n.env\n  /etc/passwd  \n.git/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.data"), []byte("# nothing\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op, err := New("pmFromFile", "words.data", false, dir)
	if err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]bool{
		"/app/.ENV":        true,
		"x=/etc/passwd":    true,
		"/repo/.git/HEAD":  true,
		"/app/environment": false,
		"# a comment":      false,
	} {
		if got := op.Match(value, nil).Matched; got != want {
			t.Errorf("@pmFromFile on %q = %v, want %v", value, got, want)
		}
	}

	for _, tt := range []struct{ argument, msg string }{
		{"missing.data", "missing.data"},
		{"empty.data", "holds no phrases"},
		{"", "exactly one data file"},
		{"a.data b.data", "exactly one data file"},
	} {
		if _, err := New("pmFromFile", tt.argument, false, dir); err == nil || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("New(pmFromFile, %q): error = %v, want one containing %q", tt.argument, err, tt.msg)
		}
	}

	// The real CRS data files load.
	for _, name := range []string{"lfi-os-files.data", "restricted-files.data", "ai-critical-artifacts.data"} {
		op, err := New("pmFromFile", name, false, "../../../coreruleset-4.30.0/rules")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "lfi-os-files.data" && !op.Match("cat /ETC/Passwd", nil).Matched {
			t.Errorf("%s does not find etc/passwd", name)
		}
	}
}

func TestTextOperators(t *testing.T) {
	contains := mustNew(t, "contains", "<!--", false)
	if !contains.Match("a <!-- b", nil).Matched || contains.Match("a <!- b", nil).Matched {
		t.Error("@contains gave the wrong answer")
	}
	streq := mustNew(t, "streq", "POST", false)
	if !streq.Match("POST", nil).Matched || streq.Match("post", nil).Matched || streq.Match("POSTS", nil).Matched {
		t.Error("@streq gave the wrong answer")
	}
	// A macro argument is expanded for every test.
	withMacro := mustNew(t, "streq", "%{tx.expected}", false)
	expand := func(string) string { return "abc" }
	if !withMacro.Match("abc", expand).Matched || withMacro.Match("abd", expand).Matched {
		t.Error("@streq with a macro gave the wrong answer")
	}
}

func TestLibinjectionOperators(t *testing.T) {
	sqli := mustNew(t, "detectSQLi", "", false)
	for value, want := range map[string]bool{
		"1' OR '1'='1":            true,
		"1 UNION SELECT password": true,
		"kitap":                   false,
		"O'Brien":                 false,
		"":                        false,
	} {
		got := sqli.Match(value, nil)
		if got.Matched != want {
			t.Errorf("@detectSQLi on %q = %v, want %v", value, got.Matched, want)
		}
		// A match captures the fingerprint of the token sequence.
		if got.Matched && (len(got.Captures) != 1 || got.Captures[0] == "") {
			t.Errorf("@detectSQLi on %q: captures = %q", value, got.Captures)
		}
	}

	xss := mustNew(t, "detectXSS", "", false)
	for value, want := range map[string]bool{
		"<script>alert(1)</script>": true,
		"<img src=x onerror=a()>":   true,
		"a < b and b > c":           false,
		"kitap":                     false,
	} {
		if got := xss.Match(value, nil).Matched; got != want {
			t.Errorf("@detectXSS on %q = %v, want %v", value, got, want)
		}
	}
}

func TestRxByteMode(t *testing.T) {
	// A pattern that names a byte above 0x7F finds that byte, whether it
	// stands alone or is part of a UTF-8 character.
	op := mustNew(t, "rx", `a[\x80-\xff]+(b)`, false)
	tests := []struct {
		value   string
		matched bool
		capture string
	}{
		{"xa\xffb", true, "a\xffb"},
		{"a\xc3\xa9b", true, "a\xc3\xa9b"},
		{"aéb", true, "aéb"},
		{"ab", false, ""},
		{"a\x7fb", false, ""},
	}
	for _, tt := range tests {
		got := op.Match(tt.value, nil)
		capture := ""
		if got.Matched {
			capture = got.Captures[0]
			if got.Captures[1] != "b" {
				t.Errorf("%q: group = %q", tt.value, got.Captures[1])
			}
		}
		if got.Matched != tt.matched || capture != tt.capture {
			t.Errorf("%q: matched %v with %q, want %v with %q", tt.value, got.Matched, capture, tt.matched, tt.capture)
		}
	}

	// Without such an escape the value is read as text, as before.
	plain := mustNew(t, "rx", `^a.b$`, false)
	if !plain.Match("aéb", nil).Matched {
		t.Error("a pattern without byte escapes no longer reads UTF-8 as characters")
	}
}

func TestValidateByteRange(t *testing.T) {
	// The list of rule 941010: characters of an ordinary file path.
	op := mustNew(t, "validateByteRange", "20,45-47,48-57,65-90,95,97-122", false)
	for value, outside := range map[string]bool{
		"/static/img/logo-2.png": false,
		"":                       false,
		"/search/<script>":       true,
		"/a b":                   true, // 20 is decimal: the space, 32, is not in the list
		"/caf\xc3\xa9":           true,
	} {
		if got := op.Match(value, nil).Matched; got != outside {
			t.Errorf("@validateByteRange on %q = %v, want %v", value, got, outside)
		}
	}
	negated := mustNew(t, "validateByteRange", "97-122", true)
	if !negated.Match("abc", nil).Matched || negated.Match("abC", nil).Matched {
		t.Error("!@validateByteRange gave the wrong answer")
	}
	for _, argument := range []string{"", "a", "10-", "300", "9-3", "1,,2"} {
		if _, err := New("validateByteRange", argument, false, ""); err == nil {
			t.Errorf("New(validateByteRange, %q): no error", argument)
		}
	}
}

func TestRxByteModeBraceForm(t *testing.T) {
	// The second rule of the chain 941310 writes its bytes as \x{bc}.
	op := mustNew(t, "rx", `\x{bc}/[^>\x{be}]*[>\x{be}]`, false)
	if !op.Match("\xbc/script\xbe", nil).Matched || op.Match("</script>", nil).Matched {
		t.Error("a pattern with \\x{..} bytes gave the wrong answer")
	}
}
