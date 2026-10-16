package operator

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/engine/transform"
	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// crsPatterns returns the @rx patterns of all CRS request rule files.
func crsPatterns(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob("../../../coreruleset-4.30.0/rules/REQUEST-*.conf")
	if err != nil || len(files) != 18 {
		t.Fatalf("found %d rule files (%v)", len(files), err)
	}
	var patterns []string
	for _, file := range files {
		directives, err := seclang.ParseFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range directives {
			if d.Kind == seclang.KindRule && strings.EqualFold(d.Operator.Name, "rx") && !hasMacro(d.Operator.Argument) {
				patterns = append(patterns, d.Operator.Argument)
			}
		}
	}
	return patterns
}

// corpus returns many values: everything the example requests carry, as
// sent and after the transformations the CRS rules use most.
func corpus(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob("../../../testdata/requests/*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob("../../../testdata/requests/*.json")
	files = append(files, more...)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	chains := [][]string{
		nil,
		{"urlDecodeUni"},
		{"urlDecodeUni", "lowercase"},
		{"utf8toUnicode", "urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode", "removeNulls"},
		{"urlDecodeUni", "removeWhitespace", "lowercase"},
		{"cmdLine"},
		{"urlDecodeUni", "replaceComments", "compressWhitespace"},
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var examples []struct {
			URI        string     `json:"uri"`
			Headers    [][]string `json:"headers"`
			Body       string     `json:"body"`
			BodyBase64 string     `json:"body_base64"`
		}
		if err := json.Unmarshal(data, &examples); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, ex := range examples {
			raw := []string{ex.URI, ex.Body}
			if b, err := base64.StdEncoding.DecodeString(ex.BodyBase64); err == nil {
				raw = append(raw, string(b))
			}
			for _, h := range ex.Headers {
				raw = append(raw, h...)
			}
			for _, part := range strings.FieldsFunc(ex.URI+"&"+ex.Body, func(r rune) bool { return r == '?' || r == '&' || r == '=' }) {
				if v, err := url.QueryUnescape(part); err == nil {
					raw = append(raw, v)
				}
			}
			for _, v := range raw {
				for _, chain := range chains {
					tr, err := transform.Resolve(chain)
					if err != nil {
						t.Fatal(err)
					}
					w := v
					for _, x := range tr {
						w = x.Apply(w)
					}
					add(w)
				}
			}
		}
	}
	return out
}

// The prefilter must never skip a value that the expression matches. This
// runs every @rx pattern of the CRS request rules on every value of the
// corpus, and on random values made of the pattern's own words, with and
// without the prefilter.
func TestPrefilterNeverHidesAMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	values := corpus(t)
	r := rand.New(rand.NewSource(20261016))
	withPre, total, matches, skipped := 0, 0, 0, 0
	for _, p := range crsPatterns(t) {
		op, err := newRx(p)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		o := op.(rx)
		total++
		if o.pre == nil {
			continue
		}
		withPre++
		plain := o
		plain.pre = nil

		// Values made of the words themselves, in random case, between
		// random text, so that many of them get past the prefilter.
		tree, _ := syntax.Parse("(?s)"+p, syntax.Perl)
		words, _ := requiredWords(tree.Simplify())
		own := make([]string, 0, 50)
		for i := 0; i < 50; i++ {
			var b strings.Builder
			for n := r.Intn(4); n >= 0; n-- {
				b.WriteString(values[r.Intn(len(values))][:0] + randomCase(r, words[r.Intn(len(words))]))
				b.WriteString(" (=';/\\\"<>")
			}
			own = append(own, b.String())
		}

		for _, v := range append(values, own...) {
			want := plain.Match(v, nil).Matched
			if want {
				matches++
			}
			if !isASCII(v) || o.pre.mayMatch(v) {
				continue
			}
			skipped++
			if want {
				t.Fatalf("the prefilter skips %q, which %q matches", v, p)
			}
		}
	}
	t.Logf("%d of %d patterns have a prefilter; %d values checked per pattern, %d matches, %d values skipped", withPre, total, len(values), matches, skipped)
	// 144 of the 268 patterns had a prefilter when this was written. The
	// test fails if a change loses many of them.
	if withPre < 140 {
		t.Errorf("only %d of %d patterns have a prefilter", withPre, total)
	}
}

func randomCase(r *rand.Rand, s string) string {
	b := []byte(s)
	for i := range b {
		if r.Intn(2) == 0 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

// Small cases of the analysis, written out.
func TestRequiredWords(t *testing.T) {
	for pattern, want := range map[string]string{
		`(?i)union\s+select`: "select",
		// Go's parser writes this as e(?:val|xec)\(; the parts are joined
		// again.
		`(?:eval|exec)\(`: "eval( exec(",
		`abc|de`:          "abc de",
		`a|bc`:            "",   // a word shorter than 2
		`(?i)(?:abc|x*)`:  "",   // a branch that can be empty
		`ab+cd`:           "cd", // "abcd" and "abbcd" both contain "cd"
		`[a-z]+passwd`:    "passwd",
		`(?:foo)+bar`:     "foo",
		`(?:foo)*barbaz`:  "barbaz",
		`\bscript\b`:      "script",
		`(?i)SeLeCt`:      "select",
		`é{1}tude`:        "tude",
		`(?i)été`:         "", // a word with other letters is no requirement
	} {
		tree, err := syntax.Parse("(?s)"+pattern, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if p := newPrefilter(tree); p != nil {
			words, _ := requiredWords(tree.Simplify())
			got = strings.Join(words, " ")
		}
		if got != want {
			t.Errorf("%q: words %q, want %q", pattern, got, want)
		}
	}
}

// On any input, a value the prefilter skips must be one the expression does
// not match. Without -fuzz the seeds run as an ordinary test.
func FuzzPrefilter(f *testing.F) {
	for _, seed := range []string{"", "union select", "UnIoN/**/SeLeCt", "eval(", "file:///etc/passwd", "s3://x", "<script>", "' or 1=1--", "cat /etc/passwd"} {
		f.Add(seed)
	}
	type pair struct{ with, without rx }
	var ops []pair
	for _, p := range crsPatterns(f) {
		op, err := newRx(p)
		if err != nil {
			f.Fatal(err)
		}
		if o := op.(rx); o.pre != nil {
			plain := o
			plain.pre = nil
			ops = append(ops, pair{o, plain})
		}
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, op := range ops {
			if !isASCII(value) || op.with.pre.mayMatch(value) {
				continue
			}
			if op.without.Match(value, nil).Matched {
				t.Fatalf("the prefilter skips %q, which %q matches", value, op.with.re)
			}
		}
	})
}
