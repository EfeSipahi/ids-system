package seclang

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// crsDir is the unmodified CRS 4.30.0 source directory, relative to this
// package.
const crsDir = "../../coreruleset-4.30.0"

func parseCRS(t *testing.T, name string) []Directive {
	t.Helper()
	ds, err := ParseFile(filepath.Join(crsDir, name))
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", name, err)
	}
	return ds
}

func findID(t *testing.T, ds []Directive, id int) (int, Directive) {
	t.Helper()
	for i, d := range ds {
		if d.ID == id {
			return i, d
		}
	}
	t.Fatalf("rule %d not found", id)
	return 0, Directive{}
}

// The expected numbers were counted independently of this parser, with a
// script that joins continuation lines and skips comments.
func TestParseFirstEngineFiles(t *testing.T) {
	tests := []struct {
		file    string
		kinds   map[Kind]int
		ids     int
		chained int
		firstID int
		lastID  int
	}{
		{
			file:    "crs-setup.conf.example",
			kinds:   map[Kind]int{KindDefaultAction: 5, KindAction: 1},
			ids:     1,
			firstID: 900990, lastID: 900990,
		},
		{
			file:    "rules/REQUEST-901-INITIALIZATION.conf",
			kinds:   map[Kind]int{KindComponentSignature: 1, KindRule: 35, KindAction: 1, KindMarker: 1},
			ids:     33,
			chained: 3,
			firstID: 901001, lastID: 901500,
		},
		{
			file:    "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
			kinds:   map[Kind]int{KindRule: 14, KindMarker: 1},
			ids:     14,
			firstID: 930011, lastID: 930018,
		},
		{
			file:    "rules/REQUEST-949-BLOCKING-EVALUATION.conf",
			kinds:   map[Kind]int{KindRule: 27, KindAction: 2, KindMarker: 2},
			ids:     28,
			chained: 1,
			firstID: 949052, lastID: 949018,
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			ds := parseCRS(t, tt.file)

			kinds := map[Kind]int{}
			var ids []int
			chained := 0
			for _, d := range ds {
				kinds[d.Kind]++
				if d.ID != 0 {
					ids = append(ids, d.ID)
				}
				if d.Chained {
					chained++
				}
			}
			if !reflect.DeepEqual(kinds, tt.kinds) {
				t.Errorf("directive kinds = %v, want %v", kinds, tt.kinds)
			}
			if len(ids) != tt.ids {
				t.Fatalf("directives with an id = %d, want %d", len(ids), tt.ids)
			}
			if chained != tt.chained {
				t.Errorf("chained rules = %d, want %d", chained, tt.chained)
			}
			if ids[0] != tt.firstID || ids[len(ids)-1] != tt.lastID {
				t.Errorf("first and last id = %d, %d, want %d, %d", ids[0], ids[len(ids)-1], tt.firstID, tt.lastID)
			}
		})
	}
}

func TestParseRule930110(t *testing.T) {
	ds := parseCRS(t, "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf")
	_, d := findID(t, ds, 930110)

	if d.Kind != KindRule || d.Chained {
		t.Errorf("Kind = %v, Chained = %v, want an unchained SecRule", d.Kind, d.Chained)
	}
	if d.Pos.Line != 73 {
		t.Errorf("line = %d, want 73", d.Pos.Line)
	}

	wantVars := []Variable{
		{Collection: "REQUEST_URI_RAW"},
		{Collection: "ARGS"},
		{Collection: "REQUEST_HEADERS"},
		{Collection: "REQUEST_HEADERS", Selector: "Referer", Exclude: true},
		{Collection: "FILES"},
		{Collection: "XML", Selector: "/*"},
		{Collection: "XML", Selector: "//@*"},
	}
	if !reflect.DeepEqual(d.Variables, wantVars) {
		t.Errorf("variables = %v\nwant %v", d.Variables, wantVars)
	}

	wantOp := Operator{Name: "rx", Argument: `(?:^|[/;\x5c])\.{2,3}[/;\x5c]`}
	if d.Operator != wantOp {
		t.Errorf("operator = %+v, want %+v", d.Operator, wantOp)
	}

	checks := map[string][]string{
		"phase":    {"2"},
		"t":        {"none", "utf8toUnicode", "urlDecodeUni", "removeNulls", "cmdLine"},
		"severity": {"CRITICAL"},
		"msg":      {"Path Traversal Attack (/../) or (/.../)"},
		"logdata":  {"Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}"},
		"setvar": {
			"tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}",
			"tx.lfi_score=+%{tx.critical_anomaly_score}",
		},
	}
	for name, want := range checks {
		if got := d.ActionValues(name); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, flag := range []string{"block", "capture", "multiMatch"} {
		if !d.HasAction(flag) {
			t.Errorf("action %s is missing", flag)
		}
	}
	if d.HasAction("chain") {
		t.Error("930110 must not have chain")
	}
	if tags := d.ActionValues("tag"); len(tags) != 8 || tags[4] != "paranoia-level/1" {
		t.Errorf("tags = %q", tags)
	}
}

// 930100 is the other first-engine rule. Its long pattern must arrive
// byte for byte as it is in the file.
func TestParseRule930100(t *testing.T) {
	ds := parseCRS(t, "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf")
	_, d := findID(t, ds, 930100)

	if got := d.ActionValues("t"); !reflect.DeepEqual(got, []string{"none"}) {
		t.Errorf("t = %q, want only none", got)
	}
	if d.HasAction("multiMatch") {
		t.Error("930100 must not have multiMatch")
	}

	// Cut the pattern out of line 35 of the raw file without the parser.
	raw, err := os.ReadFile(filepath.Join(crsDir, "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Split(string(raw), "\n")[34]
	_, want, ok := strings.Cut(line, `"@rx `)
	want, ok2 := strings.CutSuffix(want, `" \`)
	if !ok || !ok2 || len(want) < 500 {
		t.Fatalf("line 35 of the rule file is not the 930100 rule: %s", line)
	}
	if d.Operator.Argument != want {
		t.Errorf("pattern = %s\nwant      %s", d.Operator.Argument, want)
	}
}

func TestParseChain949111(t *testing.T) {
	ds := parseCRS(t, "rules/REQUEST-949-BLOCKING-EVALUATION.conf")
	i, first := findID(t, ds, 949111)

	wantOp := Operator{Name: "ge", Argument: "%{tx.inbound_anomaly_score_threshold}"}
	if first.Operator != wantOp || !first.HasAction("chain") || first.Chained {
		t.Errorf("chain starter = %+v", first)
	}

	second := ds[i+1]
	wantVars := []Variable{{Collection: "TX", Selector: "EARLY_BLOCKING"}}
	if !second.Chained || second.ID != 0 || len(second.Actions) != 0 ||
		!reflect.DeepEqual(second.Variables, wantVars) ||
		second.Operator != (Operator{Name: "eq", Argument: "1"}) {
		t.Errorf("second rule of chain = %+v", second)
	}
	if ds[i+2].Chained {
		t.Error("the rule after the chain must not be chained")
	}
}

func TestParseSetupRules(t *testing.T) {
	ds := parseCRS(t, "rules/REQUEST-901-INITIALIZATION.conf")

	_, d := findID(t, ds, 901120)
	wantVars := []Variable{{Collection: "TX", Selector: "blocking_paranoia_level", Count: true}}
	if !reflect.DeepEqual(d.Variables, wantVars) || d.Operator != (Operator{Name: "eq", Argument: "0"}) {
		t.Errorf("901120 = %v %+v", d.Variables, d.Operator)
	}
	if got := d.ActionValues("setvar"); !reflect.DeepEqual(got, []string{"tx.blocking_paranoia_level=1"}) {
		t.Errorf("901120 setvar = %q", got)
	}

	_, d = findID(t, ds, 901200)
	if d.Kind != KindAction || len(d.ActionValues("setvar")) != 21 {
		t.Errorf("901200: kind %v with %d setvar actions, want SecAction with 21", d.Kind, len(d.ActionValues("setvar")))
	}

	_, d = findID(t, ds, 901340)
	if !d.Operator.Negated || d.Operator.Name != "rx" || d.Operator.Argument != "(?:URLENCODED|MULTIPART|XML|JSON)" {
		t.Errorf("901340 operator = %+v", d.Operator)
	}

	if ds[0].Kind != KindComponentSignature || ds[0].Text != "OWASP_CRS/4.30.0" {
		t.Errorf("first directive = %+v", ds[0])
	}
	last := ds[len(ds)-2]
	if last.Kind != KindMarker || last.Text != "END-SAMPLING" {
		// END-SAMPLING is followed only by rule 901500.
		t.Errorf("directive before the last = %+v", last)
	}
}

// Every rule file parses. The totals were counted independently: 627 rules
// with an id, and 55 SecRuleUpdateTargetById lines, all in file 999.
func TestParseAllRuleFiles(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(crsDir, "rules", "*.conf"))
	if err != nil || len(files) != 27 {
		t.Fatalf("found %d rule files (%v), want 27", len(files), err)
	}
	total, updates := 0, 0
	seen := map[int]string{}
	for _, f := range files {
		ds, err := ParseFile(f)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		for _, d := range ds {
			if d.Kind == KindUpdateTargetByID {
				updates++
				if !strings.HasSuffix(f, "REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf") {
					t.Errorf("%s: target update outside file 999", d.Pos)
				}
			}
			if d.ID == 0 {
				continue
			}
			total++
			if other, dup := seen[d.ID]; dup {
				t.Errorf("id %d is in %s and %s", d.ID, other, f)
			}
			seen[d.ID] = f
		}
	}
	if total != 627 || updates != 55 {
		t.Errorf("%d rules with an id and %d target updates, want 627 and 55", total, updates)
	}
}

func TestParseUpdateTargetByID(t *testing.T) {
	ds := parseCRS(t, "rules/REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf")
	first := ds[0]
	wantVars := []Variable{{Collection: "REQUEST_COOKIES", Selector: `^_ga(?:_\w+)?$`, Regex: true, Exclude: true}}
	if first.Kind != KindUpdateTargetByID || first.TargetID != 932240 || first.ID != 0 || first.Pos.Line != 26 ||
		!reflect.DeepEqual(first.Variables, wantVars) {
		t.Errorf("first directive = %+v", first)
	}

	for _, src := range []string{
		`SecRuleUpdateTargetById 942100`,
		`SecRuleUpdateTargetById 942100 "!ARGS:a" "ARGS:b"`,
		`SecRuleUpdateTargetById 942100-942200 "!ARGS:a"`,
		`SecRuleUpdateTargetById abc "!ARGS:a"`,
		`SecRuleUpdateTargetById 942100 "!ARGS:"`,
	} {
		if _, err := Parse("test.conf", strings.NewReader(src)); err == nil {
			t.Errorf("no error for %s", src)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		line int
		msg  string
	}{
		{"unknown directive", "SecRuleEngine On\n", 1, "unsupported directive SecRuleEngine"},
		{"rule without id", `SecRule ARGS "@rx a" "phase:2,pass"` + "\n", 1, "SecRule has no id"},
		{"action without id", `SecAction "phase:1,pass"` + "\n", 1, "SecAction has no id"},
		{"id not a number", `SecAction "id:abc,phase:1"` + "\n", 1, "id must be a positive number"},
		{"duplicate id", "SecAction \"id:1\"\n\nSecAction \"id:1\"\n", 3, "id 1 is already used at line 1"},
		{"too few arguments", "SecRule ARGS\n", 1, "found 1 arguments"},
		{"open double quote", `SecRule ARGS "@rx a` + "\n", 1, "missing closing double quote"},
		{"open single quote", `SecAction "id:1,msg:'abc"` + "\n", 1, "missing closing single quote"},
		{"chain at end of file", `SecRule ARGS "@rx a" "id:1,chain"` + "\n", 1, "no SecRule follows"},
		{"chain followed by marker", "SecRule ARGS \"@rx a\" \"id:1,chain\"\nSecMarker X\n", 2, "must be followed by a SecRule"},
		{"id inside chain", "SecRule ARGS \"@rx a\" \"id:1,chain\"\nSecRule ARGS \"@rx b\" \"id:2\"\n", 2, "must not have its own id"},
		{"continuation at end of file", "SecAction \\\n    \"id:1,\\\n", 1, "file ends in the middle"},
		{"error after continuation", "# c\nSecAction \\\n    \"id:1\"\nSecFoo\n", 4, "unsupported directive SecFoo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("test.conf", strings.NewReader(tt.src))
			var perr *Error
			if !errors.As(err, &perr) {
				t.Fatalf("error = %v, want *Error", err)
			}
			if perr.Pos.Line != tt.line || !strings.Contains(perr.Msg, tt.msg) {
				t.Errorf("error = %q, want line %d containing %q", perr, tt.line, tt.msg)
			}
			if !strings.HasPrefix(perr.Error(), "test.conf:") {
				t.Errorf("error text %q does not start with the file name", perr.Error())
			}
		})
	}
}

func TestParseSmallExample(t *testing.T) {
	src := "# a comment \\\n" +
		"SecMarker \"SWALLOWED-BY-COMMENT\"\n" +
		"\n" +
		"secdefaultaction \"phase:2,log,pass\"\n" +
		"SecRule ARGS \\\n" +
		"    \"@rx a\\\"b\" \\\n" +
		"    \"id:10,\\\n" +
		"    phase:2,\\\n" +
		"    msg:'it\\'s, here'\"\n" +
		"SecMarker END"
	ds, err := Parse("test.conf", strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 3 {
		t.Fatalf("got %d directives, want 3: %+v", len(ds), ds)
	}
	if ds[0].Kind != KindDefaultAction || ds[0].Pos.Line != 4 {
		t.Errorf("first = %+v", ds[0])
	}
	rule := ds[1]
	if rule.Pos.Line != 5 || rule.ID != 10 || rule.Operator.Argument != `a"b` {
		t.Errorf("rule = %+v", rule)
	}
	if got := rule.ActionValues("MSG"); !reflect.DeepEqual(got, []string{"it's, here"}) {
		t.Errorf("msg = %q", got)
	}
	if ds[2].Kind != KindMarker || ds[2].Text != "END" || ds[2].Pos.Line != 10 {
		t.Errorf("marker = %+v", ds[2])
	}
}
