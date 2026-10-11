package seclang

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{``, nil},
		{`ARGS "@rx a b" "id:1,phase:2"`, []string{"ARGS", "@rx a b", "id:1,phase:2"}},
		{"  ARGS\t\"@eq 0\"  ", []string{"ARGS", "@eq 0"}},
		{`"say \"hi\""`, []string{`say "hi"`}},
		{`"[/;\x5c]\."`, []string{`[/;\x5c]\.`}},
		{`"a\\" b`, []string{`a\\`, "b"}},
		{`""`, []string{""}},
	}
	for _, tt := range tests {
		got, err := splitArgs(tt.in)
		if err != nil {
			t.Errorf("splitArgs(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitArgs(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{`"abc`, `"abc"def`, `"abc\"`} {
		if _, err := splitArgs(in); err == nil {
			t.Errorf("splitArgs(%q): no error", in)
		}
	}
}

func TestParseVariables(t *testing.T) {
	tests := []struct {
		in   string
		want []Variable
	}{
		{"ARGS", []Variable{{Collection: "ARGS"}}},
		{"args_names", []Variable{{Collection: "ARGS_NAMES"}}},
		{"REQUEST_HEADERS:User-Agent", []Variable{{Collection: "REQUEST_HEADERS", Selector: "User-Agent"}}},
		{"&TX:crs_setup_version", []Variable{{Collection: "TX", Selector: "crs_setup_version", Count: true}}},
		{
			"ARGS|!REQUEST_HEADERS:Referer",
			[]Variable{{Collection: "ARGS"}, {Collection: "REQUEST_HEADERS", Selector: "Referer", Exclude: true}},
		},
		{
			"XML:/*|XML://@*",
			[]Variable{{Collection: "XML", Selector: "/*"}, {Collection: "XML", Selector: "//@*"}},
		},
		{
			// A regular expression selector may contain "|" and "\/".
			`!REQUEST_COOKIES:/^(?:_ga|_gid)\/x$/|ARGS`,
			[]Variable{
				{Collection: "REQUEST_COOKIES", Selector: `^(?:_ga|_gid)\/x$`, Regex: true, Exclude: true},
				{Collection: "ARGS"},
			},
		},
		{
			`TX:/^header_name_920450_/`,
			[]Variable{{Collection: "TX", Selector: "^header_name_920450_", Regex: true}},
		},
	}
	for _, tt := range tests {
		got, err := parseVariables(tt.in)
		if err != nil {
			t.Errorf("parseVariables(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseVariables(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"", "|ARGS", "ARGS|", "ARGS||TX", "ARGS:", "ARGS:|TX", "!", "AR GS", "ARGS:/abc", "ARGS://"} {
		if got, err := parseVariables(in); err == nil {
			t.Errorf("parseVariables(%q) = %+v, want an error", in, got)
		}
	}
}

func TestVariableString(t *testing.T) {
	for _, in := range []string{"ARGS", "!REQUEST_HEADERS:Referer", "&TX:x", "TX:/^a|b$/", "XML://@*"} {
		vars, err := parseVariables(in)
		if err != nil {
			t.Fatalf("parseVariables(%q): %v", in, err)
		}
		if got := vars[0].String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
	}
}

func TestParseOperator(t *testing.T) {
	tests := []struct {
		in   string
		want Operator
	}{
		{"@rx ^a b$", Operator{Name: "rx", Argument: "^a b$"}},
		{"@eq 0", Operator{Name: "eq", Argument: "0"}},
		{"!@lt %{tx.sampling_percentage}", Operator{Name: "lt", Argument: "%{tx.sampling_percentage}", Negated: true}},
		{"@unconditionalMatch", Operator{Name: "unconditionalMatch"}},
		{"@pmFromFile lfi-os-files.data", Operator{Name: "pmFromFile", Argument: "lfi-os-files.data"}},
		{"@rx   spaced ", Operator{Name: "rx", Argument: "spaced "}},
		{"^plain$", Operator{Name: "rx", Argument: "^plain$"}},
		{"!^plain$", Operator{Name: "rx", Argument: "^plain$", Negated: true}},
		{"", Operator{Name: "rx"}},
	}
	for _, tt := range tests {
		got, err := parseOperator(tt.in)
		if err != nil {
			t.Errorf("parseOperator(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseOperator(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"@", "@ rx a", "@rx-x a"} {
		if got, err := parseOperator(in); err == nil {
			t.Errorf("parseOperator(%q) = %+v, want an error", in, got)
		}
	}
	if got := (Operator{Name: "lt", Argument: "2", Negated: true}).String(); got != "!@lt 2" {
		t.Errorf("String() = %q", got)
	}
}

func TestParseActions(t *testing.T) {
	tests := []struct {
		in   string
		want []Action
	}{
		{"pass", []Action{{Name: "pass"}}},
		{
			"id:930011,phase:1,pass,nolog",
			[]Action{{Name: "id", Value: "930011"}, {Name: "phase", Value: "1"}, {Name: "pass"}, {Name: "nolog"}},
		},
		{
			// As the text looks after continuation lines are joined.
			"id:1,    phase:2,    t:none,t:urlDecodeUni",
			[]Action{{Name: "id", Value: "1"}, {Name: "phase", Value: "2"}, {Name: "t", Value: "none"}, {Name: "t", Value: "urlDecodeUni"}},
		},
		{
			"msg:'a, b: c',tag:'OWASP_CRS'",
			[]Action{{Name: "msg", Value: "a, b: c"}, {Name: "tag", Value: "OWASP_CRS"}},
		},
		{
			`msg:'lama\'s\'hell web shell'`,
			[]Action{{Name: "msg", Value: "lama's'hell web shell"}},
		},
		{
			"setvar:tx.crs_setup_version=4300",
			[]Action{{Name: "setvar", Value: "tx.crs_setup_version=4300"}},
		},
		{
			"setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}',skipAfter:END-SAMPLING",
			[]Action{{Name: "setvar", Value: "tx.lfi_score=+%{tx.critical_anomaly_score}"}, {Name: "skipAfter", Value: "END-SAMPLING"}},
		},
		{
			"initcol:ip=%{remote_addr}_%{MATCHED_VAR}",
			[]Action{{Name: "initcol", Value: "ip=%{remote_addr}_%{MATCHED_VAR}"}},
		},
	}
	for _, tt := range tests {
		got, err := parseActions(tt.in)
		if err != nil {
			t.Errorf("parseActions(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseActions(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"", "  ", "pass,", ",pass", "pass,,log", "msg:'abc", "msg:'abc'x", ":1", "a b"} {
		if got, err := parseActions(in); err == nil {
			t.Errorf("parseActions(%q) = %+v, want an error", in, got)
		}
	}
}

func TestReadLogicalLines(t *testing.T) {
	src := "\n" +
		"# comment\n" +
		"   # indented comment\n" +
		"SecMarker A\r\n" +
		"SecAction \\\n" +
		"    \"id:1,\\\n" +
		"    pass\"\n" +
		"\n" +
		"SecMarker B"
	got, err := readLogicalLines(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []logicalLine{
		{text: "SecMarker A", line: 4},
		{text: "SecAction     \"id:1,    pass\"", line: 5},
		{text: "SecMarker B", line: 9},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}
