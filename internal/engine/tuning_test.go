package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/offline"
)

// The tests of this file check option B of decision F5 (main plan, section
// 11.25): an application's exceptions applied per request on one shared
// rule set must give exactly what CRS's configure-time way gives, a rule
// set loaded with the same exceptions written in SecLang.

// testSpec holds every kind of exception: settings, skipped variables
// (on a rule with exclusions of its own, on the start of a chain, and one
// that changes nothing) and rules off, on files and levels of all kinds.
func testSpec(level int) TuningSpec {
	return TuningSpec{
		ParanoiaLevel: level,
		Settings: map[string]string{
			"crs_validate_utf8_encoding":  "0",
			"restricted_headers_extended": "",
			"arg_length":                  "50",
			"allowed_methods":             "GET POST",
		},
		Skips: map[int][]string{
			932350: {"ARGS_NAMES:pwd", "ARGS_NAMES:id"},
			942100: {"ARGS"},
			941100: {"REQUEST_HEADERS:User-Agent", "REQUEST_COOKIES:/^x/"},
			920340: {"REQUEST_HEADERS:Content-Length"},
			920230: {"REQUEST_COOKIES:a"},
		},
		Off: []int{930120, 920180, 942200, 932236},
	}
}

// The same exceptions as SecLang: a SecAction before CRS's setup rules,
// SecRuleUpdateTargetById after the rule files, and the configuration's
// exclude list.
const testSetupConf = `SecAction "id:9100001,phase:1,pass,nolog,setvar:tx.crs_validate_utf8_encoding=0,setvar:'tx.restricted_headers_extended=',setvar:tx.arg_length=50,setvar:'tx.allowed_methods=GET POST'"
`

const testUpdatesConf = `SecRuleUpdateTargetById 932350 "!ARGS_NAMES:pwd|!ARGS_NAMES:id"
SecRuleUpdateTargetById 942100 "!ARGS"
SecRuleUpdateTargetById 941100 "!REQUEST_HEADERS:User-Agent|!REQUEST_COOKIES:/^x/"
SecRuleUpdateTargetById 920340 "!REQUEST_HEADERS:Content-Length"
SecRuleUpdateTargetById 920230 "!REQUEST_COOKIES:a"
`

// loadConfigureTime loads the product configuration at a level with the
// exceptions of testSpec written in SecLang.
func loadConfigureTime(t testing.TB, level int) *RuleSet {
	t.Helper()
	cfg, err := readConfig(firstEngineConfig)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	setup, updates := filepath.Join(dir, "setup.conf"), filepath.Join(dir, "updates.conf")
	if err := os.WriteFile(setup, []byte(testSetupConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(updates, []byte(testUpdatesConf), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.Files[0], "crs-setup.conf.example") {
		t.Fatalf("the first file is %s, want the CRS setup file", cfg.Files[0])
	}
	cfg.Files = append([]string{cfg.Files[0], setup}, append(cfg.Files[1:], updates)...)
	for _, id := range testSpec(level).Off {
		cfg.Exclude = append(cfg.Exclude, Exclusion{ID: id, Reason: "test"})
	}
	cfg.ParanoiaLevel = level
	rs, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// outcome is everything a result says, apart from the configure-time
// SecAction, which only exists on one side.
func outcome(res *Result) string {
	var b strings.Builder
	for _, m := range res.Matches {
		if m.RuleID == 9100001 {
			continue
		}
		fmt.Fprintf(&b, "%d %s %q %q %q|", m.RuleID, m.VarName, m.Value, m.Data, m.Message)
	}
	names := make([]string, 0, len(res.Variables))
	for name := range res.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%q,", name, res.Variables[name])
	}
	return b.String()
}

// matchesOf lists the rules that matched and where.
func matchesOf(res *Result) string {
	var b strings.Builder
	for _, m := range res.Matches {
		fmt.Fprintf(&b, "%d %s|", m.RuleID, m.VarName)
	}
	return b.String()
}

func crsExamples(t testing.TB) []offline.Example {
	t.Helper()
	files, err := filepath.Glob("../../testdata/requests/crs/*.json")
	if err != nil || len(files) != 290 {
		t.Fatalf("found %d test files (%v), want 290", len(files), err)
	}
	var all []offline.Example
	for _, file := range files {
		examples, err := offline.LoadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, examples...)
	}
	if len(all) != 5072 {
		t.Fatalf("%d examples, want 5072", len(all))
	}
	return all
}

// TestTuningEqualsConfigureTimeExclusions runs all 5,072 CRS tests at every
// level through both ways. The shared rule set is loaded at level 1 and
// the tuning sets the level, so this also checks a level per application
// (F11).
func TestTuningEqualsConfigureTimeExclusions(t *testing.T) {
	examples := crsExamples(t)
	shared := loadCRSAt(t, 1)
	for level := 1; level <= MaxParanoiaLevel; level++ {
		t.Run(fmt.Sprintf("PL%d", level), func(t *testing.T) {
			t.Parallel()
			configured := loadConfigureTime(t, level)
			plain := loadCRSAt(t, level)
			tuning, _, err := shared.NewTuning(testSpec(level))
			if err != nil {
				t.Fatal(err)
			}
			changed := 0
			for _, ex := range examples {
				want := outcome(configured.Evaluate(ex.Request))
				got := outcome(shared.EvaluateWith(ex.Request, tuning))
				if got != want {
					t.Errorf("%s: per request\n%s\nconfigure time\n%s", ex.Name, got, want)
				}
				if matchesOf(shared.EvaluateWith(ex.Request, tuning)) != matchesOf(plain.Evaluate(ex.Request)) {
					changed++
				}
			}
			// The exceptions must matter, or the comparison shows nothing.
			if changed == 0 {
				t.Error("the exceptions changed no result")
			}
			t.Logf("level %d: the exceptions changed the matches of %d of %d tests; both ways agree on all", level, changed, len(examples))
		})
	}
}

// TestTuningOfOneApplicationDoesNotReachAnother sends requests of two
// applications at once through one rule set: X with exceptions, Y with
// none. Y's results must equal plain Evaluate, and X's the configure-time
// rules.
func TestTuningOfOneApplicationDoesNotReachAnother(t *testing.T) {
	examples := crsExamples(t)
	shared := loadCRSAt(t, 1)
	x, _, err := shared.NewTuning(testSpec(1))
	if err != nil {
		t.Fatal(err)
	}
	y, _, err := shared.NewTuning(TuningSpec{})
	if err != nil {
		t.Fatal(err)
	}
	configured := loadConfigureTime(t, 1)
	wantX := make([]string, len(examples))
	wantY := make([]string, len(examples))
	for i, ex := range examples {
		wantX[i] = outcome(configured.Evaluate(ex.Request))
		wantY[i] = outcome(shared.Evaluate(ex.Request))
	}

	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := g; i < len(examples); i += 8 {
				// Even goroutines start with X and odd ones with Y, so
				// the two applications are always mixed.
				order := []*Tuning{x, y}
				if g%2 == 1 {
					order = []*Tuning{y, x}
				}
				for _, tuning := range order {
					want := wantY
					if tuning == x {
						want = wantX
					}
					if got := outcome(shared.EvaluateWith(examples[i].Request, tuning)); got != want[i] {
						select {
						case errs <- fmt.Sprintf("%s: application %p got another result", examples[i].Name, tuning):
						default:
						}
					}
				}
				if got := outcome(shared.EvaluateWith(examples[i].Request, nil)); got != wantY[i] {
					select {
					case errs <- examples[i].Name + ": no application got another result":
					default:
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestNewTuningErrors(t *testing.T) {
	rs := loadCRS(t)
	for _, tc := range []struct {
		name string
		spec TuningSpec
		want string
	}{
		{"unknown rule", TuningSpec{Off: []int{999999}}, "rule 999999 is not an active rule"},
		{"excluded rule", TuningSpec{Skips: map[int][]string{901320: {"ARGS"}}}, "rule 901320 is not an active rule"},
		{"bad variable", TuningSpec{Skips: map[int][]string{942100: {"ARGS:"}}}, `rule 942100, variable "ARGS:"`},
		{"unknown collection", TuningSpec{Skips: map[int][]string{942100: {"NOT_A_VARIABLE"}}}, "variable NOT_A_VARIABLE is not supported"},
		{"exclusion mark", TuningSpec{Skips: map[int][]string{942100: {"!ARGS:id"}}}, "write the variable without !"},
		{"count", TuningSpec{Skips: map[int][]string{942100: {"&ARGS"}}}, "a count (&) cannot be skipped"},
		{"two variables", TuningSpec{Skips: map[int][]string{942100: {"ARGS:a|ARGS:b"}}}, "one variable per entry"},
		{"level", TuningSpec{ParanoiaLevel: 5}, "paranoia level 5 is not supported"},
		{"setting name", TuningSpec{Settings: map[string]string{"Arg-Length": "5"}}, `setting "Arg-Length"`},
		{"level as setting", TuningSpec{Settings: map[string]string{"blocking_paranoia_level": "4"}}, "give the paranoia level as the level"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := rs.NewTuning(tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// TestNewTuningSettingThatARuleOverwrites uses the CRS test configuration,
// whose rule 900005 sets crs_validate_utf8_encoding during each request.
func TestNewTuningSettingThatARuleOverwrites(t *testing.T) {
	rs := loadConfigAt(t, crsTestConfig, 1)
	_, _, err := rs.NewTuning(TuningSpec{Settings: map[string]string{"crs_validate_utf8_encoding": "0"}})
	want := "setting crs_validate_utf8_encoding: rule 900005 (crs-test-setup.conf:"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v, want one containing %q", err, want)
	}
	// CRS's own default rule fills the same setting only when it is
	// missing; that one is not an overwrite.
	if _, _, err := loadCRS(t).NewTuning(TuningSpec{Settings: map[string]string{"crs_validate_utf8_encoding": "0"}}); err != nil {
		t.Errorf("product configuration: %v", err)
	}
}

func TestNewTuningNotes(t *testing.T) {
	_, notes, err := loadCRS(t).NewTuning(testSpec(1))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rule 920230 does not look at REQUEST_COOKIES, so skipping REQUEST_COOKIES:a changes nothing"}
	if !reflect.DeepEqual(notes, want) {
		t.Errorf("notes %q, want %q", notes, want)
	}
}

func TestTuningLevelAndEmptySpec(t *testing.T) {
	rs := loadCRS(t)
	empty, _, err := rs.NewTuning(TuningSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if empty.ParanoiaLevel() != 1 || empty.excludes != nil || empty.off != nil {
		t.Errorf("an empty spec: level %d, tables %v %v", empty.ParanoiaLevel(), empty.excludes != nil, empty.off != nil)
	}
	four, _, err := rs.NewTuning(TuningSpec{ParanoiaLevel: 4})
	if err != nil {
		t.Fatal(err)
	}
	res := rs.EvaluateWith(httpmodel.New(httpmodel.Received{Method: "GET", Target: "/", Headers: []httpmodel.Header{{Name: "Host", Value: "a"}}}), four)
	if got := res.Variables["detection_paranoia_level"]; got != "4" {
		t.Errorf("detection_paranoia_level %q, want 4", got)
	}
}

// TestTuningTiming compares the request time of the two ways in turns, so
// that heat and clock changes of the machine hit both alike. It is slow and
// depends on the machine, so it only runs with IDS_TIMING set:
//
//	IDS_TIMING=1 go test -run TestTuningTiming -v ./internal/engine/
//
// IDS_TIMING=control compares two configure-time rule sets loaded the same
// way instead. That shows how far apart two equal rule sets measure on the
// machine, which the real comparison has to be read against.
func TestTuningTiming(t *testing.T) {
	mode := os.Getenv("IDS_TIMING")
	if mode == "" {
		t.Skip("set IDS_TIMING=1 or IDS_TIMING=control")
	}
	for _, level := range []int{1, 4} {
		configured := loadConfigureTime(t, level)
		shared := loadCRSAt(t, 1)
		tuning, _, err := shared.NewTuning(testSpec(level))
		if err != nil {
			t.Fatal(err)
		}
		other := loadConfigureTime(t, level)
		for _, name := range []string{"normal GET", "normal POST form", "normal POST json", "attack GET", "large POST form"} {
			rec := benchRequests()[name]
			runA := func() { configured.Evaluate(httpmodel.New(rec)) }
			runB := func() { shared.EvaluateWith(httpmodel.New(rec), tuning) }
			if mode == "control" {
				runB = func() { other.Evaluate(httpmodel.New(rec)) }
			}
			start := time.Now()
			runA()
			k := int(40*time.Millisecond/time.Since(start)) + 1
			block := func(f func()) float64 {
				runtime.GC()
				s := time.Now()
				for i := 0; i < k; i++ {
					f()
				}
				return float64(time.Since(s).Nanoseconds()) / float64(k)
			}
			var ratios []float64
			for r := 0; r < 40; r++ {
				if r%2 == 0 {
					a, b := block(runA), block(runB)
					ratios = append(ratios, b/a)
				} else {
					b, a := block(runB), block(runA)
					ratios = append(ratios, b/a)
				}
			}
			sort.Float64s(ratios)
			t.Logf("level %d %-17s per request / configure time: median %+.2f %% (middle half %+.2f .. %+.2f %%)",
				level, name, 100*(ratios[20]-1), 100*(ratios[10]-1), 100*(ratios[30]-1))
		}
	}
}
