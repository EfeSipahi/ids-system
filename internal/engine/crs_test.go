package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/offline"
)

// These tests run the original CRS 4.30.0 files with the configuration of
// the first engine: detection rules 930100 and 930110 with their setup,
// gate and evaluation rules.

const firstEngineConfig = "../../configs/crs-first-engine.json"

// readConfig reads the engine settings of a configuration file. The
// product configuration also has a "records" section, which belongs to the
// parts around the engine and is read by package config (which imports
// this package, so these tests cannot use it). It is skipped here; every
// other unknown field is still an error.
func readConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var file struct {
		Config
		Records json.RawMessage `json:"records"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	cfg := file.Config
	if err := cfg.Prepare(filepath.Dir(path)); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func loadCRS(t *testing.T) *RuleSet {
	t.Helper()
	return loadCRSAt(t, DefaultParanoiaLevel)
}

// crsTestConfig is the configuration the CRS regression tests are written
// for: the product configuration plus rule 900005 of the CRS test setup,
// at paranoia level 4. See testdata/crs-test-setup.conf.
const crsTestConfig = "../../testdata/crs-tests.json"

// loadCRSAt loads the CRS rules at the given paranoia level.
func loadCRSAt(t *testing.T, level int) *RuleSet {
	t.Helper()
	return loadConfigAt(t, firstEngineConfig, level)
}

// loadConfigAt loads a configuration at the given paranoia level.
func loadConfigAt(t *testing.T, path string, level int) *RuleSet {
	t.Helper()
	cfg, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ParanoiaLevel = level
	rs, err := Load(cfg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rs
}

func loadExamples(t *testing.T, name string) []offline.Example {
	t.Helper()
	examples, err := offline.LoadFile("../../testdata/requests/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return examples
}

func contains(ids []int, id int) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestCRSStartupReport(t *testing.T) {
	rs := loadCRS(t)

	if rs.Signature() != "OWASP_CRS/4.30.0" {
		t.Errorf("signature = %q", rs.Signature())
	}

	// 1 rule in crs-setup, 33 in 901, 2 in 905, 9 in 911, 9 in 913, 68 in
	// 920, 26 in 921, 7 in 922, 14 in 930, 13 in 931, 56 in 932, 29 in 933, 22 in
	// 934, 42 in 941, 68 in 942, 11 in 943, 22 in 944 and 28 in 949: every
	// one has a status.
	statuses := rs.Statuses()
	if len(statuses) != 460 {
		t.Errorf("%d statuses, want 460", len(statuses))
	}
	if rs.ParanoiaLevel() != 1 {
		t.Errorf("paranoia level = %d, want the default 1", rs.ParanoiaLevel())
	}
	// Detection rules per level, counted from the tags in the CRS files:
	// 911 has 1; 913 has 1; 920 has 40, 9, 5 and 5; 921 has 11, 2, 3 and
	// 1; 922 has 4; 930 has 5 and 1; 931 has 3 and 2; 932 has 19, 19 and 10; 933 has
	// 13, 3 and 5; 934 has 8, 5 and 1; 941 has 26 and 7; 942 has 20, 31, 7
	// and 2; 943 has 3; 944 has 6, 6, 1 and 1.
	perLevel := map[int]int{}
	for _, s := range statuses {
		if s.ParanoiaLevel != 0 {
			perLevel[s.ParanoiaLevel]++
		}
	}
	if want := map[int]int{1: 160, 2: 85, 3: 32, 4: 9}; !reflect.DeepEqual(perLevel, want) {
		t.Errorf("detection rules per level = %v, want %v", perLevel, want)
	}
	// File 999 holds one update, for rule 932240 of file 932. That file is
	// loaded, so the update is applied and nothing is ignored.
	if got := rs.IgnoredTargetUpdates(); len(got) != 0 {
		t.Errorf("ignored target updates = %v", got)
	}
	var excluded []int
	byID := map[int]RuleStatus{}
	for _, s := range statuses {
		byID[s.ID] = s
		if !s.Active {
			excluded = append(excluded, s.ID)
			if s.Reason == "" {
				t.Errorf("rule %d is excluded without a reason", s.ID)
			}
		}
	}
	want := []int{901320, 901350, 901410, 901450}
	if !reflect.DeepEqual(excluded, want) {
		t.Errorf("excluded = %v\nwant       %v", excluded, want)
	}

	for _, id := range []int{930100, 930110} {
		s := byID[id]
		if !s.Active || s.Phase != 2 {
			t.Errorf("status of %d = %+v", id, s)
		}
	}
	// The other PL1 rules of file 930, and its one PL2 rule, which the
	// gate skips at level 1.
	for id, phase := range map[int]int{930120: 2, 930130: 1, 930140: 1, 930121: 1} {
		if s := byID[id]; !s.Active || s.Phase != phase {
			t.Errorf("status of %d = %+v", id, s)
		}
	}
	if s := byID[949110]; !s.Active {
		t.Errorf("status of 949110 = %+v", s)
	}
	// Each rule's msg as written in its file, a macro left as it is; an
	// excluded rule keeps its msg too, and a rule without one has "".
	for id, want := range map[int]string{
		942100: "SQL Injection Attack Detected via libinjection",
		920450: "HTTP header is restricted by policy (%{MATCHED_VAR})",
		901350: "Enabling forced body inspection for ASCII content",
		901320: "",
	} {
		if got := byID[id].Msg; got != want {
			t.Errorf("msg of %d = %q, want %q", id, got, want)
		}
	}
}

// A rule file with rules the engine cannot run must stop it from starting,
// with a message that names each rule and what it lacks. The file used here
// inspects responses, which is outside Phase 1.
func TestCRSUnsupportedRuleStopsLoading(t *testing.T) {
	cfg, err := readConfig(firstEngineConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Files = append(cfg.Files, "../../coreruleset-4.30.0/rules/RESPONSE-950-DATA-LEAKAGES.conf")

	_, err = Load(cfg)
	if err == nil {
		t.Fatal("Load succeeded with a response rule file")
	}
	for _, msg := range []string{
		"RESPONSE-950-DATA-LEAKAGES.conf:",
		"rule 950130: phase 4 is not supported",
		"rule 950130: variable RESPONSE_BODY is not supported",
	} {
		if !strings.Contains(err.Error(), msg) {
			t.Errorf("error does not contain %q:\n%v", msg, err)
		}
	}
	if strings.Contains(err.Error(), "rule 930") {
		t.Errorf("error mentions a supported rule:\n%v", err)
	}

	// Taking a rule off the exclusion list has the same effect.
	cfg, _ = readConfig(firstEngineConfig)
	var kept []Exclusion
	for _, ex := range cfg.Exclude {
		if ex.ID != 901320 {
			kept = append(kept, ex)
		}
	}
	cfg.Exclude = kept
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "REQUEST-901-INITIALIZATION.conf:363: rule 901320: action initcol is not supported on a chained rule") {
		t.Errorf("error = %v", err)
	}
}

func TestCRSNormalRequest(t *testing.T) {
	rs := loadCRS(t)
	res := rs.Evaluate(get("/arama?q=kitap&q=kalem", httpmodel.Header{Name: "Host", Value: "localhost"}))

	if len(res.Matches) != 0 {
		t.Errorf("matches = %+v, want none", res.Matches)
	}
	// What the setup rules of file 901 leave behind.
	wantVars(t, res, map[string]string{
		"crs_setup_version":               "4300",
		"inbound_anomaly_score_threshold": "5",
		"blocking_paranoia_level":         "1",
		"detection_paranoia_level":        "1",
		"critical_anomaly_score":          "5",
		"sampling_percentage":             "100",
		"inbound_anomaly_score_pl1":       "0",
		"inbound_anomaly_score_pl2":       "0",
		"lfi_score":                       "0",
		"blocking_inbound_anomaly_score":  "0",
		"detection_inbound_anomaly_score": "0",
	})
}

// One attack request followed step by step.
func TestCRSTraversalInQuery(t *testing.T) {
	rs := loadCRS(t)
	res := rs.Evaluate(get("/get?arg=../../../etc/passwd", httpmodel.Header{Name: "Host", Value: "localhost"}))

	type row struct {
		id      int
		varName string
		data    string
	}
	var got []row
	for _, m := range res.Matches {
		got = append(got, row{m.RuleID, m.VarName, m.Data})
	}
	want := []row{
		// 930100 looks at the values as received. Both the raw URI and
		// the argument contain "/../".
		{930100, "REQUEST_URI_RAW", "Matched Data: /../ found within REQUEST_URI_RAW: /get?arg=../../../etc/passwd"},
		{930100, "ARGS:arg", "Matched Data: /../ found within ARGS:arg: ../../../etc/passwd"},
		// 930110 accepts the start of a value in place of the first
		// separator, so in the argument it finds "../" at once.
		{930110, "REQUEST_URI_RAW", "Matched Data: /../ found within REQUEST_URI_RAW: /get?arg=../../../etc/passwd"},
		{930110, "ARGS:arg", "Matched Data: ../ found within ARGS:arg: ../../../etc/passwd"},
		// 930120 looks for the names of system files. It does not look
		// at the raw URI, only at parameters and cookies.
		{930120, "ARGS:arg", "Matched Data: etc/passwd found within ARGS:arg: ../../../etc/passwd"},
		// 932160, of the command execution rules, also knows
		// etc/passwd: as a file a shell command would read.
		{932160, "ARGS:arg", "Matched Data: etc/passwd found within ARGS:arg: ../../../etc/passwd"},
		{949110, "TX:BLOCKING_INBOUND_ANOMALY_SCORE", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matches:\n%v\nwant:\n%v", got, want)
	}

	first := res.Matches[0]
	if first.Message != "Path Traversal Attack (/../) or (/.../)" || first.Severity != "CRITICAL" ||
		first.Phase != 2 || first.Action != "pass" || !reflect.DeepEqual(first.Tags[3:5], []string{"attack-lfi", "paranoia-level/1"}) {
		t.Errorf("first match = %+v", first)
	}

	// Six matches of 5 points each; Coraza gives the same total. Rule
	// 949110 compares the total with the threshold of 5. Its deny is
	// recorded, not carried out.
	last := res.Matches[6]
	if last.Message != "Inbound Anomaly Score Exceeded (Total Score: 30)" || last.Action != "deny" || last.Value != "30" {
		t.Errorf("949110 match = %+v", last)
	}
	wantVars(t, res, map[string]string{
		"inbound_anomaly_score_pl1":       "30",
		"lfi_score":                       "25",
		"rce_score":                       "5",
		"blocking_inbound_anomaly_score":  "30",
		"detection_inbound_anomaly_score": "30",
		"inbound_anomaly_score_pl2":       "0",
	})
	if res.Score("lfi_score") != 25 || res.Score("no_such_variable") != 0 {
		t.Errorf("Score gave %d and %d", res.Score("lfi_score"), res.Score("no_such_variable"))
	}
}

// The hand-picked starter examples.
func TestCRSStarterExamples(t *testing.T) {
	rs := loadCRS(t)
	for _, ex := range loadExamples(t, "path-traversal.json") {
		t.Run(ex.Name, func(t *testing.T) {
			checkExample(t, rs, ex, DefaultParanoiaLevel)
		})
	}
}

// TestCRSRegression runs the converted CRS regression tests of the rule
// files that are finished: 911, 913, 930 to 934 and 941 to 944, at every
// paranoia level of their rules. Each test is named after one rule and says which rules
// must and must not match.
//
// The tests run at level 4, as the CRS project runs them: its test setup
// sets BLOCKING_PARANOIA to 4 (tests/docker-compose.yml). At that level
// every test must pass.
//
// They then run at levels 1 to 3 as a check of the levels themselves. A
// test whose rule belongs to the level or a lower one must still pass. A
// test of a rule above the level must not find that rule: the rule is
// switched off there.
func TestCRSRegression(t *testing.T) {
	files, err := filepath.Glob("../../testdata/requests/crs/*.json")
	if err != nil || len(files) != 290 {
		t.Fatalf("found %d test files (%v), want 290", len(files), err)
	}
	// The level of each rule, from the tags in the CRS files.
	levelOfRule := map[int]int{}
	for _, s := range loadCRS(t).Statuses() {
		levelOfRule[s.ID] = s.ParanoiaLevel
	}
	// File 944000 is named after no rule. Its one test is about rule
	// 944100 and a body of type text/plain.
	levelOfRule[944000] = levelOfRule[944100]

	for level := MaxParanoiaLevel; level >= 1; level-- {
		rs := loadConfigAt(t, crsTestConfig, level)
		total := 0
		for _, file := range files {
			name := strings.TrimSuffix(filepath.Base(file), ".json")
			ruleID, err := strconv.Atoi(name)
			if _, known := levelOfRule[ruleID]; err != nil || !known {
				t.Fatalf("%s is not named after a rule", file)
			}
			for _, ex := range loadExamples(t, "crs/"+filepath.Base(file)) {
				total++
				t.Run(fmt.Sprintf("PL%d/%s", level, ex.Name), func(t *testing.T) {
					// A body of a type that has no reader is not split into
					// fields; the rules see it as one text (REQUEST_BODY).
					// A broken body is read as far as it goes. Ten CRS
					// tests send one on purpose, and they must still pass;
					// if a test with a broken body fails, the reason is
					// named.
					if !ex.Request.Status.Body.Complete() && ex.Request.Status.BodyFormat != "" {
						if !brokenBodies[testID(ex.Name)] {
							t.Errorf("unexpected broken body: %s", ex.Request.Status.BodyReason)
						}
						defer func() {
							if t.Failed() {
								t.Logf("the body was not read to its end: %s", ex.Request.Status.BodyReason)
							}
						}()
					}
					if levelOfRule[ruleID] > level {
						if ids := rs.Evaluate(ex.Request).MatchedIDs(); contains(ids, ruleID) {
							t.Errorf("rule %d of level %d matched at level %d", ruleID, levelOfRule[ruleID], level)
						}
						return
					}
					checkExample(t, rs, ex, level)
				})
			}
		}
		// 18 tests in file 901, 8 in 911, 9 in 913, 407 in 920, 116 in
		// 921, 47 in 922, 83 in 930, 42 in 931, 1,089 in 932, 442 in 933,
		// 287 in 934, 263 in 941, 1,033 in 942, 47 in 943, 1,176 in 944 and
		// 5 in 949, counted from the converted files: every CRS request
		// test that an offline engine can check.
		if total != 5072 {
			t.Errorf("%d tests, want 5072", total)
		}
	}
}

// brokenBodies are the CRS tests that send a body that cannot be read to
// its end, on purpose, by test id.
var brokenBodies = map[string]bool{
	"920240-4": true, // XML that is not well-formed
	"920400-1": true, // a multipart part without an empty line after its headers
	"920400-2": true, // the same
	"920420-9": true, // JSON that is not valid
	"922130-1": true, // a multipart header name with a character outside 33 to 126
	"922130-2": true, // the same
	"922130-5": true, // a header name with "!", which Go's reader does not allow
	"922130-7": true, // a header name with DEL
	"922130-8": true, // multipart parts without headers
	"932180-3": true, // a multipart part without headers
}

// testID returns "922130-1" for a test named "CRS 922130-1: ...".
func testID(name string) string {
	id, _, _ := strings.Cut(strings.TrimPrefix(name, "CRS "), ":")
	return id
}

// checkExample runs one example and compares the result with what the
// example expects.
func checkExample(t *testing.T, rs *RuleSet, ex offline.Example, level int) {
	t.Helper()
	res := rs.Evaluate(ex.Request)
	ids := res.MatchedIDs()
	for _, id := range ex.ExpectIDs {
		if !contains(ids, id) {
			t.Errorf("rule %d did not match; matched: %v", id, ids)
		}
	}
	for _, id := range ex.NoExpectIDs {
		if contains(ids, id) {
			t.Errorf("rule %d matched but must not; matches: %+v", id, res.Matches)
		}
	}
	logged := func(pattern *regexp.Regexp) bool {
		return slices.ContainsFunc(res.LogLines(), pattern.MatchString)
	}
	if ex.ExpectLog != nil && !logged(ex.ExpectLog) {
		t.Errorf("no log line has %q; lines: %q", ex.ExpectLog, res.LogLines())
	}
	if ex.NoExpectLog != nil && logged(ex.NoExpectLog) {
		t.Errorf("a log line has %q", ex.NoExpectLog)
	}
	// The scoring must agree with the matches: a request with a detection
	// has a score, one without has none, and rule 949110 reports exactly
	// the requests whose score reaches the threshold. A detection alone
	// does not always reach it: some rules of levels 2 to 4 add 3, and the
	// threshold is 5.
	detected := false
	for _, id := range ids {
		if id/1000 >= 911 && id/1000 <= 944 {
			detected = true
		}
	}
	score := 0
	for pl := 1; pl <= level; pl++ {
		score += res.Score(fmt.Sprintf("inbound_anomaly_score_pl%d", pl))
	}
	threshold := res.Score("inbound_anomaly_score_threshold")
	if detected != (score > 0) || contains(ids, 949110) != (score >= threshold) || threshold != 5 {
		t.Errorf("matched %v with score %d, threshold %d", ids, score, threshold)
	}
}

// M21: requests share the prepared rules and nothing else. An attack must
// not leave anything behind for the next request, in sequence or in
// parallel. Run with -race.
func TestCRSRequestsDoNotShareState(t *testing.T) {
	rs := loadCRS(t)
	host := httpmodel.Header{Name: "Host", Value: "localhost"}
	attack := get("/get?arg=../../../etc/passwd", host)
	normal := get("/arama?q=kitap", host)

	summary := func(res *Result) string {
		return fmt.Sprintf("%v pl1=%s lfi=%s total=%s", res.MatchedIDs(), res.Variables["inbound_anomaly_score_pl1"], res.Variables["lfi_score"], res.Variables["blocking_inbound_anomaly_score"])
	}
	const wantAttack = "[930100 930110 930120 932160 949110] pl1=30 lfi=25 total=30"
	const wantNormal = "[] pl1=0 lfi=0 total=0"

	for i := 0; i < 3; i++ {
		if got := summary(rs.Evaluate(attack)); got != wantAttack {
			t.Fatalf("attack, round %d: %s", i, got)
		}
		if got := summary(rs.Evaluate(normal)); got != wantNormal {
			t.Fatalf("normal after attack, round %d: %s", i, got)
		}
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			req, want := attack, wantAttack
			if g%2 == 1 {
				req, want = normal, wantNormal
			}
			for i := 0; i < 200; i++ {
				if got := summary(rs.Evaluate(req)); got != want {
					t.Errorf("goroutine %d: %s, want %s", g, got, want)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// The requests themselves are untouched.
	if attack.Received.Target != "/get?arg=../../../etc/passwd" || attack.Parsed.Query[0].Value != "../../../etc/passwd" {
		t.Errorf("the request was changed: %+v", attack)
	}
}
