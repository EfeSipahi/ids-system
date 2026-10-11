package engine

import (
	"fmt"
	"path/filepath"
	"reflect"
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

func loadCRS(t *testing.T) *RuleSet {
	t.Helper()
	cfg, err := LoadConfig(firstEngineConfig)
	if err != nil {
		t.Fatal(err)
	}
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

	// 1 rule in crs-setup, 33 in 901, 14 in 930, 42 in 941, 68 in 942 and
	// 28 in 949: every one has a status.
	statuses := rs.Statuses()
	if len(statuses) != 186 {
		t.Errorf("%d statuses, want 186", len(statuses))
	}
	// File 999 holds one update for a rule of file 932, which is not
	// loaded.
	if got := rs.IgnoredTargetUpdates(); !reflect.DeepEqual(got, []int{932240}) {
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
	want := []int{901320, 901340, 901350, 901360, 901370, 901410, 901450}
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
}

// A rule file with rules the engine cannot run must stop it from starting,
// with a message that names each rule and what it lacks. The file used here
// inspects responses, which is outside Phase 1.
func TestCRSUnsupportedRuleStopsLoading(t *testing.T) {
	cfg, err := LoadConfig(firstEngineConfig)
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
	cfg, _ = LoadConfig(firstEngineConfig)
	var kept []Exclusion
	for _, ex := range cfg.Exclude {
		if ex.ID != 901340 {
			kept = append(kept, ex)
		}
	}
	cfg.Exclude = kept
	if _, err := Load(cfg); err == nil || !strings.Contains(err.Error(), "REQUEST-901-INITIALIZATION.conf:375: rule 901340: variable REQBODY_PROCESSOR is not supported") {
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

	// Five matches of 5 points each. Rule 949110 compares the total with
	// the threshold of 5. Its deny is recorded, not carried out.
	last := res.Matches[5]
	if last.Message != "Inbound Anomaly Score Exceeded (Total Score: 25)" || last.Action != "deny" || last.Value != "25" {
		t.Errorf("949110 match = %+v", last)
	}
	wantVars(t, res, map[string]string{
		"inbound_anomaly_score_pl1":       "25",
		"lfi_score":                       "25",
		"blocking_inbound_anomaly_score":  "25",
		"detection_inbound_anomaly_score": "25",
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
			checkExample(t, rs, ex)
		})
	}
}

// The acceptance check: the CRS regression tests of every PL1 rule in scope,
// converted by tools/convert_crs_tests.py. Each request must be read
// completely, every rule a test expects must match, and no rule it forbids
// may match.
func TestCRSRegression(t *testing.T) {
	rs := loadCRS(t)
	files, err := filepath.Glob("../../testdata/requests/crs/*.json")
	if err != nil || len(files) != 51 {
		t.Fatalf("found %d test files (%v), want 51", len(files), err)
	}
	total := 0
	for _, file := range files {
		for _, ex := range loadExamples(t, "crs/"+filepath.Base(file)) {
			total++
			t.Run(ex.Name, func(t *testing.T) {
				if !ex.Request.Status.Body.Complete() {
					t.Fatalf("the body was not read completely: %s", ex.Request.Status.BodyReason)
				}
				checkExample(t, rs, ex)
			})
		}
	}
	if total != 687 {
		t.Errorf("%d tests, want 687", total)
	}
}

// checkExample runs one example and compares the matched rules with what
// the example expects.
func checkExample(t *testing.T, rs *RuleSet, ex offline.Example) {
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
	// A detection always reaches the threshold, and a request with no
	// detection has no score.
	detected := false
	for _, id := range ids {
		switch id / 1000 {
		case 930, 941, 942:
			detected = true
		}
	}
	if detected != contains(ids, 949110) || detected != (res.Score("inbound_anomaly_score_pl1") >= 5) {
		t.Errorf("matched %v with score %d", ids, res.Score("inbound_anomaly_score_pl1"))
	}
}

// M21: requests share the prepared rules and nothing else. An attack must
// not leave anything behind for the next request, in sequence or in
// parallel. Run with -race.
func TestCRSRequestsDoNotShareState(t *testing.T) {
	rs := loadCRS(t)
	attack := get("/get?arg=../../../etc/passwd")
	normal := get("/arama?q=kitap")

	summary := func(res *Result) string {
		return fmt.Sprintf("%v pl1=%s lfi=%s total=%s", res.MatchedIDs(), res.Variables["inbound_anomaly_score_pl1"], res.Variables["lfi_score"], res.Variables["blocking_inbound_anomaly_score"])
	}
	const wantAttack = "[930100 930110 930120 949110] pl1=25 lfi=25 total=25"
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
