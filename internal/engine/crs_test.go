package engine

import (
	"fmt"
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
	if got := rs.NotInspected(); !reflect.DeepEqual(got, []string{"FILES", "XML"}) {
		t.Errorf("not inspected = %v", got)
	}

	// 1 rule in crs-setup, 33 in 901, 14 in 930 and 28 in 949: every one
	// has a status.
	statuses := rs.Statuses()
	if len(statuses) != 76 {
		t.Errorf("%d statuses, want 76", len(statuses))
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
	want := []int{901320, 901340, 901350, 901360, 901370, 901410, 901450, 930120, 930130, 930140, 930121}
	if !reflect.DeepEqual(excluded, want) {
		t.Errorf("excluded = %v\nwant       %v", excluded, want)
	}

	for _, id := range []int{930100, 930110} {
		s := byID[id]
		if !s.Active || s.Phase != 2 || !reflect.DeepEqual(s.NotInspected, []string{"FILES", "XML"}) {
			t.Errorf("status of %d = %+v", id, s)
		}
	}
	if s := byID[949110]; !s.Active || s.NotInspected != nil {
		t.Errorf("status of 949110 = %+v", s)
	}
}

// Taking a rule off the exclusion list must stop the engine from starting,
// with a message that names the rule and what it lacks.
func TestCRSUnsupportedRuleStopsLoading(t *testing.T) {
	cfg, err := LoadConfig(firstEngineConfig)
	if err != nil {
		t.Fatal(err)
	}
	var kept []Exclusion
	for _, ex := range cfg.Exclude {
		if ex.ID != 930120 {
			kept = append(kept, ex)
		}
	}
	cfg.Exclude = kept

	_, err = Load(cfg)
	if err == nil {
		t.Fatal("Load succeeded with rule 930120 active")
	}
	for _, msg := range []string{
		"REQUEST-930-APPLICATION-ATTACK-LFI.conf:104: rule 930120: operator @pmFromFile is not supported",
		`rule 930120: transformation "normalizePathWin" is not supported`,
		"rule 930120: variable REQUEST_COOKIES is not supported",
	} {
		if !strings.Contains(err.Error(), msg) {
			t.Errorf("error does not contain %q:\n%v", msg, err)
		}
	}
	if strings.Contains(err.Error(), "rule 930110") {
		t.Errorf("error mentions a supported rule:\n%v", err)
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

	// Four matches of 5 points each. Rule 949110 compares the total with
	// the threshold of 5. Its deny is recorded, not carried out.
	last := res.Matches[4]
	if last.Message != "Inbound Anomaly Score Exceeded (Total Score: 20)" || last.Action != "deny" || last.Value != "20" {
		t.Errorf("949110 match = %+v", last)
	}
	wantVars(t, res, map[string]string{
		"inbound_anomaly_score_pl1":       "20",
		"lfi_score":                       "20",
		"blocking_inbound_anomaly_score":  "20",
		"detection_inbound_anomaly_score": "20",
		"inbound_anomaly_score_pl2":       "0",
	})
	if res.Score("lfi_score") != 20 || res.Score("no_such_variable") != 0 {
		t.Errorf("Score gave %d and %d", res.Score("lfi_score"), res.Score("no_such_variable"))
	}
}

// The acceptance check of the first engine: the expectations in the example
// files, which for the crs-930 file come from the CRS regression tests.
func TestCRSExamples(t *testing.T) {
	rs := loadCRS(t)
	for _, file := range []string{"path-traversal.json", "crs-930-regression.json"} {
		examples := loadExamples(t, file)
		expected, forbidden := 0, 0
		for _, ex := range examples {
			t.Run(ex.Name, func(t *testing.T) {
				if ex.Request.Status.Body == httpmodel.BodyNotInspected {
					t.Fatalf("the body is not inspected: %s", ex.Request.Status.BodyReason)
				}
				res := rs.Evaluate(ex.Request)
				ids := res.MatchedIDs()
				for _, id := range ex.ExpectIDs {
					expected++
					if !contains(ids, id) {
						t.Errorf("rule %d did not match; matched: %v", id, ids)
					}
				}
				for _, id := range ex.NoExpectIDs {
					forbidden++
					if contains(ids, id) {
						t.Errorf("rule %d matched but must not; matches: %+v", id, res.Matches)
					}
				}
				// A detection always reaches the threshold, and a
				// request with no detection has no score.
				detected := contains(ids, 930100) || contains(ids, 930110)
				if detected != contains(ids, 949110) || detected != (res.Score("inbound_anomaly_score_pl1") >= 5) {
					t.Errorf("matched %v with score %d", ids, res.Score("inbound_anomaly_score_pl1"))
				}
			})
		}
		if expected == 0 || forbidden == 0 {
			t.Errorf("%s: %d expected and %d forbidden ids were checked", file, expected, forbidden)
		}
	}
}

// These CRS regression tests carry their payload in an XML or multipart
// body. The engine does not parse those yet, so it cannot find the payload.
// The test pins that down: the request must say that its body was not
// inspected, and the day one of these starts matching, this test fails and
// the case moves to the supported file.
func TestCRSExamplesNotYetSupported(t *testing.T) {
	rs := loadCRS(t)
	examples := loadExamples(t, "crs-930-regression-not-yet-supported.json")
	if len(examples) != 4 {
		t.Fatalf("%d examples, want 4", len(examples))
	}
	for _, ex := range examples {
		t.Run(ex.Name, func(t *testing.T) {
			if ex.Request.Status.Body != httpmodel.BodyNotInspected || ex.Request.Status.BodyReason == "" {
				t.Errorf("body status = %+v, want not inspected with a reason", ex.Request.Status)
			}
			ids := rs.Evaluate(ex.Request).MatchedIDs()
			for _, id := range ex.ExpectIDs {
				if contains(ids, id) {
					t.Errorf("rule %d matches now: move this example to crs-930-regression.json", id)
				}
			}
		})
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
	const wantAttack = "[930100 930110 949110] pl1=20 lfi=20 total=20"
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
