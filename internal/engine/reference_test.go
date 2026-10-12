package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/offline"
)

// referenceFile holds what the Coraza engine found for the example
// requests. It is written by tools/coraza-reference; see the README next to
// the file.
// There is one file per paranoia level that is compared: level 1, the
// default, and level 4, at which every rule runs.
var referenceFiles = []string{
	"../../testdata/reference/coraza-first-engine.json",
	"../../testdata/reference/coraza-first-engine-pl4.json",
}

type referenceDoc struct {
	Engine        string `json:"engine"`
	ParanoiaLevel int    `json:"paranoia_level"`
	Results       []struct {
		Source  string `json:"source"`
		Index   int    `json:"index"`
		Name    string `json:"name"`
		Score   int    `json:"score"`
		Matches []struct {
			RuleID    int      `json:"rule_id"`
			Variables []string `json:"variables"`
		} `json:"matches"`
	} `json:"results"`
}

// compared reports whether a rule's matches are compared. Those are the
// detection rules of files 930, 941 and 942 and the rule that evaluates the
// score. Setup rules are left out: some of them are excluded in our
// configuration, and the reference lists some that only log in Coraza.
func compared(ruleID int) bool {
	switch ruleID / 1000 {
	case 913, 930, 941, 942:
		return true
	}
	return ruleID == 949110
}

// TestAgainstCoraza compares our engine with the reference engine, request
// by request: which rules matched, in which places and how often, and the
// total anomaly score.
//
// Two kinds of request are treated specially:
//
//   - A request whose body our engine could not read to its end is not
//     compared; the request itself reports that.
//
//   - The requests in knownDifferences are compared on nothing; each has a
//     written reason.
//
//   - A request with a parameter or header value that is not valid UTF-8 is
//     compared on the set of matched rules only. Coraza's utf8toUnicode
//     rewrites an invalid byte as %ufffd; ours copies the byte, as
//     ModSecurity v2 does. Coraza's value therefore changes at that step,
//     and a multiMatch rule such as 930110 tests it one more time. The rule
//     is found by both engines; Coraza counts it more often and ends with a
//     higher score.
//
// knownDifferences lists single requests on which the two engines are known
// to disagree, with the reason. The key is the example file and the position
// in it.
var knownDifferences = map[string]string{}

func TestAgainstCoraza(t *testing.T) {
	for _, file := range referenceFiles {
		t.Run(filepath.Base(file), func(t *testing.T) { compareWithCoraza(t, file) })
	}
}

func compareWithCoraza(t *testing.T, referenceFile string) {
	data, err := os.ReadFile(referenceFile)
	if err != nil {
		t.Fatal(err)
	}
	var ref referenceDoc
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref.Engine, "coraza v3.") {
		t.Fatalf("reference engine = %q", ref.Engine)
	}

	rs := loadCRSAt(t, ref.ParanoiaLevel)
	examples := map[string][]offline.Example{}
	load := func(source string) []offline.Example {
		if list, ok := examples[source]; ok {
			return list
		}
		var path string
		for _, dir := range []string{"", "crs", "generated"} {
			path = filepath.Join("../../testdata/requests", dir, source+".json")
			if _, err := os.Stat(path); err == nil {
				break
			}
		}
		list, err := offline.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		examples[source] = list
		return list
	}

	comparedCount, skipped, withMatches, differences := 0, 0, 0, 0
	invalidUTF8, invalidUTF8Differ := 0, 0
	seenKnown := map[string]bool{}
	for _, want := range ref.Results {
		list := load(want.Source)
		if want.Index > len(list) || list[want.Index-1].Name != want.Name {
			t.Fatalf("%s #%d: the reference does not belong to the current example files; run tools/coraza-reference again", want.Source, want.Index)
		}
		ex := list[want.Index-1]
		if !ex.Request.Status.Body.Complete() {
			skipped++
			continue
		}
		key := fmt.Sprintf("%s#%d", want.Source, want.Index)
		if _, known := knownDifferences[key]; known {
			seenKnown[key] = true
			continue
		}
		comparedCount++

		var wantMatches []string
		for _, m := range want.Matches {
			if !compared(m.RuleID) {
				continue
			}
			for _, v := range m.Variables {
				wantMatches = append(wantMatches, fmt.Sprintf("%d@%s", m.RuleID, comparableName(v)))
			}
		}
		res := rs.Evaluate(ex.Request)
		var gotMatches []string
		for _, m := range res.Matches {
			if compared(m.RuleID) {
				gotMatches = append(gotMatches, fmt.Sprintf("%d@%s", m.RuleID, comparableName(m.VarName)))
			}
		}
		if len(wantMatches) > 0 {
			withMatches++
		}
		// The order of matches inside one rule is not compared.
		sort.Strings(wantMatches)
		sort.Strings(gotMatches)
		// The reference holds the score that rule 949110 reports, so it is
		// 0 for a request whose score stays below the threshold. Ours is
		// brought to the same form.
		gotScore := res.Score("blocking_inbound_anomaly_score")
		if gotScore < res.Score("inbound_anomaly_score_threshold") {
			gotScore = 0
		}
		same := strings.Join(gotMatches, " ") == strings.Join(wantMatches, " ") && gotScore == want.Score

		if hasInvalidUTF8(ex.Request) {
			invalidUTF8++
			if same {
				continue
			}
			invalidUTF8Differ++
			// The same rules must be found, and Coraza is the one
			// that counts more.
			if strings.Join(ruleIDs(gotMatches), " ") != strings.Join(ruleIDs(wantMatches), " ") || gotScore > want.Score {
				t.Errorf("%s #%d (%s), a request with invalid UTF-8\n  ours:   score %d, %v\n  coraza: score %d, %v", want.Source, want.Index, ex.Name, gotScore, gotMatches, want.Score, wantMatches)
			}
			continue
		}
		if !same {
			differences++
			if differences <= 15 {
				t.Errorf("%s #%d (%s)\n  ours:   score %d, %v\n  coraza: score %d, %v", want.Source, want.Index, ex.Name, gotScore, gotMatches, want.Score, wantMatches)
			}
		}
	}
	if differences > 15 {
		t.Errorf("%d more differences not shown", differences-15)
	}
	t.Logf("%s at paranoia level %d: %d requests compared (%d with a match), %d differences; %d of them have invalid UTF-8, of which %d differ in match count only; %d skipped because their body was not read to its end",
		ref.Engine, ref.ParanoiaLevel, comparedCount, withMatches, differences, invalidUTF8, invalidUTF8Differ, skipped)

	for key := range knownDifferences {
		if !seenKnown[key] {
			t.Errorf("known difference %s is not in the reference file any more; remove it", key)
		}
	}

	// The comparison must not shrink without notice.
	if comparedCount < 2600 || withMatches < 1400 {
		t.Errorf("only %d requests compared, %d with a match", comparedCount, withMatches)
	}
}

// hasInvalidUTF8 reports whether a value the rules inspect is not valid
// UTF-8.
func hasInvalidUTF8(req *httpmodel.Request) bool {
	for _, p := range req.Args() {
		if !utf8.ValidString(p.Value) {
			return true
		}
	}
	for _, h := range req.Received.Headers {
		if !utf8.ValidString(h.Value) {
			return true
		}
	}
	return !utf8.ValidString(req.Received.Target)
}

// ruleIDs returns the distinct rule ids of sorted "id@variable" entries.
func ruleIDs(matches []string) []string {
	var ids []string
	for _, m := range matches {
		id, _, _ := strings.Cut(m, "@")
		if len(ids) == 0 || ids[len(ids)-1] != id {
			ids = append(ids, id)
		}
	}
	return ids
}

// comparableName brings a variable name into a form both engines share.
// Names are compared without regard to case. Coraza reports XML content
// under the name REQUEST_XML. For an uploaded file, Coraza reports "FILES"
// where we report "FILES:" and the form field, so the field is left out.
func comparableName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "request_xml:", "xml:")
	for _, prefix := range []string{"files_names", "files"} {
		if name == prefix || strings.HasPrefix(name, prefix+":") {
			return prefix
		}
	}
	return name
}
