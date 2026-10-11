// Command coraza-reference runs example requests through the Coraza WAF
// engine and writes down which rules matched. The output is a reference
// file: the tests of our own engine compare their results with it.
//
// This program is a separate Go module on purpose. Coraza is needed only to
// produce the reference file, so it is not a dependency of the IDS itself
// (M15).
//
// Usage, from this directory:
//
//	go run . -config ../../configs/crs-first-engine.json \
//	    -requests ../../testdata/requests/crs \
//	    -out ../../testdata/reference/coraza-first-engine.json
//
// The program loads the same rule files as our engine, in the same order,
// with the rule engine in detection-only mode. Of the rules our
// configuration excludes, it removes those outside the setup file 901, so
// that both engines run the same detection rules. The setup rules stay,
// because Coraza supports them and needs them to behave normally.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// engineConfig is the part of our engine's configuration that is used here.
type engineConfig struct {
	Files   []string `json:"files"`
	Exclude []struct {
		ID int `json:"id"`
	} `json:"exclude"`
}

// example is one request of an example file.
type example struct {
	Name    string     `json:"name"`
	Method  string     `json:"method"`
	URI     string     `json:"uri"`
	Version string     `json:"version"`
	Headers [][]string `json:"headers"`
	Body    string     `json:"body"`
}

// reference is the output file.
type reference struct {
	Engine string `json:"engine"`
	// RemovedRules are the rules taken out so that both engines run the
	// same detection rules.
	RemovedRules []int `json:"removed_rules"`
	// SkippedTargetUpdates are the rule ids of SecRuleUpdateTargetById
	// lines that were left out because the rule is not in the loaded
	// files.
	SkippedTargetUpdates []int    `json:"skipped_target_updates"`
	Results              []result `json:"results"`
}

// result is what Coraza found for one request.
type result struct {
	Source string `json:"source"` // the example file, without ".json"
	Index  int    `json:"index"`  // position in that file, from 1
	Name   string `json:"name,omitempty"`

	// Matches lists every matched rule that has a message, in the order
	// Coraza reports them. Rules without a message are setup and gate
	// rules.
	Matches []match `json:"matches"`

	// Score is the total in the message of rule 949110, or 0 when that
	// rule did not match.
	Score int `json:"score"`
}

type match struct {
	RuleID int `json:"rule_id"`
	// Variables are the places the rule matched, such as "ARGS:arg".
	Variables []string `json:"variables"`
}

var (
	totalScore   = regexp.MustCompile(`Total Score: (\d+)`)
	ruleID       = regexp.MustCompile(`\bid:'?(\d+)`)
	targetUpdate = regexp.MustCompile(`(?m)^\s*SecRuleUpdateTargetById\s+(\d+)\s`)
)

// engineSetup is loaded before the rule files. The two rules choose the XML
// and JSON body readers from the Content-Type; they are copied from
// coraza.conf-recommended, the configuration Coraza suggests for every
// deployment. Form and multipart bodies are recognised by Coraza itself.
const engineSetup = `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "coraza-reference: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "our engine configuration `file`")
	requestsPath := flag.String("requests", "", "example `file` or directory; may be given as a comma-separated list")
	outPath := flag.String("out", "", "reference `file` to write")
	flag.Parse()
	if *configPath == "" || *requestsPath == "" || *outPath == "" {
		return fmt.Errorf("-config, -requests and -out are all required")
	}

	var cfg engineConfig
	if err := readJSON(*configPath, &cfg); err != nil {
		return err
	}

	ref := reference{Engine: "coraza " + corazaVersion(), RemovedRules: []int{}, SkippedTargetUpdates: []int{}, Results: []result{}}

	// Coraza refuses a SecRuleUpdateTargetById line whose rule is not
	// loaded; our engine ignores such a line and reports it. To load the
	// same files in both, those lines are left out here. First collect the
	// ids of all rules in the files.
	var files []string
	loaded := map[int]bool{}
	for _, file := range cfg.Files {
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(*configPath), file)
		}
		files = append(files, file)
		text, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, m := range ruleID.FindAllSubmatch(text, -1) {
			id, _ := strconv.Atoi(string(m[1]))
			loaded[id] = true
		}
	}

	wafConfig := coraza.NewWAFConfig().WithDirectives(engineSetup)
	for _, file := range files {
		text, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if !targetUpdate.Match(text) {
			wafConfig = wafConfig.WithDirectivesFromFile(file)
			continue
		}
		var kept []string
		for _, line := range strings.Split(string(text), "\n") {
			if m := targetUpdate.FindStringSubmatch(line); m != nil {
				if id, _ := strconv.Atoi(m[1]); !loaded[id] {
					ref.SkippedTargetUpdates = append(ref.SkippedTargetUpdates, id)
					continue
				}
			}
			kept = append(kept, line)
		}
		wafConfig = wafConfig.WithDirectives(strings.Join(kept, "\n"))
	}
	for _, ex := range cfg.Exclude {
		if ex.ID/1000 == 901 {
			continue
		}
		ref.RemovedRules = append(ref.RemovedRules, ex.ID)
		wafConfig = wafConfig.WithDirectives("SecRuleRemoveById " + strconv.Itoa(ex.ID) + "\n")
	}
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return fmt.Errorf("loading the rules into Coraza: %w", err)
	}

	var exampleFiles []string
	for _, path := range strings.Split(*requestsPath, ",") {
		found, err := requestFiles(path)
		if err != nil {
			return err
		}
		exampleFiles = append(exampleFiles, found...)
	}
	for _, file := range exampleFiles {
		var examples []example
		if err := readJSON(file, &examples); err != nil {
			return err
		}
		source := strings.TrimSuffix(filepath.Base(file), ".json")
		for i, ex := range examples {
			res, err := evaluate(waf, ex)
			if err != nil {
				return fmt.Errorf("%s, example %d: %w", file, i+1, err)
			}
			res.Source, res.Index, res.Name = source, i+1, ex.Name
			ref.Results = append(ref.Results, res)
		}
	}

	out, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %d requests from %d files written to %s\n", ref.Engine, len(ref.Results), len(exampleFiles), *outPath)
	return nil
}

// evaluate runs one request through Coraza.
func evaluate(waf coraza.WAF, ex example) (result, error) {
	version := ex.Version
	if version == "" {
		version = "HTTP/1.1"
	}

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("127.0.0.1", 40000, "127.0.0.1", 80)
	tx.ProcessURI(ex.URI, ex.Method, version)
	for _, h := range ex.Headers {
		if len(h) != 2 {
			return result{}, fmt.Errorf("a header is not a [name, value] pair")
		}
		tx.AddRequestHeader(h[0], h[1])
		if strings.EqualFold(h[0], "Host") {
			tx.SetServerName(h[1])
		}
	}
	tx.ProcessRequestHeaders()
	if ex.Body != "" && tx.IsRequestBodyAccessible() {
		if _, _, err := tx.WriteRequestBody([]byte(ex.Body)); err != nil {
			return result{}, err
		}
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return result{}, err
	}
	tx.ProcessLogging()

	res := result{Matches: []match{}}
	for _, mr := range tx.MatchedRules() {
		if mr.Message() == "" {
			continue
		}
		m := match{RuleID: mr.Rule().ID(), Variables: []string{}}
		// For a chained rule Coraza lists what every rule of the chain
		// matched. Our engine reports what the last rule matched, so
		// only the deepest level is kept.
		deepest := 0
		for _, md := range mr.MatchedDatas() {
			if md.ChainLevel() > deepest {
				deepest = md.ChainLevel()
			}
		}
		for _, md := range mr.MatchedDatas() {
			if md.ChainLevel() != deepest {
				continue
			}
			name := md.Variable().Name()
			if md.Key() != "" {
				name += ":" + md.Key()
			}
			m.Variables = append(m.Variables, name)
		}
		res.Matches = append(res.Matches, m)
		if found := totalScore.FindStringSubmatch(mr.Message()); m.RuleID == 949110 && found != nil {
			res.Score, _ = strconv.Atoi(found[1])
		}
	}
	return res, nil
}

func readJSON(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// requestFiles returns path itself, or the *.json files in it when path is
// a directory, sorted by name.
func requestFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	files, err := filepath.Glob(filepath.Join(path, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// corazaVersion returns the version of the Coraza module this program was
// built with.
func corazaVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/corazawaf/coraza/v3" {
				return dep.Version
			}
		}
	}
	return "(unknown version)"
}
