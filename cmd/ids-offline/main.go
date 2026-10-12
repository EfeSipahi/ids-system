// Command ids-offline runs the rule engine on example requests and prints
// what it found.
//
//	ids-offline -requests testdata/requests/path-traversal.json
//	ids-offline -requests testdata/requests/crs -summary
//
// -requests names a JSON file, or a directory whose *.json files are all
// read. Without -requests only the startup report is printed: which rules
// are active, which are excluded and why.
//
// -summary prints one line per file instead of one block per request. For
// the converted CRS tests, where each file holds the tests of one rule,
// that is one line per rule.
//
// Matched values are not printed unless -show-values is given (M11).
//
// Exit status: 0 on success, 1 when an example's expect_ids or
// no_expect_ids is not met, 2 when the rules or the requests cannot be
// loaded.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/result"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// output is everything one run prints.
type output struct {
	Startup result.Startup `json:"startup"`
	// Requests is left out with -summary, and Summary without it.
	Requests []requestOutput `json:"requests,omitempty"`
	Summary  []groupSummary  `json:"summary,omitempty"`
}

// requestOutput is the record of one example with its test expectation.
type requestOutput struct {
	Index int `json:"index"`
	// Source is the file the example came from, without ".json".
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	result.Record
	Expectation *expectation `json:"expectation,omitempty"`
}

// expectation says whether the rule ids an example names came out right.
type expectation struct {
	Met bool `json:"met"`
	// Missing are rules that were expected and did not match.
	Missing []int `json:"missing,omitempty"`
	// Unwanted are rules that matched and must not.
	Unwanted []int `json:"unwanted,omitempty"`
	// MissingLog is the expected log pattern when no match produced it,
	// and UnwantedLog the forbidden one when a match did.
	MissingLog  string `json:"missing_log,omitempty"`
	UnwantedLog string `json:"unwanted_log,omitempty"`
}

// groupSummary counts the examples of one file.
type groupSummary struct {
	Source string `json:"source"`

	// RuleStatus is set when the file is named after a rule id, as the
	// converted CRS tests are: "active", "excluded", or "not loaded" when
	// the rule is in none of the loaded rule files.
	RuleStatus string `json:"rule_status,omitempty"`

	Tests int `json:"tests"`
	// Flagged counts the requests whose anomaly score reached the
	// threshold, whatever their expectation says.
	Flagged int `json:"flagged"`
	// Incomplete counts the requests that could not be inspected
	// completely.
	Incomplete int `json:"incomplete"`
	Passed     int `json:"passed"`
	// Failed counts examples whose expectation was not met although the
	// whole request was inspected.
	Failed int `json:"failed"`
	// NotInspected counts examples whose expectation was not met and
	// whose body could not be inspected. The engine could not have seen
	// the payload.
	NotInspected int `json:"not_inspected"`
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ids-offline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "configs/crs-first-engine.json", "engine configuration `file`")
	requestsPath := flags.String("requests", "", "JSON `file` with example requests, or a directory of such files")
	summary := flags.Bool("summary", false, "print one line per file instead of every request")
	asJSON := flags.Bool("json", false, "print JSON instead of text")
	showValues := flags.Bool("show-values", false, "also print matched values and the request URI (may reveal sensitive content)")
	level := flags.Int("paranoia-level", 0, "CRS paranoia `level` 1 to 4, in place of the one in the configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ids-offline: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	cfg, err := engine.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: %v\n", err)
		return 2
	}
	if *level != 0 {
		cfg.ParanoiaLevel = *level
	}
	rules, err := engine.Load(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: the rules cannot be loaded:\n%v\n", err)
		return 2
	}

	out := output{Startup: result.NewStartup(rules)}
	if *requestsPath != "" {
		files, err := requestFiles(*requestsPath)
		if err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
		opt := result.Options{ShowValues: *showValues}
		for _, file := range files {
			examples, err := offline.LoadFile(file)
			if err != nil {
				fmt.Fprintf(stderr, "ids-offline: %v\n", err)
				return 2
			}
			source := strings.TrimSuffix(filepath.Base(file), ".json")
			for _, ex := range examples {
				res := rules.Evaluate(ex.Request)
				out.Requests = append(out.Requests, requestOutput{
					Index:       len(out.Requests) + 1,
					Source:      source,
					Name:        ex.Name,
					Record:      result.NewRecord(ex.Request, res, opt),
					Expectation: check(ex, res),
				})
			}
		}
	}

	exit := 0
	for _, r := range out.Requests {
		if r.Expectation != nil && !r.Expectation.Met {
			exit = 1
		}
	}
	if *summary {
		out.Summary = summarize(out.Requests, rules.Statuses())
		out.Requests = nil
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
	} else if *summary {
		writeSummary(stdout, out)
	} else {
		writeText(stdout, out)
	}
	return exit
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
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no .json files in this directory", path)
	}
	sort.Strings(files)
	return files, nil
}

// summarize counts the requests of each source file, in the order the
// files were read.
func summarize(requests []requestOutput, statuses []engine.RuleStatus) []groupSummary {
	ruleStatus := map[int]string{}
	for _, st := range statuses {
		if st.Active {
			ruleStatus[st.ID] = "active"
		} else {
			ruleStatus[st.ID] = "excluded"
		}
	}

	var groups []groupSummary
	index := map[string]int{}
	for _, r := range requests {
		i, ok := index[r.Source]
		if !ok {
			i = len(groups)
			index[r.Source] = i
			g := groupSummary{Source: r.Source}
			if id, err := strconv.Atoi(r.Source); err == nil {
				g.RuleStatus = "not loaded"
				if status, known := ruleStatus[id]; known {
					g.RuleStatus = status
				}
			}
			groups = append(groups, g)
		}
		g := &groups[i]
		g.Tests++
		if r.Score.Exceeded {
			g.Flagged++
		}
		if !r.Analysis.Complete {
			g.Incomplete++
		}
		switch {
		case r.Expectation == nil || r.Expectation.Met:
			g.Passed++
		case !r.Analysis.Complete:
			g.NotInspected++
		default:
			g.Failed++
		}
	}
	return groups
}

func writeSummary(w io.Writer, out output) {
	writeStartup(w, out.Startup, len(out.Summary) > 0)
	if len(out.Summary) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%-24s  %-10s  %5s  %7s  %6s  %6s  %13s\n", "file", "rule", "tests", "flagged", "passed", "failed", "not inspected")
	var total groupSummary
	for _, g := range out.Summary {
		fmt.Fprintf(w, "%-24s  %-10s  %5d  %7d  %6d  %6d  %13d\n", g.Source, orDash(g.RuleStatus), g.Tests, g.Flagged, g.Passed, g.Failed, g.NotInspected)
		total.Tests += g.Tests
		total.Flagged += g.Flagged
		total.Passed += g.Passed
		total.Failed += g.Failed
		total.NotInspected += g.NotInspected
	}
	fmt.Fprintf(w, "%-24s  %-10s  %5d  %7d  %6d  %6d  %13d\n", "total", "", total.Tests, total.Flagged, total.Passed, total.Failed, total.NotInspected)
	fmt.Fprintln(w, "\nflagged: the anomaly score reached the threshold")
	fmt.Fprintln(w, "failed: the expectation was not met although the whole request was inspected")
	fmt.Fprintln(w, "not inspected: the expectation was not met and the body could not be read")
}

// check compares the matched rule ids with what an example expects. It
// returns nil for an example that expects nothing.
func check(ex offline.Example, res *engine.Result) *expectation {
	if !ex.HasExpectation() {
		return nil
	}
	has := map[int]bool{}
	for _, id := range res.MatchedIDs() {
		has[id] = true
	}
	e := &expectation{}
	for _, id := range ex.ExpectIDs {
		if !has[id] {
			e.Missing = append(e.Missing, id)
		}
	}
	for _, id := range ex.NoExpectIDs {
		if has[id] {
			e.Unwanted = append(e.Unwanted, id)
		}
	}
	logged := func(pattern *regexp.Regexp) bool {
		return slices.ContainsFunc(res.LogLines(), pattern.MatchString)
	}
	if ex.ExpectLog != nil && !logged(ex.ExpectLog) {
		e.MissingLog = ex.ExpectLog.String()
	}
	if ex.NoExpectLog != nil && logged(ex.NoExpectLog) {
		e.UnwantedLog = ex.NoExpectLog.String()
	}
	e.Met = len(e.Missing) == 0 && len(e.Unwanted) == 0 && e.MissingLog == "" && e.UnwantedLog == ""
	return e
}

// writeStartup prints the rule report. With brief set, the excluded rules
// are counted but not listed.
func writeStartup(w io.Writer, s result.Startup, brief bool) {
	fmt.Fprintf(w, "Rules: %s, paranoia level %d, %d active, %d excluded\n", orNone(s.Ruleset), s.ParanoiaLevel, s.ActiveRules, len(s.ExcludedRules))
	if !brief {
		for _, ex := range s.ExcludedRules {
			fmt.Fprintf(w, "  excluded %d (%s:%d): %s\n", ex.ID, ex.File, ex.Line, ex.Reason)
		}
	} else if len(s.ExcludedRules) > 0 {
		fmt.Fprintln(w, "  (run without -requests to list the excluded rules and the reasons)")
	}
	if n := len(s.IgnoredTargetUpdates); n > 0 {
		fmt.Fprintf(w, "Target updates for %d rules that are not active were ignored\n", n)
	}
}

func writeText(w io.Writer, out output) {
	writeStartup(w, out.Startup, len(out.Requests) > 0)

	failed := 0
	for _, r := range out.Requests {
		fmt.Fprintf(w, "\n[%d] %s\n", r.Index, orNone(r.Name))
		fmt.Fprintf(w, "    request: %s", r.Method)
		if r.URI != "" {
			fmt.Fprintf(w, " %s", r.URI)
		}
		fmt.Fprintf(w, ", body %s", r.Analysis.Body)
		if r.Analysis.BodyFormat != "" {
			fmt.Fprintf(w, " as %s", r.Analysis.BodyFormat)
		}
		if r.Analysis.BodyReason != "" {
			fmt.Fprintf(w, " (%s)", r.Analysis.BodyReason)
		}
		fmt.Fprintln(w)
		if !r.Analysis.Complete {
			fmt.Fprintln(w, "    ANALYSIS INCOMPLETE: no finding here does not mean the request is clean")
		}
		for _, issue := range r.Analysis.Issues {
			fmt.Fprintf(w, "    note (%s): %s\n", issue.Part, issue.Message)
		}

		if len(r.Findings) == 0 {
			fmt.Fprintln(w, "    no findings")
		}
		for _, f := range r.Findings {
			fmt.Fprintf(w, "    %d  %-8s  %-34s  %s\n", f.RuleID, orDash(f.Severity), orDash(f.Location), f.Message)
			if f.Value != nil {
				fmt.Fprintf(w, "            value: %s\n", *f.Value)
			}
			if f.Data != nil {
				fmt.Fprintf(w, "            data:  %s\n", *f.Data)
			}
		}

		verdict := "below threshold"
		if r.Score.Exceeded {
			verdict = "THRESHOLD EXCEEDED"
		}
		fmt.Fprintf(w, "    score %d, threshold %d: %s\n", r.Score.Total, r.Score.Threshold, verdict)

		if e := r.Expectation; e != nil {
			if e.Met {
				fmt.Fprintln(w, "    expectation: met")
			} else {
				failed++
				fmt.Fprintf(w, "    expectation: NOT MET")
				if len(e.Missing) > 0 {
					fmt.Fprintf(w, ", did not match %v", e.Missing)
				}
				if len(e.Unwanted) > 0 {
					fmt.Fprintf(w, ", must not match %v", e.Unwanted)
				}
				if e.MissingLog != "" {
					fmt.Fprintf(w, ", no log line has %q", e.MissingLog)
				}
				if e.UnwantedLog != "" {
					fmt.Fprintf(w, ", a log line has %q", e.UnwantedLog)
				}
				fmt.Fprintln(w)
			}
		}
	}

	if len(out.Requests) > 0 {
		fmt.Fprintf(w, "\n%d requests, %d with an expectation that was not met\n", len(out.Requests), failed)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
