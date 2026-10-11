// Command ids-offline runs the rule engine on example requests from a file
// and prints what it found.
//
//	ids-offline -config configs/crs-first-engine.json -requests testdata/requests/path-traversal.json
//
// Without -requests it prints only the startup report: which rules are
// active, which are excluded and why.
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
	Startup  result.Startup  `json:"startup"`
	Requests []requestOutput `json:"requests"`
}

// requestOutput is the record of one example with its test expectation.
type requestOutput struct {
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
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
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ids-offline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "configs/crs-first-engine.json", "engine configuration `file`")
	requestsPath := flags.String("requests", "", "JSON `file` with example requests")
	asJSON := flags.Bool("json", false, "print JSON instead of text")
	showValues := flags.Bool("show-values", false, "also print matched values and the request URI (may reveal sensitive content)")
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
	rules, err := engine.Load(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: the rules cannot be loaded:\n%v\n", err)
		return 2
	}

	out := output{Startup: result.NewStartup(rules), Requests: []requestOutput{}}
	if *requestsPath != "" {
		examples, err := offline.LoadFile(*requestsPath)
		if err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
		opt := result.Options{ShowValues: *showValues}
		for i, ex := range examples {
			res := rules.Evaluate(ex.Request)
			out.Requests = append(out.Requests, requestOutput{
				Index:       i + 1,
				Name:        ex.Name,
				Record:      result.NewRecord(ex.Request, res, opt),
				Expectation: check(ex, res.MatchedIDs()),
			})
		}
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
	} else {
		writeText(stdout, out)
	}

	for _, r := range out.Requests {
		if r.Expectation != nil && !r.Expectation.Met {
			return 1
		}
	}
	return 0
}

// check compares the matched rule ids with what an example expects. It
// returns nil for an example that expects nothing.
func check(ex offline.Example, matched []int) *expectation {
	if len(ex.ExpectIDs) == 0 && len(ex.NoExpectIDs) == 0 {
		return nil
	}
	has := map[int]bool{}
	for _, id := range matched {
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
	e.Met = len(e.Missing) == 0 && len(e.Unwanted) == 0
	return e
}

func writeText(w io.Writer, out output) {
	s := out.Startup
	fmt.Fprintf(w, "Rules: %s, %d active, %d excluded\n", orNone(s.Ruleset), s.ActiveRules, len(s.ExcludedRules))
	if len(out.Requests) == 0 {
		for _, ex := range s.ExcludedRules {
			fmt.Fprintf(w, "  excluded %d (%s:%d): %s\n", ex.ID, ex.File, ex.Line, ex.Reason)
		}
	} else if len(s.ExcludedRules) > 0 {
		fmt.Fprintln(w, "  (run without -requests to list the excluded rules and the reasons)")
	}
	if len(s.VariablesNotProvided) > 0 {
		fmt.Fprintf(w, "Variables named by rules but not provided: %s\n", strings.Join(s.VariablesNotProvided, ", "))
	}

	failed := 0
	for _, r := range out.Requests {
		fmt.Fprintf(w, "\n[%d] %s\n", r.Index, orNone(r.Name))
		fmt.Fprintf(w, "    request: %s", r.Method)
		if r.URI != "" {
			fmt.Fprintf(w, " %s", r.URI)
		}
		fmt.Fprintf(w, ", body %s", r.Analysis.Body)
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
