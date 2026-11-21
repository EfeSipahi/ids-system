// Package batch is what ids-offline and the dashboard's Analyse files page
// both say of a set of analysed request files (W14 of
// docs/development-plan-dashboard-control.md): whether each request met
// what its file expects, and a summary per file. The two give the same
// numbers because they use the same code.
package batch

import (
	"regexp"
	"slices"
	"strconv"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
)

// Expectation says whether the rule ids an example names came out right.
type Expectation struct {
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

// Check compares the matched rule ids with what an example expects. It
// returns nil for an example that expects nothing.
func Check(ex offline.Example, res *engine.Result) *Expectation {
	if !ex.HasExpectation() {
		return nil
	}
	has := map[int]bool{}
	for _, id := range res.MatchedIDs() {
		has[id] = true
	}
	e := &Expectation{}
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

// Group counts the examples of one file.
type Group struct {
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

	// Profile is set when the configuration has applications.
	Profile *ProfileCounts `json:"profile,omitempty"`
}

// ProfileCounts counts what the profile layer found in the examples of one
// file.
type ProfileCounts struct {
	// Findings counts the requests with a profile finding.
	Findings int `json:"findings"`
	// UnknownEndpoints counts the requests whose path fits no endpoint of
	// their profile.
	UnknownEndpoints int `json:"unknown_endpoints"`
	// Alerts counts the requests that are alerts because of the profile,
	// whose mode is "alert".
	Alerts int `json:"alerts"`
	// NoApplication counts the requests of no application.
	NoApplication int `json:"no_application"`
}

// Item is what the summary needs of one analysed example.
type Item struct {
	Source   string
	Exceeded bool
	Complete bool
	// Application is the request's application, profile.NoApplication
	// for none; Findings the profile's findings, and ByProfile whether
	// the profile made it an alert.
	Application string
	Findings    []profile.Finding
	ByProfile   bool
	Expectation *Expectation
}

// Summarize counts the examples of each source file, in the order the files
// were read.
func Summarize(items []Item, statuses []engine.RuleStatus, profiled bool) []Group {
	ruleStatus := map[int]string{}
	for _, st := range statuses {
		if st.Active {
			ruleStatus[st.ID] = "active"
		} else {
			ruleStatus[st.ID] = "excluded"
		}
	}

	var groups []Group
	index := map[string]int{}
	for _, r := range items {
		i, ok := index[r.Source]
		if !ok {
			i = len(groups)
			index[r.Source] = i
			g := Group{Source: r.Source}
			if profiled {
				g.Profile = &ProfileCounts{}
			}
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
		if r.Exceeded {
			g.Flagged++
		}
		if !r.Complete {
			g.Incomplete++
		}
		if g.Profile != nil {
			countProfile(g.Profile, r)
		}
		switch {
		case r.Expectation == nil || r.Expectation.Met:
			g.Passed++
		case !r.Complete:
			g.NotInspected++
		default:
			g.Failed++
		}
	}
	return groups
}

func countProfile(c *ProfileCounts, r Item) {
	if r.Application == profile.NoApplication {
		c.NoApplication++
	}
	if len(r.Findings) == 0 {
		return
	}
	c.Findings++
	if slices.ContainsFunc(r.Findings, func(f profile.Finding) bool { return f.Kind == profile.KindUnknownEndpoint }) {
		c.UnknownEndpoints++
	}
	if r.ByProfile {
		c.Alerts++
	}
}
