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
// When the configuration has "applications", each request is checked
// against the profile of its application (A04): the one whose host is the
// request's Host header, with the longest path prefix that fits (F3).
// -application NAME checks every request against one application instead.
// The rules run with the application's exceptions and paranoia level, and
// the profile's findings are printed apart from the rule findings (M10).
// -paranoia-level changes the level of the configuration, which an
// application with its own level does not use (F11).
//
// -endpoints lists the endpoints and parameters of the requests, as a start
// for writing a profile (F4g), and does nothing else: no rules run and no
// records are written. Values are never listed; paths are, as received.
//
// When the configuration has a "records" section, or -records names a
// directory, the requests with a finding or an incomplete analysis are also
// written to record files there (R1), for the dashboard. Records follow
// their own rule for request content (R4): they keep who sent a request
// and what matched, with secrets masked, whatever -show-values says.
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

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
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
	// Records says where records were written, when they were.
	Records *recordsOutput `json:"records,omitempty"`
}

// recordsOutput says what was written to the record files.
type recordsOutput struct {
	Dir      string `json:"dir"`
	Run      string `json:"run"`
	Analysed int    `json:"analysed"`
	Written  int    `json:"written"`
}

// requestOutput is the record of one example with its test expectation.
type requestOutput struct {
	Index int `json:"index"`
	// Source is the file the example came from, without ".json".
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	result.Record

	// Application, Profile and AlertBy are set when the configuration has
	// applications. AlertBy names what made the request an alert: "rules",
	// "profile" or both.
	Application *result.Application `json:"application,omitempty"`
	Profile     *result.Profile     `json:"profile,omitempty"`
	AlertBy     []string            `json:"alert_by,omitempty"`

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

	// Profile is set when the configuration has applications.
	Profile *profileCounts `json:"profile,omitempty"`
}

// profileCounts counts what the profile layer found in the examples of one
// file.
type profileCounts struct {
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

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ids-offline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "configs/crs-first-engine.json", "engine configuration `file`")
	requestsPath := flags.String("requests", "", "JSON `file` with example requests, or a directory of such files")
	summary := flags.Bool("summary", false, "print one line per file instead of every request")
	asJSON := flags.Bool("json", false, "print JSON instead of text")
	showValues := flags.Bool("show-values", false, "also print matched values and the request URI (may reveal sensitive content)")
	level := flags.Int("paranoia-level", 0, "CRS paranoia `level` 1 to 4, in place of the one in the configuration; an application with its own level keeps it")
	recordsDir := flags.String("records", "", "write records to this `directory`, in place of the one in the configuration")
	appName := flags.String("application", "", "check every request against the profile of the application with this `name`, whatever its host")
	endpoints := flags.Bool("endpoints", false, "only list the endpoints and parameters of the requests, without values")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ids-offline: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	if *endpoints {
		if *requestsPath == "" || *recordsDir != "" || *summary || *appName != "" {
			fmt.Fprintln(stderr, "ids-offline: -endpoints needs -requests and lists the requests only; leave out -records, -summary and -application")
			return 2
		}
		return listEndpoints(*requestsPath, *asJSON, stdout, stderr)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: %v\n", err)
		return 2
	}
	if *level != 0 {
		cfg.ParanoiaLevel = *level
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: the rules cannot be loaded:\n%v\n", err)
		return 2
	}

	apps, err := profile.NewSet(rules, cfg.Applications, cfg.RequireProfile)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: the applications cannot be prepared:\n%v\n", err)
		return 2
	}
	var forced *profile.App
	if *appName != "" {
		if forced = apps.ByName(*appName); forced == nil {
			fmt.Fprintf(stderr, "ids-offline: -application %s: %s\n", *appName, knownApps(apps))
			return 2
		}
	}
	profiled := len(apps.Apps()) > 0

	out := output{Startup: result.NewStartup(rules)}
	out.Startup.SetApplications(apps)
	if *requestsPath != "" {
		files, examples, err := loadExamples(*requestsPath)
		if err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
		recorder, err := openRecords(cfg, *recordsDir, rules, apps)
		if err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
		if recorder != nil {
			out.Records = &recordsOutput{Dir: recordsDirOf(cfg, *recordsDir), Run: recorder.Run()}
		}

		opt := result.Options{ShowValues: *showValues}
		for i, file := range files {
			source := strings.TrimSuffix(filepath.Base(file), ".json")
			for _, ex := range examples[i] {
				app := forced
				if app == nil {
					app = apps.Match(ex.Request)
				}
				var tuning *engine.Tuning
				if app != nil {
					tuning = app.Tuning
				}
				res := rules.EvaluateWith(ex.Request, tuning)
				r := requestOutput{
					Index:       len(out.Requests) + 1,
					Source:      source,
					Name:        ex.Name,
					Record:      result.NewRecord(res.Request, res, opt),
					Expectation: check(ex, res),
				}
				var prof *profile.Result
				if profiled {
					checked := apps.Check(res.Request, app)
					prof = &checked
					a := result.NewApplication(app, rules.ParanoiaLevel())
					r.Application, r.Profile = &a, result.NewProfile(checked)
					r.AlertBy = result.AlertBy(r.Score, checked)
				}
				out.Requests = append(out.Requests, r)
				if recorder == nil {
					continue
				}
				if err := recorder.Add(res.Request, res, prof); err != nil {
					recorder.Close()
					fmt.Fprintf(stderr, "ids-offline: %v\n", err)
					return 2
				}
				out.Records.Analysed++
				if record.Wanted(res.Request, res, prof) {
					out.Records.Written++
				}
			}
		}
		if recorder != nil {
			if err := recorder.Close(); err != nil {
				fmt.Fprintf(stderr, "ids-offline: %v\n", err)
				return 2
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
		out.Summary = summarize(out.Requests, rules.Statuses(), profiled)
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

// openRecords starts the record files of this run, or returns nil when no
// records are to be written: the configuration has no "records" section
// and -records was not given.
func openRecords(cfg *config.Product, dir string, rules *engine.RuleSet, apps *profile.Set) (*record.Recorder, error) {
	if cfg.Records == nil && dir == "" {
		return nil, nil
	}
	rc := record.Config{}
	if cfg.Records != nil {
		rc = *cfg.Records
	}
	rc.Dir = recordsDirOf(cfg, dir)
	fingerprint, err := cfg.Fingerprint(rules.ParanoiaLevel())
	if err != nil {
		return nil, err
	}
	return record.Open(rc, record.NewEngine(rules, fingerprint), rules.Statuses(), apps)
}

// recordsDirOf returns the directory records are written to: the one of
// -records, or else the one of the configuration.
func recordsDirOf(cfg *config.Product, dir string) string {
	if dir != "" || cfg.Records == nil {
		return dir
	}
	return cfg.Records.Dir
}

// knownApps says which applications -application can name.
func knownApps(apps *profile.Set) string {
	var names []string
	for _, a := range apps.Apps() {
		names = append(names, a.Name)
	}
	if len(names) == 0 {
		return "the configuration has no applications"
	}
	return "no such application; the configuration has: " + strings.Join(names, ", ")
}

// loadExamples reads the example files of path, as requestFiles finds them.
func loadExamples(path string) ([]string, [][]offline.Example, error) {
	files, err := requestFiles(path)
	if err != nil {
		return nil, nil, err
	}
	var examples [][]offline.Example
	for _, file := range files {
		ex, err := offline.LoadFile(file)
		if err != nil {
			return nil, nil, err
		}
		examples = append(examples, ex)
	}
	return files, examples, nil
}

// listEndpoints prints the endpoints and parameters of the examples of
// path (F4g).
func listEndpoints(path string, asJSON bool, stdout, stderr io.Writer) int {
	_, examples, err := loadExamples(path)
	if err != nil {
		fmt.Fprintf(stderr, "ids-offline: %v\n", err)
		return 2
	}
	survey := profile.NewSurvey()
	requests := 0
	for _, file := range examples {
		for _, ex := range file {
			survey.Add(ex.Request)
			requests++
		}
	}
	list := struct {
		Requests  int                      `json:"requests"`
		Endpoints []profile.SurveyEndpoint `json:"endpoints"`
		Cookies   []profile.SurveyParam    `json:"cookies"`
	}{requests, survey.Endpoints(), survey.Cookies()}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(list); err != nil {
			fmt.Fprintf(stderr, "ids-offline: %v\n", err)
			return 2
		}
		return 0
	}
	fmt.Fprintf(stdout, "%d requests, %d endpoints (method and path as received; no values are shown)\n", list.Requests, len(list.Endpoints))
	for _, ep := range list.Endpoints {
		fmt.Fprintf(stdout, "\n%s %s  %s", ep.Method, result.Printable(ep.Path), count(ep.Count, "request"))
		if ep.BodyNotRead > 0 {
			fmt.Fprintf(stdout, ", %d with a body not read to its end", ep.BodyNotRead)
		}
		fmt.Fprintln(stdout)
		if len(ep.ContentTypes) > 0 {
			fmt.Fprintf(stdout, "  body types: %s\n", strings.Join(ep.ContentTypes, ", "))
		}
		for _, p := range ep.Params {
			writeSurveyParam(stdout, p)
		}
	}
	if len(list.Cookies) > 0 {
		fmt.Fprintln(stdout, "\nCookies")
		for _, p := range list.Cookies {
			writeSurveyParam(stdout, p)
		}
	}
	fmt.Fprintln(stdout, "\nsent: requests that sent it; max: the longest value in bytes after decoding")
	return 0
}

func writeSurveyParam(w io.Writer, p profile.SurveyParam) {
	fmt.Fprintf(w, "  %-6s  %-30s  sent %5d  max %5d", p.In, result.Printable(p.Name), p.Count, p.MaxLength)
	if p.AllInteger {
		fmt.Fprint(w, "  integers only")
	}
	if p.Repeated {
		fmt.Fprint(w, "  repeated")
	}
	fmt.Fprintln(w)
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
func summarize(requests []requestOutput, statuses []engine.RuleStatus, profiled bool) []groupSummary {
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
			if profiled {
				g.Profile = &profileCounts{}
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
		if r.Score.Exceeded {
			g.Flagged++
		}
		if !r.Analysis.Complete {
			g.Incomplete++
		}
		if g.Profile != nil {
			countProfile(g.Profile, r)
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

func countProfile(c *profileCounts, r requestOutput) {
	if r.Application.Name == profile.NoApplication {
		c.NoApplication++
	}
	if r.Profile == nil || len(r.Profile.Findings) == 0 {
		return
	}
	c.Findings++
	if slices.ContainsFunc(r.Profile.Findings, func(f profile.Finding) bool { return f.Kind == profile.KindUnknownEndpoint }) {
		c.UnknownEndpoints++
	}
	if slices.Contains(r.AlertBy, result.AlertByProfile) {
		c.Alerts++
	}
}

func writeSummary(w io.Writer, out output) {
	writeStartup(w, out.Startup, len(out.Summary) > 0)
	if len(out.Summary) == 0 {
		return
	}
	profiled := out.Summary[0].Profile != nil
	fmt.Fprintf(w, "\n%-24s  %-10s  %5s  %7s  %6s  %6s  %13s", "file", "rule", "tests", "flagged", "passed", "failed", "not inspected")
	if profiled {
		fmt.Fprintf(w, "  %7s  %7s  %8s  %6s", "profile", "unknown", "p.alerts", "no app")
	}
	fmt.Fprintln(w)
	total := groupSummary{Profile: &profileCounts{}}
	row := func(name, status string, g groupSummary) {
		fmt.Fprintf(w, "%-24s  %-10s  %5d  %7d  %6d  %6d  %13d", name, status, g.Tests, g.Flagged, g.Passed, g.Failed, g.NotInspected)
		if profiled {
			fmt.Fprintf(w, "  %7d  %7d  %8d  %6d", g.Profile.Findings, g.Profile.UnknownEndpoints, g.Profile.Alerts, g.Profile.NoApplication)
		}
		fmt.Fprintln(w)
	}
	for _, g := range out.Summary {
		row(g.Source, orDash(g.RuleStatus), g)
		total.Tests += g.Tests
		total.Flagged += g.Flagged
		total.Passed += g.Passed
		total.Failed += g.Failed
		total.NotInspected += g.NotInspected
		if profiled {
			total.Profile.Findings += g.Profile.Findings
			total.Profile.UnknownEndpoints += g.Profile.UnknownEndpoints
			total.Profile.Alerts += g.Profile.Alerts
			total.Profile.NoApplication += g.Profile.NoApplication
		}
	}
	row("total", "", total)
	fmt.Fprintln(w, "\nflagged: the anomaly score reached the threshold")
	fmt.Fprintln(w, "failed: the expectation was not met although the whole request was inspected")
	fmt.Fprintln(w, "not inspected: the expectation was not met and the body could not be read")
	if profiled {
		fmt.Fprintln(w, "profile: requests with a profile finding; unknown: of these, requests whose path fits no endpoint")
		fmt.Fprintln(w, "p.alerts: alerts because of a profile in alert mode; no app: requests of no application")
	}
	writeRecords(w, out.Records)
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
	level := ""
	if len(s.Applications) > 0 {
		level = " by default"
	}
	fmt.Fprintf(w, "Rules: %s, paranoia level %d%s, %d active, %d excluded\n", orNone(s.Ruleset), s.ParanoiaLevel, level, s.ActiveRules, len(s.ExcludedRules))
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
	writeApplications(w, s, brief)
}

// writeApplications prints the applications of the startup report. With
// brief set, the exceptions are counted but not listed; notes are always
// printed.
func writeApplications(w io.Writer, s result.Startup, brief bool) {
	if len(s.Applications) == 0 {
		return
	}
	other := "requests of other hosts get the rules only"
	if s.RequireProfile {
		other = "requests of other hosts get a no_profile finding (require_profile)"
	}
	fmt.Fprintf(w, "Applications: %d; %s\n", len(s.Applications), other)
	for _, a := range s.Applications {
		fmt.Fprintf(w, "  %s: hosts %s", a.Name, strings.Join(a.Hosts, ", "))
		if len(a.Paths) > 0 {
			fmt.Fprintf(w, ", paths %s", strings.Join(a.Paths, ", "))
		}
		fmt.Fprintf(w, "; profile %s, mode %s, paranoia level %d, %s\n", a.Profile, a.Mode, a.ParanoiaLevel, count(len(a.Exceptions), "exception"))
		if !brief {
			for _, ex := range a.Exceptions {
				fmt.Fprintf(w, "    %s: %s\n", exceptionText(ex.Exception), ex.Reason)
			}
		}
		for _, n := range a.Notes {
			fmt.Fprintf(w, "    note: %s\n", n)
		}
	}
	if brief && slices.ContainsFunc(s.Applications, func(a result.AppStartup) bool { return len(a.Exceptions) > 0 }) {
		fmt.Fprintln(w, "  (run without -requests to list the exceptions)")
	}
}

// exceptionText says what an exception changes, such as "rule 932350
// skips ARGS_NAMES:pwd".
func exceptionText(ex profile.Exception) string {
	switch {
	case ex.Setting != "":
		return fmt.Sprintf("setting %s = %q", ex.Setting, *ex.Value)
	case ex.Off:
		return fmt.Sprintf("rule %d off", ex.Rule)
	default:
		return fmt.Sprintf("rule %d skips %s", ex.Rule, strings.Join(ex.Skip, ", "))
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
		if a := r.Application; a != nil {
			fmt.Fprintf(w, "    application: %s, paranoia level %d", a.Name, a.ParanoiaLevel)
			if a.Mode != "" {
				fmt.Fprintf(w, ", profile mode %s", a.Mode)
			}
			fmt.Fprintln(w)
		}
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
		switch {
		case r.Score.Exceeded && r.Application != nil:
			verdict = "ALERT (" + result.AlertByRules + ")"
		case r.Score.Exceeded:
			verdict = "ALERT (" + record.DecidedBy + ")"
		}
		fmt.Fprintf(w, "    score %d, threshold %d: %s\n", r.Score.Total, r.Score.Threshold, verdict)
		writeProfile(w, r)

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
	writeRecords(w, out.Records)
}

// writeProfile prints the profile part of a request's text.
func writeProfile(w io.Writer, r requestOutput) {
	p := r.Profile
	if p == nil {
		return
	}
	if !p.BodyChecked && r.Application.Name != profile.NoApplication {
		fmt.Fprintln(w, "    profile: the body was not read to its end, so its parameters were not checked")
	}
	switch {
	case len(p.Findings) == 0:
		fmt.Fprintln(w, "    profile: no findings")
	case slices.Contains(r.AlertBy, result.AlertByProfile):
		fmt.Fprintf(w, "    profile: %s: ALERT (%s)\n", count(len(p.Findings), "finding"), result.AlertByProfile)
	case r.Application.Mode == "":
		fmt.Fprintf(w, "    profile: %s, recorded only (no application)\n", count(len(p.Findings), "finding"))
	default:
		fmt.Fprintf(w, "    profile: %s, recorded only (mode %s)\n", count(len(p.Findings), "finding"), r.Application.Mode)
	}
	for _, f := range p.Findings {
		fmt.Fprintf(w, "      %-16s  %-34s  %s\n", f.Kind, result.Printable(f.Location), f.Message)
	}
}

// writeRecords says where the records of this run went.
func writeRecords(w io.Writer, r *recordsOutput) {
	if r != nil {
		fmt.Fprintf(w, "\nRecords: %d of %d requests written to %s (run %s)\n", r.Written, r.Analysed, r.Dir, r.Run)
	}
}

// count writes n with the word, as "1 finding" or "2 findings".
func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
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
