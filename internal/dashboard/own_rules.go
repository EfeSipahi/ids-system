package dashboard

// Own rules in the dashboard (stage 3 of docs/development-plan-own-rules.md):
// the New rule form writes a rule's SecLang (N1) with the next free id
// (N3); changes add, edit and remove the rules of the configuration's
// own-rules file as pending changes for every application, which analysts
// propose and admins apply (N7).

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/jsonedit"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// ownPlace is a part of the request a condition of the form looks at.
type ownPlace struct {
	// Name is the variable, such as REQUEST_HEADERS.
	Name  string `json:"name"`
	Label string `json:"label"`
	// Key says whether the place takes the name of a header, cookie or
	// parameter: "", "optional" or "required".
	Key string `json:"key,omitempty"`
	// Body is true for a place read with the body, in phase 2.
	Body bool `json:"body,omitempty"`
}

var ownPlaces = []ownPlace{
	{Name: "REQUEST_FILENAME", Label: "Path, without the query string"},
	{Name: "REQUEST_URI", Label: "Path with the query string"},
	{Name: "REQUEST_METHOD", Label: "Method"},
	{Name: "REQUEST_HEADERS", Label: "Header", Key: "required"},
	{Name: "REQUEST_COOKIES", Label: "Cookie", Key: "required"},
	{Name: "ARGS", Label: "Parameter, of the query or the body", Key: "optional", Body: true},
	{Name: "ARGS_NAMES", Label: "Names of the parameters", Body: true},
	{Name: "REQUEST_BODY", Label: "Whole body", Body: true},
	{Name: "REMOTE_ADDR", Label: "Client IP address"},
}

// ownTest is a test of the form: a SecLang operator.
type ownTest struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	// Text is true when the value is text, which "ignore case" writes in
	// lower case for t:lowercase.
	Text bool `json:"text,omitempty"`
}

var ownTests = []ownTest{
	{Name: "contains", Label: "contains", Text: true},
	{Name: "streq", Label: "is", Text: true},
	{Name: "beginsWith", Label: "begins with", Text: true},
	{Name: "endsWith", Label: "ends with", Text: true},
	{Name: "pm", Label: "has one of the words (a space between them)", Text: true},
	{Name: "rx", Label: "matches the regular expression"},
	{Name: "ipMatch", Label: "is in the addresses or ranges (a comma between them)"},
}

// ownSeverity is a severity of the form with the points CRS 4.30.0 gives
// it (REQUEST-901), which the rule adds (N6).
type ownSeverity struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
}

var ownSeverities = []ownSeverity{{"CRITICAL", 5}, {"ERROR", 4}, {"WARNING", 3}, {"NOTICE", 2}}

// ownCondition is one condition of the form: the place, the test, "not",
// and the value.
type ownCondition struct {
	Place      string `json:"place"`
	Key        string `json:"key,omitempty"`
	Test       string `json:"test"`
	Not        bool   `json:"not,omitempty"`
	Value      string `json:"value"`
	IgnoreCase bool   `json:"ignore_case,omitempty"`
}

// ownForm is an own rule as the form gives it (N1): conditions that must
// all match, a message, a severity, and the applications it is for, empty
// for every request ("none": requests of no application).
type ownForm struct {
	Msg          string         `json:"msg"`
	Severity     string         `json:"severity"`
	Applications []string       `json:"applications,omitempty"`
	Conditions   []ownCondition `json:"conditions"`
}

// Limits of the form and of a rule's text.
const (
	maxOwnConditions = 10
	maxOwnMsg        = 200
	maxOwnValue      = 2000
	maxOwnKey        = 100
	maxOwnText       = 64 << 10
)

// ownHeader starts an own-rules file the dashboard makes.
const ownHeader = `# Own rules of this IDS (docs/development-plan-own-rules.md), written with
# the dashboard. Each rule only detects: when all its conditions match, it
# adds its severity's points to the request's score. The IDS checks the
# rules when it loads them; edit them in the dashboard, which keeps every
# version.
`

func findPlace(name string) *ownPlace {
	for i := range ownPlaces {
		if ownPlaces[i].Name == name {
			return &ownPlaces[i]
		}
	}
	return nil
}

func findTest(name string) *ownTest {
	for i := range ownTests {
		if ownTests[i].Name == name {
			return &ownTests[i]
		}
	}
	return nil
}

// cleanText checks a value of the form: text of at most max characters,
// without control characters or "%{", which starts a variable in SecLang.
func cleanText(what, s string, max int) error {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return fmt.Errorf("%s: give text of at most %d characters", what, max)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s: write it on one line, without control characters", what)
	}
	if strings.Contains(s, "%{") {
		return fmt.Errorf("%s: %%{ starts a variable in a rule; write it another way", what)
	}
	return nil
}

func validOwnKey(s string) bool {
	if s == "" || len(s) > maxOwnKey {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// check checks the form and puts it in its usual shape: values trimmed,
// the severity in upper case, each application once.
func (f *ownForm) check() error {
	f.Msg = strings.TrimSpace(f.Msg)
	if f.Msg == "" {
		return errors.New("give a message: it says what the rule found, with every match")
	}
	if err := cleanText("the message", f.Msg, maxOwnMsg); err != nil {
		return err
	}
	f.Severity = strings.ToUpper(strings.TrimSpace(f.Severity))
	if engine.OwnScore(f.Severity) == "" {
		return errors.New("give a severity: CRITICAL, ERROR, WARNING or NOTICE")
	}
	var apps []string
	for _, a := range f.Applications {
		a = strings.TrimSpace(a)
		if !validAppName(a) {
			return fmt.Errorf("application %q: not an application's name", a)
		}
		if !slices.Contains(apps, a) {
			apps = append(apps, a)
		}
	}
	f.Applications = apps
	if len(f.Conditions) == 0 || len(f.Conditions) > maxOwnConditions {
		return fmt.Errorf("give 1 to %d conditions", maxOwnConditions)
	}
	for i := range f.Conditions {
		c := &f.Conditions[i]
		n := i + 1
		p := findPlace(c.Place)
		if p == nil {
			return fmt.Errorf("condition %d: choose the place it looks at", n)
		}
		c.Key = strings.TrimSpace(c.Key)
		switch {
		case p.Key == "" && c.Key != "":
			return fmt.Errorf("condition %d: %s takes no name", n, strings.ToLower(p.Label))
		case p.Key == "required" && c.Key == "":
			return fmt.Errorf("condition %d: name the %s", n, strings.ToLower(p.Label))
		case c.Key != "" && !validOwnKey(c.Key):
			return fmt.Errorf("condition %d: name %q: use letters, digits, ., - and _", n, c.Key)
		}
		t := findTest(c.Test)
		if t == nil {
			return fmt.Errorf("condition %d: choose its test", n)
		}
		if t.Name == "ipMatch" && p.Name != "REMOTE_ADDR" {
			return fmt.Errorf("condition %d: only the client IP address is in addresses or ranges", n)
		}
		if t.Name == "ipMatch" && c.IgnoreCase {
			return fmt.Errorf("condition %d: addresses have no case", n)
		}
		c.Value = strings.TrimSpace(c.Value)
		if c.Value == "" {
			return fmt.Errorf("condition %d: give the value it tests", n)
		}
		if err := cleanText(fmt.Sprintf("condition %d", n), c.Value, maxOwnValue); err != nil {
			return err
		}
	}
	return nil
}

// quoteOp writes an operator for the double quotes of a SecRule.
func quoteOp(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// quoteAction writes an action's value in single quotes, inside the
// double quotes of the action list.
func quoteAction(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `'`, `\'`), `"`, `\"`) + "'"
}

// ownText writes the SecLang of an own rule from the form, in the layout
// of CRS's files: one action per line, each rule of the chain indented
// below the first, the score on the last (section 3 of the plan).
func ownText(id int, f ownForm) (string, error) {
	if err := f.check(); err != nil {
		return "", err
	}
	phase := 1
	for _, c := range f.Conditions {
		if findPlace(c.Place).Body {
			phase = 2
		}
	}
	var b strings.Builder
	want := make([]seclang.Operator, len(f.Conditions))
	for i, c := range f.Conditions {
		variable := c.Place
		if c.Key != "" {
			variable += ":" + c.Key
		}
		value := c.Value
		ts := []string{"t:none"}
		if c.IgnoreCase {
			if findTest(c.Test).Text {
				value = strings.ToLower(value)
				ts = append(ts, "t:lowercase")
			} else {
				value = "(?i)" + value
			}
		}
		want[i] = seclang.Operator{Name: c.Test, Argument: value, Negated: c.Not}
		op := "@" + c.Test + " " + value
		if c.Not {
			op = "!" + op
		}
		var actions []string
		if i == 0 {
			actions = append(actions, fmt.Sprintf("id:%d", id), fmt.Sprintf("phase:%d", phase), "block",
				"msg:"+quoteAction(f.Msg), "severity:"+quoteAction(f.Severity), "tag:'paranoia-level/1'")
			for _, a := range f.Applications {
				actions = append(actions, "tag:"+quoteAction(engine.ApplicationTag+a))
			}
		}
		actions = append(actions, ts...)
		if i < len(f.Conditions)-1 {
			actions = append(actions, "chain")
		} else {
			actions = append(actions, "setvar:"+quoteAction(engine.OwnScore(f.Severity)))
		}
		indent := strings.Repeat("    ", min(i, 1))
		fmt.Fprintf(&b, "%sSecRule %s \"%s\" \\\n", indent, variable, quoteOp(op))
		fmt.Fprintf(&b, "%s    \"%s\"\n", indent, strings.Join(actions, ",\\\n"+indent+"    "))
	}
	text := b.String()

	// What the rule says must be what the form said: a value with a
	// backslash before a quote, or at its end, would be read otherwise.
	ds, err := seclang.Parse("rule", strings.NewReader(text))
	if err != nil || len(ds) != len(f.Conditions) {
		return "", errors.New("the rule can't be written as the form says; leave out a backslash at the end of a value or before a quote")
	}
	for i, d := range ds {
		if d.Operator != want[i] {
			return "", fmt.Errorf("condition %d: its value can't be written in a rule as it is; leave out a backslash at its end or before a quote", i+1)
		}
	}
	if msg := ds[0].ActionValues("msg"); len(msg) != 1 || msg[0] != f.Msg {
		return "", errors.New("the message can't be written in a rule as it is; leave out a backslash before a quote")
	}
	return text, nil
}

// formOf reads a rule's text back into the form: it can when the form
// writes the rule exactly so. Otherwise the rule is edited as text, by an
// admin (N1).
func formOf(id int, text string) (*ownForm, bool) {
	ds, err := seclang.Parse("rule", strings.NewReader(text))
	if err != nil || len(ds) == 0 {
		return nil, false
	}
	f := &ownForm{}
	if v := ds[0].ActionValues("msg"); len(v) > 0 {
		f.Msg = v[len(v)-1]
	}
	if v := ds[0].ActionValues("severity"); len(v) > 0 {
		f.Severity = v[len(v)-1]
	}
	for _, tag := range ds[0].ActionValues("tag") {
		if name, ok := strings.CutPrefix(tag, engine.ApplicationTag); ok {
			f.Applications = append(f.Applications, name)
		}
	}
	for _, d := range ds {
		if len(d.Variables) != 1 {
			return nil, false
		}
		v := d.Variables[0]
		c := ownCondition{Place: v.Collection, Key: v.Selector, Test: d.Operator.Name, Not: d.Operator.Negated, Value: d.Operator.Argument}
		if slices.Contains(d.ActionValues("t"), "lowercase") {
			c.IgnoreCase = true
		} else if rest, ok := strings.CutPrefix(c.Value, "(?i)"); ok && c.Test == "rx" {
			c.Value, c.IgnoreCase = rest, true
		}
		f.Conditions = append(f.Conditions, c)
	}
	again, err := ownText(id, *f)
	if err != nil || again != strings.TrimRight(text, "\n")+"\n" {
		return nil, false
	}
	return f, true
}

// oneOwnRule reads the text of a change: exactly one rule, the first
// SecRule and the ones chained to it.
func oneOwnRule(text string) (engine.OwnRule, error) {
	if len(text) == 0 || len(text) > maxOwnText {
		return engine.OwnRule{}, fmt.Errorf("give the rule's text, at most %d bytes", maxOwnText)
	}
	rules, err := engine.ParseOwnRules("rule", []byte(text))
	if err != nil {
		return engine.OwnRule{}, err
	}
	if len(rules) != 1 {
		return engine.OwnRule{}, fmt.Errorf("give one rule, with the rules chained to it; this text has %d", len(rules))
	}
	return rules[0], nil
}

// forWhom says which requests an own rule is for.
func forWhom(apps []string) string {
	if len(apps) == 0 {
		return "every request"
	}
	names := make([]string, len(apps))
	for i, a := range apps {
		names[i] = a
		if a == profile.NoApplication {
			names[i] = "requests of no application"
		}
	}
	return strings.Join(names, ", ")
}

// ---- The own-rules file in a change ----

// ownPath is where the dashboard makes a configuration's own-rules file:
// own-rules/NAME.conf beside the profiles folder (stage 3).
func ownPath(config string) string {
	name := strings.TrimSuffix(filepath.Base(config), filepath.Ext(config))
	return filepath.Join(filepath.Dir(filepath.Dir(config)), "own-rules", name+".conf")
}

// ownFile returns the own-rules file of the change, as text. A
// configuration without own_rules gets one, with a new file; a file of
// that name already there, left by a change that was undone, is not its
// rules, so it starts again (the version keeps it).
func (w *work) ownFile() (*workFile, error) {
	cfg, err := w.config.current()
	if err != nil {
		return nil, err
	}
	var rel string
	set := cfg.Get("own_rules") != nil && cfg.Get("own_rules").Decode(&rel) == nil && rel != ""
	path := rel
	if !set {
		path = ownPath(w.c.path)
		r, err := filepath.Rel(filepath.Dir(w.c.path), path)
		if err != nil {
			r = path
		}
		cfg.SetAfter("own_rules", jsonedit.Must(filepath.ToSlash(r)), "exclude", "files")
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(w.c.path), path)
	}
	if f := w.files[path]; f != nil {
		if !set {
			f.raw = []byte(ownHeader)
		}
		return f, nil
	}
	data, err := os.ReadFile(path)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, err
	}
	f := &workFile{path: path, before: data, created: missing, raw: append([]byte{}, data...)}
	if missing || !set {
		f.raw = []byte(ownHeader)
	}
	w.files[path] = f
	w.order = append(w.order, path)
	return f, nil
}

// applyOwn adds, replaces or removes one rule of the own-rules file.
func (w *work) applyOwn(ch pendingChange) error {
	f, err := w.ownFile()
	if err != nil {
		return err
	}
	raw, err := editOwn(f.path, f.raw, ch)
	if err != nil {
		return err
	}
	f.raw = raw
	return nil
}

// editOwn makes an own-rule change to the content of an own-rules file:
// a new rule goes at the end, after a blank line; a changed one takes the
// lines of the old one; a removed one goes with the blank line after it.
func editOwn(name string, raw []byte, ch pendingChange) ([]byte, error) {
	rules, err := engine.ParseOwnRules(name, raw)
	if err != nil {
		return nil, fmt.Errorf("the own-rules file can't be read: %w", err)
	}
	i := slices.IndexFunc(rules, func(r engine.OwnRule) bool { return r.ID == ch.Rule })
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	rule := strings.Split(strings.TrimRight(ch.Text, "\n"), "\n")
	switch {
	case ch.Kind == kindOwnRuleAdd && i >= 0:
		return nil, fmt.Errorf("the own rules have a rule %d already", ch.Rule)
	case ch.Kind != kindOwnRuleAdd && i < 0:
		return nil, fmt.Errorf("the own rules have no rule %d", ch.Rule)
	case ch.Kind == kindOwnRuleAdd:
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, rule...)
	case ch.Kind == kindOwnRuleEdit:
		r := rules[i]
		lines = slices.Concat(lines[:r.Line-1], rule, lines[r.End:])
	default:
		r := rules[i]
		start, end := r.Line-1, r.End
		// The blank line after it goes with it, or the one before it at
		// the end of the file.
		if end < len(lines) && strings.TrimSpace(lines[end]) == "" {
			end++
		} else if start > 0 && strings.TrimSpace(lines[start-1]) == "" {
			start--
		}
		lines = slices.Delete(lines, start, end)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// ---- Rule numbers (N3) ----

// nextOwnID is the number after the highest of used, from 1,000 on, so a
// new rule never takes the number of one removed, whose records are kept.
func nextOwnID(used ...[]int) (int, error) {
	next := engine.OwnFirstID
	for _, list := range used {
		for _, id := range list {
			if id >= next {
				next = id + 1
			}
		}
	}
	if next > engine.OwnLastID {
		return 0, fmt.Errorf("own rules have used every number up to %d", engine.OwnLastID)
	}
	return next, nil
}

// ownIDs returns the own rules' numbers of every run the records have.
func (s *store) ownIDs() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []int
	for _, rules := range s.rules {
		for _, r := range rules {
			if r.Own {
				ids = append(ids, r.ID)
			}
		}
	}
	return ids
}

// ---- The API of the form ----

// ownRuleRow is one own rule of the configuration on disk. Form is the rule
// in the form, when the form writes it exactly so; nil for a rule only
// its text can show (N1).
type ownRuleRow struct {
	engine.OwnRule
	Form *ownForm `json:"form"`
}

// ownRulesAnswer is what the Rules page and the New rule form need: the own
// rules on disk, and the form's choices.
type ownRulesAnswer struct {
	Configured bool `json:"configured"`
	// File is the configuration's own_rules setting as written, "" when
	// it has none yet: the first rule sets it.
	File  string       `json:"file,omitempty"`
	Rules []ownRuleRow `json:"rules"`
	// Error says why the configuration or its own rules can't be read.
	Error        string        `json:"error,omitempty"`
	Applications []string      `json:"applications"`
	Places       []ownPlace    `json:"places"`
	Tests        []ownTest     `json:"tests"`
	Severities   []ownSeverity `json:"severities"`
}

func (s *Server) apiOwnRules(w http.ResponseWriter, r *http.Request) {
	a := ownRulesAnswer{Configured: s.control.path != "", Rules: []ownRuleRow{}, Applications: []string{},
		Places: ownPlaces, Tests: ownTests, Severities: ownSeverities}
	if a.Configured {
		p, err := config.Load(s.control.path)
		if err != nil {
			a.Error = "the configuration does not load: " + err.Error()
			writeJSON(w, http.StatusOK, a)
			return
		}
		for _, app := range p.Applications {
			a.Applications = append(a.Applications, app.Name)
		}
		if p.OwnRules != "" {
			a.File = filepath.Base(p.OwnRules)
			rules, err := engine.ReadOwnRules(p.Config)
			if err != nil {
				a.Error = "the own rules can't be read: " + err.Error()
			}
			for _, rule := range rules {
				f, _ := formOf(rule.ID, rule.Text)
				a.Rules = append(a.Rules, ownRuleRow{OwnRule: rule, Form: f})
			}
		}
	}
	writeJSON(w, http.StatusOK, a)
}

// ownDraft is a request of the New rule form: the rule it would add or
// change, before it is added (N1, N3).
type ownDraft struct {
	// Rule is the rule changed, 0 for a new one.
	Rule int      `json:"rule,omitempty"`
	Own  *ownForm `json:"own,omitempty"`
	Text string   `json:"text,omitempty"`
}

// apiOwnDraft answers with the rule the form would add: its number, its
// text, and why it can't be added, if it can't, together with the
// pending changes for every application.
func (s *Server) apiOwnDraft(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	var d ownDraft
	if err := readJSON(w, r, maxChangeBody, &d); err != nil {
		badRequest(w, err)
		return
	}
	if s.control.path == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": errNoConfig.Error()})
		return
	}
	ch := pendingChange{Kind: kindOwnRuleAdd, Rule: d.Rule, Own: d.Own, Text: d.Text, User: user}
	if d.Rule != 0 {
		ch.Kind = kindOwnRuleEdit
	}
	if !allows(s.auth.users.role(user), RoleAdmin) && !analystMay(objectGlobal, ch) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "an analyst writes own rules with the form; their text is an admin's"})
		return
	}
	answer := map[string]any{"rule": ch.Rule, "text": ch.Text}
	got, err := s.control.try(objectGlobal, ch)
	if got.Rule != 0 {
		answer["rule"] = got.Rule
	}
	if got.Text != "" {
		answer["text"] = got.Text
	}
	if err != nil {
		answer["error"] = err.Error()
	} else {
		answer["what"] = got.What
	}
	writeJSON(w, http.StatusOK, answer)
}
