package engine

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/engine/operator"
	"github.com/EfeSipahi/ids-system/internal/engine/transform"
	"github.com/EfeSipahi/ids-system/internal/seclang"
)

// Load reads the rule files of cfg and prepares them for use.
//
// Load fails unless every rule that is not excluded can be run completely.
// The error lists every problem with its file and line, so an unsupported
// operator, transformation, action or variable is found here and never
// while a request is being checked (M15).
func Load(cfg Config) (*RuleSet, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := &compiler{
		rs: &RuleSet{
			level: cfg.Level(),
			// What CRS's own setup rule 900000 does: it sets the blocking
			// level, and rule 901 derives the detection level from it.
			initial: map[string]string{"blocking_paranoia_level": strconv.Itoa(cfg.Level())},
		},
		byID:      map[int]*rule{},
		excluded:  map[int]string{},
		ids:       map[int]seclang.Position{},
		markers:   map[string]bool{},
		defaults:  map[int]defaults{},
		usedExcl:  map[int]bool{},
		skipSites: map[string]seclang.Position{},
	}
	for _, ex := range cfg.Exclude {
		c.excluded[ex.ID] = ex.Reason
	}

	for _, file := range cfg.Files {
		directives, err := seclang.ParseFile(file)
		if err != nil {
			return nil, err
		}
		c.addFile(directives)
	}

	for marker, pos := range c.skipSites {
		if !c.markers[marker] {
			c.errorf(pos, "skipAfter names marker %s, which is in none of the loaded files", marker)
		}
	}
	for _, ex := range cfg.Exclude {
		if !c.usedExcl[ex.ID] {
			c.errs = append(c.errs, fmt.Errorf("excluded rule %d is in none of the loaded files", ex.ID))
		}
	}
	if len(c.errs) > 0 {
		return nil, errors.Join(c.errs...)
	}

	c.markSensitiveTexts()
	return c.rs, nil
}

// markSensitiveTexts works out which rules have a msg or logdata that can
// carry request content, so the output layer can hide it (M11).
//
// A TX variable is tainted when some setvar fills it from the matched value,
// from a capture, or from another tainted variable. The loop repeats until
// no new variable is found, because taint can pass through several setvars.
func (c *compiler) markSensitiveTexts() {
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, first := range c.rules {
			for r := first; r != nil; r = r.next {
				for _, sv := range r.setvars {
					if !sv.unset && !tainted[sv.key] && sv.value.usesRequestContent(tainted) {
						tainted[sv.key] = true
						changed = true
					}
				}
			}
		}
	}
	for _, first := range c.rules {
		first.msgSensitive = first.msg.usesRequestContent(tainted)
		first.logdataSensitive = first.logdata.usesRequestContent(tainted)
	}
}

// compiler holds what is needed while the files are turned into a RuleSet.
type compiler struct {
	rs    *RuleSet
	errs  []error
	rules []*rule // the first rule of every active chain
	byID  map[int]*rule

	excluded  map[int]string // rule id -> reason, from the configuration
	usedExcl  map[int]bool
	ids       map[int]seclang.Position
	markers   map[string]bool
	skipSites map[string]seclang.Position // marker -> a rule that jumps to it
	defaults  map[int]defaults            // phase -> SecDefaultAction in force
}

// defaults is what a SecDefaultAction gives to the rules of its phase.
type defaults struct {
	log        bool
	action     string
	transforms []string
}

func (c *compiler) errorf(pos seclang.Position, format string, args ...any) {
	c.errs = append(c.errs, &seclang.Error{Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

func (c *compiler) addFile(directives []seclang.Directive) {
	for i := 0; i < len(directives); i++ {
		d := directives[i]
		switch d.Kind {
		case seclang.KindComponentSignature:
			c.rs.signature = d.Text

		case seclang.KindMarker:
			c.markers[d.Text] = true
			for p := range c.rs.phases {
				c.rs.phases[p] = append(c.rs.phases[p], item{marker: d.Text})
			}

		case seclang.KindDefaultAction:
			c.addDefaults(d)

		case seclang.KindUpdateTargetByID:
			c.updateTargets(d)

		case seclang.KindRule, seclang.KindAction:
			// A chain is the starter and the chained rules after it.
			end := i + 1
			for end < len(directives) && directives[end].Chained {
				end++
			}
			c.addRule(directives[i:end])
			i = end - 1
		}
	}
}

// updateTargets applies a SecRuleUpdateTargetById: its variables are added
// to the variable list of a rule that was loaded before it. CRS uses this
// to stop rules from looking at cookies known to be harmless.
//
// An update for a rule that is not active is not an error, because the CRS
// file of updates names rules of many files. It is recorded so the startup
// report can show it.
func (c *compiler) updateTargets(d seclang.Directive) {
	r, ok := c.byID[d.TargetID]
	if !ok {
		c.rs.ignoredUpdates = append(c.rs.ignoredUpdates, d.TargetID)
		return
	}
	for _, v := range d.Variables {
		t, err := compileTarget(v)
		switch {
		case err != nil:
			c.errorf(d.Pos, "SecRuleUpdateTargetById %d: %v", d.TargetID, err)
		case v.Exclude:
			r.excludes = append(r.excludes, t)
		default:
			r.targets = append(r.targets, t)
		}
	}
}

func (c *compiler) addDefaults(d seclang.Directive) {
	def := defaults{action: "pass"}
	phase := 0
	for _, a := range d.Actions {
		switch strings.ToLower(a.Name) {
		case "phase":
			phase, _ = strconv.Atoi(a.Value)
		case "log":
			def.log = true
		case "nolog":
			def.log = false
		case "pass", "deny":
			def.action = strings.ToLower(a.Name)
		case "t":
			def.transforms = append(def.transforms, a.Value)
		case "auditlog", "noauditlog", "status":
			// These concern audit logging and blocking, which the
			// engine does not do.
		default:
			c.errorf(d.Pos, "SecDefaultAction: action %s is not supported", a.Name)
		}
	}
	if phase < 1 || phase > 5 {
		c.errorf(d.Pos, "SecDefaultAction needs a phase from 1 to 5")
		return
	}
	c.defaults[phase] = def
}

// addRule compiles one rule or chain, or records it as excluded.
func (c *compiler) addRule(chain []seclang.Directive) {
	first := chain[0]
	if prev, dup := c.ids[first.ID]; dup {
		c.errorf(first.Pos, "rule id %d is already used at %s", first.ID, prev)
		return
	}
	c.ids[first.ID] = first.Pos

	status := RuleStatus{ID: first.ID, Pos: first.Pos, Phase: phaseOf(first), ParanoiaLevel: levelOf(first)}
	if reason, ok := c.excluded[first.ID]; ok {
		c.usedExcl[first.ID] = true
		status.Reason = reason
		c.rs.statuses = append(c.rs.statuses, status)
		return
	}

	before := len(c.errs)
	var head, tail *rule
	for i, d := range chain {
		r := c.compileOne(d, first, i > 0)
		if head == nil {
			head = r
		} else {
			tail.next = r
		}
		tail = r
	}
	if len(c.errs) > before {
		return
	}

	status.Active = true
	c.rs.statuses = append(c.rs.statuses, status)
	c.rs.phases[head.phase] = append(c.rs.phases[head.phase], item{rule: head})
	c.rules = append(c.rules, head)
	c.byID[head.id] = head
	if head.skipAfter != "" {
		c.skipSites[head.skipAfter] = head.pos
	}
}

// phaseOf returns the phase a rule names. ModSecurity's default is 2.
// levelOf returns N of the tag "paranoia-level/N", or 0 without such a tag.
func levelOf(d seclang.Directive) int {
	for _, tag := range d.ActionValues("tag") {
		if level, ok := strings.CutPrefix(tag, "paranoia-level/"); ok {
			n, _ := strconv.Atoi(level)
			return n
		}
	}
	return 0
}

func phaseOf(d seclang.Directive) int {
	if values := d.ActionValues("phase"); len(values) > 0 {
		n, _ := strconv.Atoi(values[len(values)-1])
		return n
	}
	return phaseRequestBody
}

// compileOne compiles one directive of a chain. Problems are added to
// c.errs with the position of the directive and the id of the chain.
func (c *compiler) compileOne(d, first seclang.Directive, chained bool) *rule {
	fail := func(format string, args ...any) {
		c.errorf(d.Pos, "rule %d: %s", first.ID, fmt.Sprintf(format, args...))
	}
	r := &rule{id: first.ID, pos: d.Pos, phase: phaseOf(first)}
	if r.phase != phaseRequestHeaders && r.phase != phaseRequestBody {
		if !chained {
			fail("phase %d is not supported; only request phases 1 and 2 are", r.phase)
		}
		r.phase = phaseRequestBody
	}
	def := c.defaults[r.phase]

	if d.Kind == seclang.KindAction {
		r.always = true
	} else {
		c.compileTargets(d, r, fail)

		op, err := operator.New(d.Operator.Name, d.Operator.Argument, d.Operator.Negated, filepath.Dir(d.Pos.File))
		if err != nil {
			fail("%v", err)
		}
		r.op = op
		if r.opArg, err = parseTemplate(d.Operator.Argument); err != nil {
			fail("operator argument: %v", err)
		}
	}

	transforms := append([]string(nil), def.transforms...)
	r.log, r.action = def.log, def.action
	for _, a := range d.Actions {
		name := strings.ToLower(a.Name)
		if chained && !allowedInChain[name] {
			fail("action %s is not supported on a chained rule", a.Name)
			continue
		}
		switch name {
		case "id", "phase", "chain", "ver", "status", "auditlog", "noauditlog":
			// id, phase and chain are already handled. The others
			// concern audit logging and blocking.
		case "t":
			transforms = append(transforms, a.Value)
		case "multimatch":
			r.multiMatch = true
		case "capture":
			r.capture = true
		case "setvar":
			sv, err := parseSetvar(a.Value)
			if err != nil {
				fail("setvar:%s: %v", a.Value, err)
			}
			r.setvars = append(r.setvars, sv)
		case "log", "nolog":
			r.log = name == "log"
		case "pass", "deny":
			r.action = name
		case "block":
			// block means "do what SecDefaultAction says".
			r.action = def.action
		case "ctl":
			removal, err := parseCtl(a.Value)
			if err != nil {
				fail("ctl:%s: %v", a.Value, err)
			}
			r.removals = append(r.removals, removal)
		case "skipafter":
			r.skipAfter = a.Value
		case "msg":
			var err error
			if r.msg, err = parseTemplate(a.Value); err != nil {
				fail("msg: %v", err)
			}
		case "logdata":
			var err error
			if r.logdata, err = parseTemplate(a.Value); err != nil {
				fail("logdata: %v", err)
			}
		case "severity":
			r.severity = a.Value
		case "tag":
			r.tags = append(r.tags, a.Value)
		default:
			fail("action %s is not supported", a.Name)
		}
	}

	var err error
	if r.transforms, err = transform.Resolve(transforms); err != nil {
		fail("%v", err)
	}
	return r
}

// allowedInChain are the actions a chained rule may carry. Everything that
// describes or steers the rule as a whole belongs on the first rule.
var allowedInChain = map[string]bool{
	"t": true, "setvar": true, "capture": true, "multimatch": true, "chain": true,
}

func (c *compiler) compileTargets(d seclang.Directive, r *rule, fail func(string, ...any)) {
	for _, v := range d.Variables {
		t, err := compileTarget(v)
		switch {
		case err != nil:
			fail("%v", err)
		case v.Exclude && v.Count:
			fail("variable %s: ! and & cannot be combined", v)
		case v.Exclude:
			r.excludes = append(r.excludes, t)
		default:
			r.targets = append(r.targets, t)
		}
	}
}

// parseCtl compiles a ctl action. One form is supported:
//
//	ctl:ruleRemoveTargetByTag=TAG;VARIABLE
//
// TAG is a regular expression matched against the tags of every rule.
func parseCtl(s string) (targetRemoval, error) {
	name, value, _ := strings.Cut(s, "=")
	if !strings.EqualFold(name, "ruleRemoveTargetByTag") {
		return targetRemoval{}, errors.New("only ctl:ruleRemoveTargetByTag is supported")
	}
	tag, variable, ok := strings.Cut(value, ";")
	if !ok || tag == "" || variable == "" {
		return targetRemoval{}, errors.New("expected TAG;VARIABLE")
	}
	tagRe, err := regexp.Compile(tag)
	if err != nil {
		return targetRemoval{}, err
	}
	collection, selector, _ := strings.Cut(variable, ":")
	t, err := compileTarget(seclang.Variable{Collection: strings.ToUpper(collection), Selector: selector})
	if err != nil {
		return targetRemoval{}, err
	}
	return targetRemoval{tag: tagRe, target: t}, nil
}

// parseSetvar compiles the value of a setvar action:
//
//	tx.name=value    set
//	tx.name=+value   add to the current number
//	tx.name=-value   subtract from it
//	tx.name          set to 1
//	!tx.name         remove
func parseSetvar(s string) (setvar, error) {
	var sv setvar
	name, value, hasValue := strings.Cut(s, "=")
	if strings.HasPrefix(name, "!") {
		if hasValue {
			return sv, errors.New("! and = cannot be combined")
		}
		sv.unset = true
		name = name[1:]
	}
	if !hasValue {
		value = "1"
	}

	col, key, ok := strings.Cut(name, ".")
	if !ok || !strings.EqualFold(col, "tx") || key == "" {
		return sv, errors.New("only tx.name variables are supported")
	}
	if strings.Contains(key, "%{") {
		return sv, errors.New("a macro in the variable name is not supported")
	}
	sv.key = strings.ToLower(key)
	sv.relative = strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-")

	var err error
	sv.value, err = parseTemplate(value)
	return sv, err
}
