package result

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/profile"
)

// WriteStartup prints the startup report as text, as ids-offline and
// ids-live print it. With brief set, the excluded rules and the
// applications' exceptions are counted but not listed, and hint says how to
// list them, such as "run without -requests".
func WriteStartup(w io.Writer, s Startup, brief bool, hint string) {
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
		fmt.Fprintf(w, "  (%s to list the excluded rules and the reasons)\n", hint)
	}
	if n := len(s.IgnoredTargetUpdates); n > 0 {
		fmt.Fprintf(w, "Target updates for %d rules that are not active were ignored\n", n)
	}
	writeApplications(w, s, brief, hint)
}

// writeApplications prints the applications of the startup report. With
// brief set, the exceptions are counted but not listed; notes are always
// printed.
func writeApplications(w io.Writer, s Startup, brief bool, hint string) {
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
				fmt.Fprintf(w, "    %s: %s\n", ExceptionText(ex.Exception), ex.Reason)
			}
		}
		for _, n := range a.Notes {
			fmt.Fprintf(w, "    note: %s\n", n)
		}
	}
	if brief && slices.ContainsFunc(s.Applications, func(a AppStartup) bool { return len(a.Exceptions) > 0 }) {
		fmt.Fprintf(w, "  (%s to list the exceptions)\n", hint)
	}
}

// ExceptionText says what an exception changes, such as "rule 932350
// skips ARGS_NAMES:pwd".
func ExceptionText(ex profile.Exception) string {
	switch {
	case ex.Setting != "":
		return fmt.Sprintf("setting %s = %q", ex.Setting, *ex.Value)
	case ex.Off:
		return fmt.Sprintf("rule %d off", ex.Rule)
	default:
		return fmt.Sprintf("rule %d skips %s", ex.Rule, strings.Join(ex.Skip, ", "))
	}
}

// count writes n with the word, as "1 exception" or "2 exceptions".
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
