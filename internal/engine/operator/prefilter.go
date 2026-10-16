package operator

import (
	"regexp/syntax"
	"strings"
)

// A prefilter is a quick test that comes before a regular expression: a set
// of words such that every text the expression matches contains at least
// one of them. A value that contains none of the words cannot match, and the
// expression is not run on it.
//
//	(?i)union\s+select      every match contains "union" (or "select")
//	(?:eval|exec)\(         every match contains "eval" or "exec"
//
// Words are compared without regard to the case of ASCII letters, which can
// only let more values through than the expression itself would accept.
// The test is used only on values that are pure ASCII: with (?i), Go's
// expressions also let some other letters stand for ASCII ones (U+017F for
// "s", U+212A for "k"), which a word search would not see.
//
// The prefilter only ever skips values the expression cannot match, so it
// changes no result; TestPrefilterNeverHidesAMatch checks that on the CRS
// patterns.
type prefilter struct {
	words pm
}

// minWordLength is the shortest word worth a prefilter. With a single
// character the test would let almost every value through. Two characters
// are enough for many CRS patterns, such as ":/" in URL schemes.
const minWordLength = 2

// maxWords limits the size of the set.
const maxWords = 2000

// newPrefilter returns the prefilter for an expression, or nil when there
// is no useful set of words.
func newPrefilter(re *syntax.Regexp) *prefilter {
	words, ok := requiredWords(re.Simplify())
	if !ok || len(words) == 0 || len(words) > maxWords {
		return nil
	}
	for _, w := range words {
		if len(w) < minWordLength {
			return nil
		}
	}
	return &prefilter{words: buildPm(words)}
}

// mayMatch reports whether the expression can match the value. It is only
// meaningful for a value that is pure ASCII.
func (p *prefilter) mayMatch(value string) bool {
	return p.words.Match(value, nil).Matched
}

// requiredWords returns a set of words of which every match of re contains
// at least one, in lower case. ok is false when no such set is known.
func requiredWords(re *syntax.Regexp) (words []string, ok bool) {
	if exact, ok := exactTexts(re); ok && shortest(exact) > 0 {
		return exact, true
	}
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return requiredWords(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min < 1 {
			return nil, false
		}
		return requiredWords(re.Sub[0])

	case syntax.OpConcat:
		// Every part is in every match, so any part's set will do, and
		// so will the joined texts of neighbouring parts whose texts are
		// all known: in e(?:val|xec) that is {eval, exec}. The set whose
		// shortest word is longest lets the fewest values through.
		best, bestLen := []string(nil), -1
		consider := func(w []string) {
			if n := shortest(w); n > bestLen {
				best, bestLen = w, n
			}
		}
		var run []string // the joined texts of the current run of known parts
		inRun := false
		for _, sub := range re.Sub {
			if exact, ok := exactTexts(sub); ok {
				if !inRun {
					run, inRun = exact, true
				} else if joined, ok := join(run, exact); ok {
					run = joined
				} else {
					consider(run)
					run = exact
				}
				continue
			}
			if inRun {
				consider(run)
				inRun = false
			}
			if w, ok := requiredWords(sub); ok {
				consider(w)
			}
		}
		if inRun {
			consider(run)
		}
		return best, bestLen > 0

	case syntax.OpAlternate:
		// A match comes from one of the branches, so the sets are
		// joined; a branch without a set means there is none.
		var all []string
		for _, sub := range re.Sub {
			w, ok := requiredWords(sub)
			if !ok {
				return nil, false
			}
			all = append(all, w...)
		}
		return all, true
	}
	// Character classes, any character, anchors, empty matches, and
	// repetitions that may be empty require no word.
	return nil, false
}

// maxTexts limits the sets that exactTexts builds.
const maxTexts = 256

// exactTexts returns every text re can match, in lower case, when they are
// few and known: a literal, a small class of ASCII characters, or a
// sequence, choice or optional part made of those. ok is false otherwise.
func exactTexts(re *syntax.Regexp) (texts []string, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		word := string(re.Rune)
		if !isASCII(word) {
			// Folding of other letters is not handled by the word
			// search, so such a text is not known exactly.
			return nil, false
		}
		return []string{strings.ToLower(word)}, true

	case syntax.OpCharClass:
		var chars []string
		seen := map[string]bool{}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi > 0x7f || hi-lo > 8 {
				return nil, false
			}
			for c := lo; c <= hi; c++ {
				if lower := strings.ToLower(string(c)); !seen[lower] {
					seen[lower] = true
					chars = append(chars, lower)
				}
			}
		}
		if len(chars) == 0 || len(chars) > 8 {
			return nil, false
		}
		return chars, true

	case syntax.OpCapture:
		return exactTexts(re.Sub[0])

	case syntax.OpQuest:
		inner, ok := exactTexts(re.Sub[0])
		if !ok || len(inner) >= maxTexts {
			return nil, false
		}
		return append(inner, ""), true

	case syntax.OpConcat:
		texts := []string{""}
		for _, sub := range re.Sub {
			next, ok := exactTexts(sub)
			if !ok {
				return nil, false
			}
			if texts, ok = join(texts, next); !ok {
				return nil, false
			}
		}
		return texts, true

	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			next, ok := exactTexts(sub)
			if !ok {
				return nil, false
			}
			all = append(all, next...)
			if len(all) > maxTexts {
				return nil, false
			}
		}
		return all, true

	case syntax.OpEmptyMatch:
		return []string{""}, true
	}
	return nil, false
}

// join returns every text of a followed by every text of b, if there are
// not too many.
func join(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxTexts {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out, true
}

func shortest(words []string) int {
	n := -1
	for _, w := range words {
		if n < 0 || len(w) < n {
			n = len(w)
		}
	}
	return n
}
