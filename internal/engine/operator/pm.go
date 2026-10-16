package operator

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// pm is the family @pm and @pmFromFile: it matches when the value contains
// any phrase of a list. ASCII letters are compared without regard to case.
//
//	@pm document.cookie document.write       phrases separated by spaces
//	@pmFromFile lfi-os-files.data            one phrase per line of a file
//
// A data file is read once, when the rules are loaded. Its path is taken
// from the directory of the rule file that names it. Empty lines and lines
// starting with "#" are skipped.
//
// The list can hold more than a thousand phrases, so the value is not
// searched once per phrase. The phrases are built into one automaton
// (Aho-Corasick) that reads the value a single time.
//
// On a match, the first capture is the phrase that was found, as it is
// written in the value.
//
// Difference from ModSecurity: its @pm also accepts bytes written as
// |41 42| inside a phrase. That form is rejected here.
type pm struct {
	nodes []pmNode
	// root gives the next state from the start state for every byte, or 0
	// to stay there. The start state is the one visited most, so it gets a
	// full table.
	root *[256]int32
}

// pmNode is one state of the automaton.
type pmNode struct {
	next map[byte]int32 // the state after reading a byte; used while building
	// edges is next as a list sorted by byte, which is quicker to search
	// than a map for the few bytes most states have.
	edges []pmEdge
	fail  int32 // where to continue when no next state fits
	// length is the length of the longest phrase that ends in this state,
	// taking the fail links into account; 0 if none ends here.
	length int32
}

type pmEdge struct {
	c    byte
	next int32
}

// step returns the state after reading c in state, or -1.
func (n *pmNode) step(c byte) int32 {
	for _, e := range n.edges {
		if e.c == c {
			return e.next
		}
		if e.c > c {
			break
		}
	}
	return -1
}

func newPm(argument string) (Operator, error) {
	if strings.Contains(argument, "|") {
		return nil, errors.New("a phrase with |hex| bytes is not supported")
	}
	phrases := strings.Fields(argument)
	if len(phrases) == 0 {
		return nil, errors.New("no phrases given")
	}
	return buildPm(phrases), nil
}

// newPmFromFile returns the constructor for @pmFromFile. dir is the
// directory of the rule file.
func newPmFromFile(dir string) constructor {
	return func(argument string) (Operator, error) {
		name := strings.TrimSpace(argument)
		if name == "" || strings.ContainsAny(name, " \t") {
			return nil, fmt.Errorf("exactly one data file is expected, found %q", argument)
		}
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		var phrases []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			phrases = append(phrases, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(phrases) == 0 {
			return nil, fmt.Errorf("%s holds no phrases", path)
		}
		return buildPm(phrases), nil
	}
}

func buildPm(phrases []string) pm {
	nodes := []pmNode{{next: map[byte]int32{}}}
	for _, phrase := range phrases {
		state := int32(0)
		for i := 0; i < len(phrase); i++ {
			c := lowerASCII(phrase[i])
			next, ok := nodes[state].next[c]
			if !ok {
				next = int32(len(nodes))
				nodes = append(nodes, pmNode{next: map[byte]int32{}})
				nodes[state].next[c] = next
			}
			state = next
		}
		if int32(len(phrase)) > nodes[state].length {
			nodes[state].length = int32(len(phrase))
		}
	}

	// Set the fail links level by level, so that a node's parent is always
	// finished before the node itself.
	queue := make([]int32, 0, len(nodes))
	for _, child := range nodes[0].next {
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for c, child := range nodes[state].next {
			fail := nodes[state].fail
			for fail != 0 {
				if _, ok := nodes[fail].next[c]; ok {
					break
				}
				fail = nodes[fail].fail
			}
			if target, ok := nodes[fail].next[c]; ok && target != child {
				fail = target
			}
			nodes[child].fail = fail
			if nodes[child].length == 0 {
				nodes[child].length = nodes[fail].length
			}
			queue = append(queue, child)
		}
	}
	// Turn the maps into sorted lists and the start state into a table.
	root := new([256]int32)
	for c, next := range nodes[0].next {
		root[c] = next
	}
	for i := range nodes {
		for c, next := range nodes[i].next {
			nodes[i].edges = append(nodes[i].edges, pmEdge{c: c, next: next})
		}
		slices.SortFunc(nodes[i].edges, func(a, b pmEdge) int { return int(a.c) - int(b.c) })
		nodes[i].next = nil
	}
	return pm{nodes: nodes, root: root}
}

func (o pm) Match(value string, _ func(string) string) Result {
	state := int32(0)
	for i := 0; i < len(value); i++ {
		c := lowerASCII(value[i])
		for {
			if state == 0 {
				state = o.root[c]
				break
			}
			if next := o.nodes[state].step(c); next >= 0 {
				state = next
				break
			}
			state = o.nodes[state].fail
		}
		if n := int(o.nodes[state].length); n > 0 {
			return Result{Matched: true, Captures: []string{value[i+1-n : i+1]}}
		}
	}
	return Result{}
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
