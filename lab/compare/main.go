// Command compare checks that two record folders hold the same request
// records, for the lab's equality check (T9): the records ids-offline wrote
// for request files, and those ids-live wrote for the same requests sent
// through Caddy.
//
//	go run ./lab/compare OFFLINE-DIR LIVE-DIR
//
// Records are compared as multisets, since the order in which requests
// arrive is not the order of the files. Each is reduced to its request
// line, its findings (rule, location, matched value), its score and
// alert, its analysis and its profile finding kinds. What must differ is
// left out: IDs, runs and times, cookie hashes (each folder has its own
// key), addresses, the header names (Go's server changes their case and
// order, C2), and the fields only a live record has. The header names are
// compared apart and their differences counted, as information.
//
// Exit status: 0 when the records are the same, 1 when they differ.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/record"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: compare OFFLINE-DIR LIVE-DIR")
		os.Exit(2)
	}
	a, err := load(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		os.Exit(2)
	}
	b, err := load(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("%s: %d request records, %d requests analysed\n", os.Args[1], len(a.keys), a.analysed)
	fmt.Printf("%s: %d request records, %d requests analysed\n", os.Args[2], len(b.keys), b.analysed)
	onlyA, onlyB := diff(a.keys, b.keys)
	headerA, headerB := diff(a.headers, b.headers)
	fmt.Printf("header name lists that differ (information, C2): %d of %d\n", len(headerA), len(a.headers))
	if len(headerA) > 0 && len(headerB) > 0 {
		// One example of each side; the lists are sorted, not paired.
		fmt.Printf("  for example, first: %s\n  for example, second: %s\n", headerA[0], headerB[0])
	}
	if len(onlyA) == 0 && len(onlyB) == 0 {
		fmt.Println("the request records are the same")
		return
	}
	fmt.Printf("only in the first: %d; only in the second: %d\n", len(onlyA), len(onlyB))
	for _, k := range onlyA {
		fmt.Println("< " + k)
	}
	for _, k := range onlyB {
		fmt.Println("> " + k)
	}
	os.Exit(1)
}

type folder struct {
	keys     []string // one per request record
	headers  []string // the header names of each record, in order
	analysed int
}

// finding and key are what is compared of a record.
type finding struct {
	Rule     int    `json:"rule"`
	Location string `json:"location,omitempty"`
	Matched  string `json:"matched,omitempty"`
}

type key struct {
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Query    string    `json:"query,omitempty"`
	Version  string    `json:"version,omitempty"`
	BodyLen  int       `json:"body_length"`
	Alert    bool      `json:"alert"`
	Score    int       `json:"score"`
	Complete bool      `json:"complete"`
	Body     string    `json:"body"`
	App      string    `json:"application,omitempty"`
	Profile  []string  `json:"profile,omitempty"`
	Findings []finding `json:"findings"`
}

func load(dir string) (folder, error) {
	files, err := record.RotatedFiles(dir)
	if err != nil {
		return folder{}, err
	}
	files = append(files, record.CurrentFile)
	var f folder
	for _, name := range files {
		file, err := os.Open(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return folder{}, err
		}
		sc := bufio.NewScanner(file)
		sc.Buffer(nil, 4<<20)
		for sc.Scan() {
			var head struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(sc.Bytes(), &head) != nil {
				continue
			}
			switch head.Type {
			case record.TypeCounts:
				var c record.Counts
				if json.Unmarshal(sc.Bytes(), &c) == nil {
					f.analysed += c.Analysed
				}
			case record.TypeRequest:
				var r record.Request
				if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
					file.Close()
					return folder{}, fmt.Errorf("%s: %v", name, err)
				}
				f.keys = append(f.keys, keyOf(r))
				f.headers = append(f.headers, strings.Join(r.HTTP.HeaderNames, ", "))
			}
		}
		file.Close()
		if err := sc.Err(); err != nil {
			return folder{}, err
		}
	}
	return f, nil
}

func keyOf(r record.Request) string {
	k := key{
		Method: r.HTTP.Method, Path: r.HTTP.Path, Query: r.HTTP.Query, Version: r.HTTP.Version,
		BodyLen: r.HTTP.BodyLength, Alert: r.Alert, Score: r.Score.Total,
		Complete: r.Analysis.Complete, Body: r.Analysis.Body, Findings: []finding{},
	}
	if r.Application != nil {
		k.App = r.Application.Name
	}
	if r.Profile != nil {
		for _, pf := range r.Profile.Findings {
			k.Profile = append(k.Profile, pf.Kind+" "+pf.Location)
		}
		sort.Strings(k.Profile)
	}
	for _, x := range r.Findings {
		k.Findings = append(k.Findings, finding{Rule: x.RuleID, Location: x.Location, Matched: x.Matched})
	}
	text, _ := json.Marshal(k)
	return string(text)
}

// diff returns what is only in a and only in b, as multisets.
func diff(a, b []string) (onlyA, onlyB []string) {
	count := map[string]int{}
	for _, k := range a {
		count[k]++
	}
	for _, k := range b {
		count[k]--
	}
	for k, n := range count {
		for ; n > 0; n-- {
			onlyA = append(onlyA, k)
		}
		for ; n < 0; n++ {
			onlyB = append(onlyB, k)
		}
	}
	slices.Sort(onlyA)
	slices.Sort(onlyB)
	return onlyA, onlyB
}
