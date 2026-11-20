package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// replayFile writes request files whose requests carry times, out of
// order: an attack two days ago, a request without an attack three days
// ago, and two attacks of the same moment, five minutes after the first.
func replayFile(t *testing.T, base time.Time) string {
	t.Helper()
	at := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339) }
	return write(t, "replay.json", `[
  {"name": "second", "time": "`+at(-48*time.Hour)+`", "remote_addr": "192.0.2.7", "method": "GET", "uri": "/get?file=../../../etc/passwd", "headers": [["Host", "a"], ["User-Agent", "t"], ["Accept", "*/*"]]},
  {"name": "first", "time": "`+at(-72*time.Hour)+`", "method": "GET", "uri": "/", "headers": [["Host", "a"], ["User-Agent", "t"], ["Accept", "*/*"]]},
  {"name": "third", "time": "`+at(-48*time.Hour+5*time.Minute)+`", "method": "GET", "uri": "/get?q=1'%20UNION%20SELECT%20pass%20FROM%20users--", "headers": [["Host", "a"], ["User-Agent", "t"], ["Accept", "*/*"]]},
  {"name": "fourth", "time": "`+at(-48*time.Hour+5*time.Minute)+`", "method": "GET", "uri": "/get?q=<script>alert(1)</script>", "headers": [["Host", "a"], ["User-Agent", "t"], ["Accept", "*/*"]]}
]`)
}

type line struct {
	Type    string    `json:"type"`
	Time    time.Time `json:"time"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Analyse int       `json:"analysed"`
	Input   *struct {
		Kind     string    `json:"kind"`
		Replayed time.Time `json:"replayed"`
	} `json:"input"`
	Client struct {
		IP string `json:"ip"`
	} `json:"client"`
}

func readLines(t *testing.T, dir string) []line {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []line
	for _, text := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		var l line
		if err := json.Unmarshal([]byte(text), &l); err != nil {
			t.Fatalf("%v: %s", err, text)
		}
		lines = append(lines, l)
	}
	return lines
}

// TestReplay: with -replay, the start record, every record and the counts
// carry the requests' own times, in time order; the start record names
// the run as a replay, with the real time it ran.
func TestReplay(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	file := replayFile(t, base)
	dir := t.TempDir()
	before := time.Now()
	code, out, errOut := runTool(t, "-records", dir, "-config", productConfig, "-requests", file, "-replay", "-json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	// The output lists the requests in the order they were analysed: by
	// time, the two of the same moment in the file's order.
	var o struct {
		Requests []struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range o.Requests {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "first,second,third,fourth" {
		t.Errorf("order %v", names)
	}

	lines := readLines(t, dir)
	start := lines[0]
	if start.Type != "start" || !start.Time.Equal(base.Add(-72*time.Hour)) || start.Input == nil || start.Input.Kind != "replay" ||
		start.Input.Replayed.Before(before.Add(-time.Second)) || start.Input.Replayed.After(time.Now()) {
		t.Errorf("start record: %+v %+v", start, start.Input)
	}
	var requests []time.Time
	analysed := 0
	var counts []line
	for _, l := range lines[1:] {
		switch l.Type {
		case "request":
			requests = append(requests, l.Time)
		case "counts":
			counts = append(counts, l)
			analysed += l.Analyse
		}
	}
	// Every request has a record (the "clean" one too: a finding below
	// the threshold), each at its own time, in time order.
	want := []time.Time{base.Add(-72 * time.Hour), base.Add(-48 * time.Hour), base.Add(-48*time.Hour + 5*time.Minute), base.Add(-48*time.Hour + 5*time.Minute)}
	if len(requests) != 4 {
		t.Fatalf("%d request records: %v", len(requests), requests)
	}
	for i := range want {
		if !requests[i].Equal(want[i]) {
			t.Errorf("record %d at %v, want %v", i, requests[i], want[i])
		}
	}
	// The counts follow the same clock: the first period ends when the
	// day-later request comes, the last one at the last request.
	if analysed != 4 || len(counts) < 2 || !counts[len(counts)-1].To.Equal(want[3]) || !counts[0].From.Equal(start.Time) {
		t.Errorf("counts: %d analysed, %+v", analysed, counts)
	}
}

// TestReplayRefusals: a replay needs a time on every request, none in the
// future, request files and a records folder.
func TestReplayRefusals(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	noTime := write(t, "a.json", `[{"name": "x", "method": "GET", "uri": "/", "headers": [["Host", "a"]]}]`)
	later := write(t, "b.json", `[{"name": "y", "time": "`+future+`", "method": "GET", "uri": "/", "headers": [["Host", "a"]]}]`)
	badTime := write(t, "c.json", `[{"name": "z", "time": "yesterday", "method": "GET", "uri": "/", "headers": [["Host", "a"]]}]`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-requests", noTime, "-replay"}, `request "x" of a has no time`},
		{[]string{"-requests", later, "-replay"}, `request "y" of b has a time in the future`},
		{[]string{"-requests", badTime, "-replay"}, `"yesterday" is not an RFC 3339 time`},
		{[]string{"-replay"}, "-replay needs -requests"},
		{[]string{"-requests", noTime, "-endpoints", "-replay"}, "does not go with -endpoints"},
	} {
		code, _, errOut := runTool(t, append([]string{"-config", productConfig}, tc.args...)...)
		if code != 2 || !strings.Contains(errOut, tc.want) {
			t.Errorf("%v: exit %d, %q", tc.args, code, errOut)
		}
	}
	// Without a records folder there is nothing to replay into.
	var out, errOut strings.Builder
	if code := run([]string{"-config", "../../testdata/crs-tests.json", "-requests", replayFile(t, time.Now()), "-replay"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "-replay writes records") {
		t.Errorf("no records folder: exit %d, %q", code, errOut.String())
	}
}

// TestTimesWithoutReplay: without -replay, the requests' times are read
// and checked but not used: records carry the moment of the analysis, and
// the run is not a replay.
func TestTimesWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	before := time.Now().Add(-time.Second)
	if code, _, errOut := runTool(t, "-records", dir, "-config", productConfig, "-requests", replayFile(t, time.Now().UTC())); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, l := range readLines(t, dir) {
		if (l.Type == "request" || l.Type == "start") && l.Time.Before(before) {
			t.Errorf("%s record at %v, before the run", l.Type, l.Time)
		}
		if l.Input != nil {
			t.Errorf("input %+v", l.Input)
		}
	}
}
