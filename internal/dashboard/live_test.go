package dashboard

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/EfeSipahi/ids-system/internal/record"
)

// liveRecords are a run of ids-live: its start names the socket; its
// counts say how many copiers were connected and which application names
// were unknown; two gaps fall in the last hour and one before it.
func liveRecords(t *testing.T, dir string, lastCounts time.Time, copiers int) {
	t.Helper()
	st := startRecord("live1", t0.Add(-2*time.Hour), "sha256:one")
	st.Input = &record.Input{Kind: record.InputLive, Socket: "/run/ids/copy.sock"}
	one, last := 1, copiers
	early := countsRecord("live1", t0.Add(-30*time.Minute), 50, 0, 0)
	early.Copiers, early.UnknownApplications = &one, map[string]int{"shop2": 3}
	late := countsRecord("live1", lastCounts, 20, 0, 0)
	late.Copiers, late.UnknownApplications = &last, map[string]int{"shop2": 1, "blog-old": 2}
	gap := func(from, to time.Time, missed int64, reason, source string) record.Gap {
		return record.Gap{Type: record.TypeGap, Schema: record.Schema, Run: "live1", From: from, To: to, Missed: missed, Reason: reason, Source: source}
	}
	appendLines(t, filepath.Join(dir, record.CurrentFile),
		st,
		gap(t0.Add(-3*time.Hour), t0.Add(-150*time.Minute), 7, "not connected", record.GapCopier), // before the hour
		early,
		gap(t0.Add(-40*time.Minute), t0.Add(-35*time.Minute), 1228, "not connected", record.GapCopier),
		gap(t0.Add(-20*time.Minute), t0.Add(-20*time.Minute), 12, record.ReasonQueueFull, record.GapIDS),
		gap(t0.Add(-15*time.Minute), t0.Add(-15*time.Minute), 3, record.ReasonQueueFull, record.GapIDS),
		late,
	)
}

// Stage 6: the overview counts what the live input could not analyse, by
// source and reason, lists the newest gaps, sums the unknown application
// names, and says whether a proxy is connected.
func TestOverviewOfLiveInput(t *testing.T) {
	s, dir := newTestStore(t)
	liveRecords(t, dir, t0.Add(-time.Minute), 0)
	refresh(t, s)
	r, _ := parseRange("1h", t0)
	o := s.overview(r)
	if o.NotAnalysed != 1243 {
		t.Errorf("not analysed %d, want 1243 (the gap before the hour is left out)", o.NotAnalysed)
	}
	wantBy := []missedCount{{"copier", "not connected", 1228}, {"ids", "queue full", 15}}
	if !reflect.DeepEqual(o.NotAnalysedBy, wantBy) {
		t.Errorf("by reason %+v", o.NotAnalysedBy)
	}
	if len(o.Gaps) != 3 || o.GapCount != 3 || o.Gaps[0].Missed != 3 || o.Gaps[2].Missed != 1228 {
		t.Errorf("gaps, newest first: %+v", o.Gaps)
	}
	wantApps := []item{{Key: "shop2", Count: 4}, {Key: "blog-old", Count: 2}}
	if !reflect.DeepEqual(o.UnknownApps, wantApps) {
		t.Errorf("unknown applications %+v", o.UnknownApps)
	}
	l := o.Live
	if l == nil || l.Socket != "/run/ids/copy.sock" || !l.LastCounts.Equal(t0.Add(-time.Minute)) || l.Copiers == nil || *l.Copiers != 0 || l.Stale {
		t.Fatalf("live status %+v", l)
	}
}

// Option A (18 November 2026): a live run whose newest counts record is
// more than 2 minutes old is stale: ids-live is not writing.
func TestLiveRunGoesStale(t *testing.T) {
	for _, tt := range []struct {
		age   time.Duration
		stale bool
	}{{time.Minute, false}, {2 * time.Minute, false}, {2*time.Minute + time.Second, true}, {time.Hour, true}} {
		s, dir := newTestStore(t)
		liveRecords(t, dir, t0.Add(-tt.age), 1)
		refresh(t, s)
		r, _ := parseRange("24h", t0)
		if o := s.overview(r); o.Live == nil || o.Live.Stale != tt.stale {
			t.Errorf("newest counts %v old: live %+v, want stale %v", tt.age, o.Live, tt.stale)
		}
	}
	// Before its first counts record, the run's start is what counts.
	s, dir := newTestStore(t)
	st := startRecord("live2", t0.Add(-5*time.Minute), "sha256:one")
	st.Input = &record.Input{Kind: record.InputLive}
	appendLines(t, filepath.Join(dir, record.CurrentFile), st)
	refresh(t, s)
	r, _ := parseRange("1h", t0)
	if o := s.overview(r); o.Live == nil || !o.Live.Stale || o.Live.Copiers != nil {
		t.Errorf("a live run without counts, started 5 minutes ago: %+v", o.Live)
	}
}

// A run of request files has no live status, and no gaps.
func TestOfflineRunHasNoLiveStatus(t *testing.T) {
	s, dir := newTestStore(t)
	sampleRecords(t, dir)
	refresh(t, s)
	r, _ := parseRange("1h", t0)
	o := s.overview(r)
	if o.Live != nil || o.NotAnalysed != 0 || len(o.Gaps) != 0 || o.Gaps == nil || o.UnknownApps == nil {
		t.Errorf("live %+v, not analysed %d, gaps %v, unknown %v", o.Live, o.NotAnalysed, o.Gaps, o.UnknownApps)
	}
	p := s.enginePage()
	if p.Latest == nil || p.Latest.Input != nil {
		t.Errorf("an offline run has an input: %+v", p.Latest)
	}
}

// The Engine page names the input of each run.
func TestEnginePageShowsTheInput(t *testing.T) {
	s, dir := newTestStore(t)
	liveRecords(t, dir, t0.Add(-time.Minute), 1)
	refresh(t, s)
	p := s.enginePage()
	if p.Latest == nil || p.Latest.Input == nil || p.Latest.Input.Socket != "/run/ids/copy.sock" || p.Runs[0].Input == nil {
		t.Errorf("latest %+v, runs %+v", p.Latest, p.Runs)
	}
	if p.Unreadable != 0 || p.Skipped != 0 {
		t.Errorf("unreadable %d, skipped %d", p.Unreadable, p.Skipped)
	}
}
