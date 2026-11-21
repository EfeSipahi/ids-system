package dashboard

// Monitor › Clients and Endpoints (W23 of
// docs/development-plan-dashboard-control.md): who sent what was recorded,
// and where it went. Both only read; both take the application filter
// (W1).

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// maxListRows is the most clients or endpoints a list shows.
const maxListRows = 200

// clientRow is one client address of the Clients list.
type clientRow struct {
	IP             string    `json:"ip"`
	Records        int       `json:"records"`
	Alerts         int       `json:"alerts"`
	First          time.Time `json:"first"`
	Last           time.Time `json:"last"`
	Applications   []string  `json:"applications"`
	Groups         []string  `json:"groups"`
	RealAttacks    int       `json:"real_attacks"`
	FalsePositives int       `json:"false_positives"`
}

type clientsPage struct {
	Range timeRange   `json:"range"`
	Total int         `json:"total"`
	Rows  []clientRow `json:"rows"`
	// Applications are the names the filter can choose.
	Applications []string `json:"applications"`
}

// rangeAndApp reads the period and the application filter of a list.
func (s *Server) rangeAndApp(w http.ResponseWriter, r *http.Request) (timeRange, string, bool) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return rng, "", false
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if len(app) > maxAppName {
		badRequest(w, errNoApp)
		return rng, "", false
	}
	return rng, app, true
}

func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	rng, app, ok := s.rangeAndApp(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.store.clients(rng, app))
}

func (s *store) clients(r timeRange, app string) clientsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := clientsPage{Range: r, Rows: []clientRow{}}
	by := map[string]*clientRow{}
	groups := map[string]map[string]int{}
	for _, e := range s.entries {
		if !r.contains(e.time) || e.ip == "" || app != "" && !sameApp(e.app, app) {
			continue
		}
		c := by[e.ip]
		if c == nil {
			c = &clientRow{IP: e.ip, First: e.time, Last: e.time, Applications: []string{}, Groups: []string{}}
			by[e.ip] = c
			groups[e.ip] = map[string]int{}
		}
		c.Records++
		if e.alert {
			c.Alerts++
		}
		if e.time.Before(c.First) {
			c.First = e.time
		}
		if e.time.After(c.Last) {
			c.Last = e.time
		}
		if name := appKey(e.app); !contains(c.Applications, name) {
			c.Applications = append(c.Applications, name)
		}
		for _, g := range e.groups {
			groups[e.ip][g]++
		}
		switch s.marks.verdict(e.id) {
		case verdictRealAttack:
			c.RealAttacks++
		case verdictFalsePositive:
			c.FalsePositives++
		}
	}
	for ip, c := range by {
		for _, it := range top(groups[ip]) {
			if len(c.Groups) < 3 {
				c.Groups = append(c.Groups, it.Key)
			}
		}
		sort.Strings(c.Applications)
		p.Rows = append(p.Rows, *c)
	}
	sort.Slice(p.Rows, func(i, j int) bool {
		a, b := p.Rows[i], p.Rows[j]
		if a.Alerts != b.Alerts {
			return a.Alerts > b.Alerts
		}
		if a.Records != b.Records {
			return a.Records > b.Records
		}
		return a.IP < b.IP
	})
	p.Total = len(p.Rows)
	if len(p.Rows) > maxListRows {
		p.Rows = p.Rows[:maxListRows]
	}
	p.Applications = s.appNames()
	return p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// clientPage is one client address over time (W23): the place to start
// blocking it later (K4).
type clientPage struct {
	Range      timeRange `json:"range"`
	IP         string    `json:"ip"`
	Records    int       `json:"records"`
	Alerts     int       `json:"alerts"`
	First      time.Time `json:"first,omitzero"`
	Last       time.Time `json:"last,omitzero"`
	Series     []bucket  `json:"series"`
	BucketSecs int       `json:"bucket_seconds"`
	Paths      []item    `json:"top_paths"`
	Rules      []item    `json:"top_rules"`
	Groups     []item    `json:"top_groups"`
	Apps       []item    `json:"applications"`
	Agents     []item    `json:"user_agents"`
	// Verdicts counts its records by their mark.
	Verdicts map[string]int `json:"verdicts"`
}

func (s *Server) apiClient(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not an IP address"})
		return
	}
	writeJSON(w, http.StatusOK, s.store.client(ip.String(), rng))
}

func (s *store) client(ip string, r timeRange) clientPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := clientPage{Range: r, IP: ip, Verdicts: map[string]int{}}
	tl := newTimeline(r, s.earliest())
	paths, rules, groups, apps, agents := map[string]int{}, map[int]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range s.entries {
		if e.ip != ip || !r.contains(e.time) {
			continue
		}
		p.Records++
		b := tl.slot(e.time)
		if b != nil {
			b.Records++
		}
		if e.alert {
			p.Alerts++
			if b != nil {
				b.Alerts++
			}
		}
		if p.First.IsZero() || e.time.Before(p.First) {
			p.First = e.time
		}
		if e.time.After(p.Last) {
			p.Last = e.time
		}
		paths[e.method+" "+e.path]++
		for _, id := range e.rules {
			if groupOf(id).counts {
				rules[id]++
			}
		}
		for _, g := range e.groups {
			groups[g]++
		}
		apps[appKey(e.app)]++
		if e.userAgent != "" {
			agents[e.userAgent]++
		}
		p.Verdicts[s.marks.verdict(e.id)]++
	}
	p.Series, p.BucketSecs = tl.series, int(tl.width/time.Second)
	p.Paths, p.Rules, p.Groups, p.Apps, p.Agents = top(paths), topInts(rules), top(groups), top(apps), top(agents)
	return p
}

// endpointRow is one method and path of the Endpoints list.
type endpointRow struct {
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Application    string    `json:"application"`
	Records        int       `json:"records"`
	Alerts         int       `json:"alerts"`
	Clients        int       `json:"clients"`
	Groups         []string  `json:"groups"`
	FalsePositives int       `json:"false_positives"`
	Last           time.Time `json:"last"`
}

type endpointsPage struct {
	Range        timeRange     `json:"range"`
	Total        int           `json:"total"`
	Rows         []endpointRow `json:"rows"`
	Applications []string      `json:"applications"`
}

func (s *Server) apiEndpoints(w http.ResponseWriter, r *http.Request) {
	rng, app, ok := s.rangeAndApp(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.store.endpoints(rng, app))
}

func (s *store) endpoints(r timeRange, app string) endpointsPage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := endpointsPage{Range: r, Rows: []endpointRow{}}
	type acc struct {
		endpointRow
		clients map[string]bool
		groups  map[string]int
	}
	by := map[[3]string]*acc{}
	for _, e := range s.entries {
		if !r.contains(e.time) || app != "" && !sameApp(e.app, app) {
			continue
		}
		key := [3]string{appKey(e.app), e.method, e.path}
		a := by[key]
		if a == nil {
			a = &acc{endpointRow: endpointRow{Method: e.method, Path: e.path, Application: key[0], Groups: []string{}}, clients: map[string]bool{}, groups: map[string]int{}}
			by[key] = a
		}
		a.Records++
		if e.alert {
			a.Alerts++
		}
		if e.ip != "" {
			a.clients[e.ip] = true
		}
		for _, g := range e.groups {
			a.groups[g]++
		}
		if s.marks.verdict(e.id) == verdictFalsePositive {
			a.FalsePositives++
		}
		if e.time.After(a.Last) {
			a.Last = e.time
		}
	}
	for _, a := range by {
		a.Clients = len(a.clients)
		for _, it := range top(a.groups) {
			if len(a.Groups) < 3 {
				a.Groups = append(a.Groups, it.Key)
			}
		}
		p.Rows = append(p.Rows, a.endpointRow)
	}
	sort.Slice(p.Rows, func(i, j int) bool {
		a, b := p.Rows[i], p.Rows[j]
		if a.Alerts != b.Alerts {
			return a.Alerts > b.Alerts
		}
		if a.Records != b.Records {
			return a.Records > b.Records
		}
		return a.Application+a.Method+a.Path < b.Application+b.Method+b.Path
	})
	p.Total = len(p.Rows)
	if len(p.Rows) > maxListRows {
		p.Rows = p.Rows[:maxListRows]
	}
	p.Applications = s.appNames()
	return p
}
