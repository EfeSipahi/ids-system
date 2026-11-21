package dashboard

// An application's Profile tab (W15, W16 of
// docs/development-plan-dashboard-control.md): its profile as written, a
// check as one types, and suggestions from its records.

import (
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/EfeSipahi/ids-system/internal/profile"
)

// suggestion is a path the application's records went to that its profile
// does not take, or with parameters it does not name (W15).
type suggestion struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// Seen counts its records; Alerts those the rules made alerts. Only
	// is true when every one of them is such an alert: then it is more
	// likely an attack than a part of the application.
	Seen   int  `json:"seen"`
	Alerts int  `json:"alerts"`
	Only   bool `json:"only_alerts"`
	// Endpoint is the profile's endpoint that takes it, or "".
	Endpoint string `json:"endpoint,omitempty"`
	// Params are the parameters the profile does not take there.
	Params []suggestedParam `json:"params"`
}

type suggestedParam struct {
	Name string `json:"name"`
	In   string `json:"in"`
	Seen int    `json:"seen"`
	// Only is true when every record that sent it is an alert of the
	// rules: an attack's own parameter, such as "' UNION SELECT".
	Only bool `json:"only_alerts"`
}

// maxSuggestions is how many suggestions the tab lists.
const maxSuggestions = 100

// suggestions lists, from the application's records, what its profile
// does not take. Records keep a profile's findings, not whole requests:
// a path is seen when a request to it had a finding, and a parameter when
// the profile found it unknown.
func (s *store) suggestions(app string, prof *profile.Profile) []suggestion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type acc struct {
		suggestion
		params map[[2]string]*[2]int // records, and alerts among them
	}
	byPath := map[[2]string]*acc{}
	for _, e := range s.entries {
		if e.app != app {
			continue
		}
		key := [2]string{e.method, e.path}
		a := byPath[key]
		if a == nil {
			a = &acc{suggestion: suggestion{Method: e.method, Path: e.path}, params: map[[2]string]*[2]int{}}
			byPath[key] = a
		}
		a.Seen++
		alert := e.threshold > 0 && e.score >= e.threshold
		if alert {
			a.Alerts++
		}
		for _, f := range e.profFindings {
			if f.kind != profile.KindUnknownParam {
				continue
			}
			var in, name string
			switch {
			case strings.HasPrefix(f.location, "ARGS_GET:"):
				in, name = profile.InQuery, strings.TrimPrefix(f.location, "ARGS_GET:")
			case strings.HasPrefix(f.location, "ARGS_POST:json."):
				in, name = profile.InJSON, strings.TrimPrefix(f.location, "ARGS_POST:json.")
			case strings.HasPrefix(f.location, "ARGS_POST:"):
				in, name = profile.InBody, strings.TrimPrefix(f.location, "ARGS_POST:")
			default:
				continue
			}
			k := [2]string{in, name}
			if a.params[k] == nil {
				a.params[k] = &[2]int{}
			}
			a.params[k][0]++
			if alert {
				a.params[k][1]++
			}
		}
	}
	out := []suggestion{}
	for _, a := range byPath {
		a.Only = a.Alerts == a.Seen
		a.Endpoint, _ = prof.Fits(a.Method, a.Path)
		a.Params = []suggestedParam{}
		for k, n := range a.params {
			if a.Endpoint != "" && prof.Knows(a.Method, a.Path, k[0], k[1]) {
				continue
			}
			a.Params = append(a.Params, suggestedParam{Name: k[1], In: k[0], Seen: n[0], Only: n[0] == n[1]})
		}
		sort.Slice(a.Params, func(i, j int) bool {
			if a.Params[i].Only != a.Params[j].Only {
				return !a.Params[i].Only
			}
			if a.Params[i].Seen != a.Params[j].Seen {
				return a.Params[i].Seen > a.Params[j].Seen
			}
			return a.Params[i].Name < a.Params[j].Name
		})
		if a.Endpoint == "" || len(a.Params) > 0 {
			out = append(out, a.suggestion)
		}
	}
	// What is not only attacks first, then the most seen.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Only != out[j].Only {
			return !out[i].Only
		}
		if out[i].Seen != out[j].Seen {
			return out[i].Seen > out[j].Seen
		}
		return out[i].Method+out[i].Path < out[j].Method+out[j].Path
	})
	if len(out) > maxSuggestions {
		out = out[:maxSuggestions]
	}
	return out
}

// profilePage is an application's Profile tab.
type profilePage struct {
	Configured bool   `json:"configured"`
	Error      string `json:"error,omitempty"`
	// File is the profile's file as the configuration names it, and Text
	// its content.
	File        string       `json:"file"`
	Text        string       `json:"text"`
	Endpoints   int          `json:"endpoints"`
	Suggestions []suggestion `json:"suggestions"`
}

func (s *Server) apiProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p := profilePage{Configured: s.control.path != "", Suggestions: []suggestion{}}
	if !p.Configured {
		p.Error = errNoConfig.Error()
		writeJSON(w, http.StatusOK, p)
		return
	}
	wk, err := s.control.newWork()
	if err == nil {
		var entry interface{ Decode(any) error }
		if entry, err = wk.appEntry(name); err == nil {
			var e struct {
				Profile string `json:"profile"`
			}
			entry.Decode(&e)
			p.File = e.Profile
		}
	}
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	path, _ := wk.profilePath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		p.Error = err.Error()
		writeJSON(w, http.StatusOK, p)
		return
	}
	p.Text = string(data)
	prof, err := profile.Parse(path, data)
	if err != nil {
		p.Error = "the profile on disk does not load: " + err.Error()
		writeJSON(w, http.StatusOK, p)
		return
	}
	p.Endpoints = prof.Endpoints()
	p.Suggestions = s.store.suggestions(name, prof)
	writeJSON(w, http.StatusOK, p)
}

// apiProfileCheck reads a profile as typed with the IDS's reader (W16).
// The rules are not loaded here: the exceptions are checked against them
// when the profile is added to the pending changes.
func (s *Server) apiProfileCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(w, r, maxChangeBody, &req); err != nil {
		badRequest(w, err)
		return
	}
	if len(req.Text) > maxProfileText {
		badRequest(w, errors.New("the profile is longer than 1 MiB"))
		return
	}
	prof, err := profile.Parse(r.PathValue("name")+".json", []byte(req.Text))
	if err != nil {
		// The reader names the file first; the page knows which it is.
		msg := strings.TrimPrefix(err.Error(), r.PathValue("name")+".json: ")
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "endpoints": prof.Endpoints(), "mode": prof.Mode, "level": prof.ParanoiaLevel, "exceptions": len(prof.Exceptions)})
}
