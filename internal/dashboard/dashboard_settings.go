package dashboard

// Administration › Dashboard settings (W20 of
// docs/development-plan-dashboard-control.md): the settings of the
// dashboard that change in normal use. Its address, its certificate files
// and its folders stay in its configuration file, written by hand: a
// mistake there locks everyone out of the page that could fix it (W21).

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/jsonedit"
)

const actionDashboardSettings = "dashboard_settings"

// dashboardSettings are the settings the page shows and changes.
type dashboardSettings struct {
	SessionIdleMinutes int      `json:"session_idle_minutes"`
	MarksMaxAgeDays    int      `json:"marks_max_age_days"`
	TestConfigs        []string `json:"test_configs"`
	TestRequestsDir    string   `json:"test_requests_dir"`
	CertNames          []string `json:"cert_names"`
}

// dashboardSettingsPage adds what stays in the file, shown only.
type dashboardSettingsPage struct {
	dashboardSettings
	File        string   `json:"file"`
	Listen      string   `json:"listen"`
	OwnCert     bool     `json:"own_cert"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	CertNamesOn []string `json:"cert_names_on"`
	RecordsDir  string   `json:"records_dir"`
	StateDir    string   `json:"state_dir"`
	IDSConfig   string   `json:"ids_config,omitempty"`
}

// asWritten returns the settings as the file writes them: paths relative
// to its folder stay so.
func (s *Server) settingsFile() (*jsonedit.Value, error) {
	if s.cfg.path == "" {
		return nil, errors.New("the dashboard was not started from a configuration file")
	}
	data, err := os.ReadFile(s.cfg.path)
	if err != nil {
		return nil, err
	}
	return jsonedit.Parse(data)
}

func (s *Server) apiDashboardSettings(w http.ResponseWriter, r *http.Request) {
	p := dashboardSettingsPage{File: s.cfg.path, Listen: s.cfg.Listen, OwnCert: s.cfg.TLSCert == "", RecordsDir: s.cfg.RecordsDir, StateDir: s.cfg.StateDir, IDSConfig: s.cfg.IDSConfig}
	p.dashboardSettings = dashboardSettings{SessionIdleMinutes: s.cfg.SessionIdleMinutes, MarksMaxAgeDays: s.cfg.MarksMaxAgeDays, TestConfigs: []string{}, CertNames: nonNil(s.cfg.CertNames)}
	if v, err := s.settingsFile(); err == nil {
		var written struct {
			TestConfigs     []string `json:"test_configs"`
			TestRequestsDir string   `json:"test_requests_dir"`
		}
		v.Decode(&written)
		p.TestConfigs, p.TestRequestsDir = nonNil(written.TestConfigs), written.TestRequestsDir
	}
	if c := s.cert.Load(); c != nil {
		p.Fingerprint = Fingerprint(*c)
		if c.Leaf != nil {
			p.CertNamesOn = slices.Clone(c.Leaf.DNSNames)
			for _, ip := range c.Leaf.IPAddresses {
				p.CertNamesOn = append(p.CertNamesOn, ip.String())
			}
		}
	}
	p.CertNamesOn = nonNil(p.CertNamesOn)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) apiDashboardSettingsPost(w http.ResponseWriter, r *http.Request) {
	user := s.auth.user(sessionToken(r))
	var req struct {
		dashboardSettings
		Reason   string `json:"reason"`
		Password string `json:"password"`
	}
	if err := readJSON(w, r, 64<<10, &req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		badRequest(w, errors.New("give a reason: the change log keeps it"))
		return
	}
	v, err := s.settingsFile()
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	// The new configuration is checked as a whole, as it will be read at
	// the next start, before anything is written.
	next := s.cfg
	next.SessionIdleMinutes, next.MarksMaxAgeDays, next.CertNames = req.SessionIdleMinutes, req.MarksMaxAgeDays, req.CertNames
	dir := filepath.Dir(s.cfg.path)
	abs := func(p string) string {
		if p != "" && !filepath.IsAbs(p) {
			return filepath.Join(dir, p)
		}
		return p
	}
	next.TestConfigs = nil
	for _, c := range req.TestConfigs {
		next.TestConfigs = append(next.TestConfigs, abs(strings.TrimSpace(c)))
	}
	next.TestRequestsDir = abs(strings.TrimSpace(req.TestRequestsDir))
	if err := next.validate(); err != nil {
		badRequest(w, err)
		return
	}
	if next.TestRequestsDir != "" {
		if info, err := os.Stat(next.TestRequestsDir); err != nil || !info.IsDir() {
			badRequest(w, fmt.Errorf("the example folder %s is not a folder", req.TestRequestsDir))
			return
		}
	}
	test, err := newTester(next.IDSConfig, next.TestConfigs, next.TestRequestsDir, s.now)
	if err != nil {
		badRequest(w, err)
		return
	}
	if !s.confirm(w, r, user, req.Password) {
		return
	}
	v.Set("session_idle_minutes", jsonedit.Must(req.SessionIdleMinutes))
	setOrDelete := func(key string, val any, empty bool) {
		if empty {
			v.Delete(key)
		} else {
			v.Set(key, jsonedit.Must(val))
		}
	}
	setOrDelete("marks_max_age_days", req.MarksMaxAgeDays, req.MarksMaxAgeDays == 0)
	setOrDelete("test_configs", req.TestConfigs, len(req.TestConfigs) == 0)
	setOrDelete("test_requests_dir", strings.TrimSpace(req.TestRequestsDir), strings.TrimSpace(req.TestRequestsDir) == "")
	setOrDelete("cert_names", req.CertNames, len(req.CertNames) == 0)
	mode := os.FileMode(0o600)
	if info, err := os.Stat(s.cfg.path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := writeFileAtomic(s.cfg.path, v.Marshal(), mode); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Taken at once: the idle time, the marks' age, the test tab's files,
	// and the certificate's names, with a new certificate when the
	// dashboard makes its own.
	certNamesChanged := !slices.Equal(next.CertNames, s.cfg.CertNames)
	s.cfg = next
	s.auth.setIdle(time.Duration(next.SessionIdleMinutes) * time.Minute)
	s.test = test
	answer := map[string]string{"saved": s.cfg.path}
	if certNamesChanged && s.cfg.TLSCert == "" {
		cert, _, err := certificate(s.cfg, s.now())
		if err != nil {
			answer["certificate_error"] = err.Error()
		} else {
			s.cert.Store(&cert)
			answer["fingerprint"] = Fingerprint(cert)
		}
	}
	s.logChange(change{User: user, Action: actionDashboardSettings, Reason: strings.TrimSpace(req.Reason),
		What: []string{fmt.Sprintf("idle time %d min, marks kept %s, %d test configurations, certificate names %s", req.SessionIdleMinutes, daysText(req.MarksMaxAgeDays), len(req.TestConfigs), orText(strings.Join(req.CertNames, ", "), "none"))}})
	writeJSON(w, http.StatusOK, answer)
}

func daysText(n int) string {
	if n == 0 {
		return "forever"
	}
	return fmt.Sprintf("%d days", n)
}
