package dashboard

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	buildversion "github.com/EfeSipahi/ids-system/internal/version"
)

//go:embed web
var webFiles embed.FS

// refreshInterval is how often the record files are read for new lines.
const refreshInterval = 2 * time.Second

// pollSeconds is how often the pages ask for new data (V6).
const pollSeconds = 5

// Server is the dashboard.
type Server struct {
	cfg     Config
	store   *store
	auth    *auth
	test    *tester
	changes *changeLog
	marks   *marks
	control *control
	disk    diskState
	analyse *analyser
	// lock is the state folder's lock (C4), held while the dashboard runs.
	lock  *os.File
	pages map[string]*template.Template
	now   func() time.Time
	log   *log.Logger
}

// New prepares the dashboard. It fails when the records directory does
// not exist or no user has been added yet.
func New(cfg Config, logOut io.Writer) (*Server, error) {
	return newServer(cfg, logOut, time.Now)
}

func newServer(cfg Config, logOut io.Writer, now func() time.Time) (*Server, error) {
	if info, err := os.Stat(cfg.RecordsDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("records directory %s does not exist; run the IDS with records first", cfg.RecordsDir)
	}
	u, err := openUsers(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if len(u.names()) == 0 {
		return nil, errors.New("there is no user yet; add one with: ids-dashboard -add-user NAME")
	}
	// One dashboard writes a state folder (G6, C4).
	lock, err := lockFile(filepath.Join(cfg.StateDir, stateLockFile), false)
	if errors.Is(err, errInUse) {
		return nil, fmt.Errorf("the state folder %s is in use by another dashboard", cfg.StateDir)
	}
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		store:   newStore(cfg.RecordsDir),
		auth:    newAuth(u, cfg.StateDir, time.Duration(cfg.SessionIdleMinutes)*time.Minute, now),
		now:     now,
		log:     log.New(logOut, "ids-dashboard: ", log.LstdFlags),
		changes: &changeLog{path: filepath.Join(cfg.StateDir, ChangesFile)},
		lock:    lock,
		control: newControl(cfg.IDSConfig, cfg.StateDir, now),
		analyse: &analyser{recordsDir: cfg.RecordsDir, now: now},
	}
	if s.marks, err = openMarks(filepath.Join(cfg.StateDir, MarksFile)); err != nil {
		s.Close()
		return nil, err
	}
	s.store.marks = s.marks
	if s.test, err = newTester(cfg.TestConfigs, cfg.TestRequestsDir, now); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.loadPages(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.store.refresh(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close lets go of the state folder, so that another dashboard may use it.
func (s *Server) Close() {
	unlockFile(s.lock)
	s.lock = nil
}

// pageData is what a page template gets.
type pageData struct {
	Title string
	Page  string
	// User is the logged-in user; the header is shown only with one.
	User  string
	ID    string
	Error string
	Poll  int
	// Name is the user name typed into the login form, given back after
	// a wrong password. Next is where to go after logging in.
	Name    string
	Next    string
	Version string
	// Role is the user's role, and Analyst whether it is analyst or
	// more; Need is the role a refused page needs (G3).
	Role    string
	Analyst bool
	Admin   bool
	Need    string
	// App is the application of an application's page, and Tab the part
	// of it shown (W3).
	App string
	Tab string
}

var pageNames = []string{"overview", "alerts", "alert", "rules", "rule", "applications", "application", "settings", "settingshistory", "proposals", "analyse", "engine", "test", "users", "account", "log", "login", "notfound", "forbidden"}

func (s *Server) loadPages() error {
	s.pages = map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.ParseFS(webFiles, "web/templates/layout.html", "web/templates/"+name+".html")
		if err != nil {
			return err
		}
		s.pages[name] = t
	}
	return nil
}

// Handler returns the dashboard's routes, behind its security checks.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFiles, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logoutPost)

	page := func(name, title, least string) http.Handler {
		return s.requirePage(least, func(w http.ResponseWriter, r *http.Request, user string) {
			s.render(w, http.StatusOK, name, pageData{Title: title, Page: name, User: user, ID: r.PathValue("id"), Poll: pollSeconds})
		})
	}
	// Each route names the least role that may use it (G3).
	mux.Handle("GET /{$}", page("overview", "Overview", RoleViewer))
	mux.Handle("GET /alerts", page("alerts", "Alerts", RoleViewer))
	mux.Handle("GET /alerts/{id}", page("alert", "Alert", RoleViewer))
	mux.Handle("GET /rules", page("rules", "Rules", RoleViewer))
	mux.Handle("GET /rules/{id}", s.requirePage(RoleViewer, s.rulePage))
	mux.Handle("GET /applications", page("applications", "Applications", RoleViewer))
	mux.Handle("GET /applications/{name}", s.requirePage(RoleViewer, s.appPage("summary")))
	mux.Handle("GET /applications/{name}/rules", s.requirePage(RoleViewer, s.appPage("rules")))
	mux.Handle("GET /applications/{name}/history", s.requirePage(RoleViewer, s.appPage("history")))
	mux.Handle("GET /applications/{name}/settings", s.requirePage(RoleViewer, s.appPage("settings")))
	mux.Handle("GET /applications/{name}/profile", s.requirePage(RoleViewer, s.appPage("profile")))
	mux.Handle("GET /settings", page("settings", "Settings for every application", RoleViewer))
	mux.Handle("GET /settings/history", page("settingshistory", "History of the settings for every application", RoleViewer))
	mux.Handle("GET /proposals", page("proposals", "Proposed changes", RoleAdmin))
	mux.Handle("GET /engine", page("engine", "Engine and live input", RoleViewer))
	mux.Handle("GET /test", page("test", "Test a request", RoleAnalyst))
	mux.Handle("GET /analyse", page("analyse", "Analyse files", RoleAnalyst))
	mux.Handle("GET /users", page("users", "Users", RoleAdmin))
	mux.Handle("GET /log", page("log", "Change log", RoleAdmin))
	mux.Handle("GET /account", page("account", "Your account", RoleViewer))

	mux.Handle("GET /api/overview", s.requireAPI(RoleViewer, s.apiOverview))
	mux.Handle("GET /api/alerts", s.requireAPI(RoleViewer, s.apiAlerts))
	mux.Handle("GET /api/records/{id}", s.requireAPI(RoleViewer, s.apiRecord))
	mux.Handle("GET /api/rules", s.requireAPI(RoleViewer, s.apiRules))
	mux.Handle("GET /api/rules/{id}", s.requireAPI(RoleViewer, s.apiRule))
	mux.Handle("GET /api/applications", s.requireAPI(RoleViewer, s.apiApplications))
	mux.Handle("GET /api/applications/{name}", s.requireAPI(RoleViewer, s.apiApplication))
	mux.Handle("GET /api/engine", s.requireAPI(RoleViewer, s.apiEngine))
	mux.Handle("GET /api/test", s.requireAPI(RoleAnalyst, s.apiTest))
	mux.Handle("GET /api/test/files/{name}", s.requireAPI(RoleAnalyst, s.apiTestFile))
	mux.Handle("POST /api/test", s.requireAPI(RoleAnalyst, s.apiTestRun))
	mux.Handle("GET /api/analyse", s.requireAPI(RoleAnalyst, s.apiAnalyse))
	mux.Handle("POST /api/analyse", s.requireAPI(RoleAnalyst, s.apiAnalyseStart))
	mux.Handle("POST /api/analyse/stop", s.requireAPI(RoleAnalyst, s.apiAnalyseStop))
	mux.Handle("POST /api/analyse/try", s.requireAPI(RoleAnalyst, s.apiAnalyseTry))
	mux.Handle("GET /api/users", s.requireAPI(RoleAdmin, s.apiUsers))
	mux.Handle("POST /api/users", s.requireAPI(RoleAdmin, s.apiUsersChange))
	mux.Handle("GET /api/log", s.requireAPI(RoleAdmin, s.apiLog))
	mux.Handle("POST /api/account", s.requireAPI(RoleViewer, s.apiAccount))
	mux.Handle("POST /api/marks", s.requireAPI(RoleAnalyst, s.apiMark))
	mux.Handle("GET /api/marks/{id}", s.requireAPI(RoleViewer, s.apiMarkHistory))
	mux.Handle("GET /api/changes", s.requireAPI(RoleViewer, s.apiChanges))
	mux.Handle("POST /api/changes", s.requireAPI(RoleAnalyst, s.apiChangesPost))
	mux.Handle("GET /api/changes/preview", s.requireAPI(RoleViewer, s.apiPreview))
	mux.Handle("GET /api/proposals", s.requireAPI(RoleAdmin, s.apiProposals))
	mux.Handle("GET /api/versions", s.requireAPI(RoleViewer, s.apiVersions))
	mux.Handle("GET /api/control", s.requireAPI(RoleViewer, s.apiControl))
	mux.Handle("GET /api/settings", s.requireAPI(RoleViewer, s.apiSettings))
	mux.Handle("GET /api/applications/{name}/settings", s.requireAPI(RoleViewer, s.apiAppSettings))
	mux.Handle("GET /api/applications/{name}/profile", s.requireAPI(RoleViewer, s.apiProfile))
	mux.Handle("POST /api/applications/{name}/profile/check", s.requireAPI(RoleViewer, s.apiProfileCheck))

	// Everything else needs a login too, so that the dashboard says
	// nothing about what exists to someone who is not logged in.
	mux.Handle("/", s.requirePage(RoleViewer, func(w http.ResponseWriter, r *http.Request, user string) {
		s.render(w, http.StatusNotFound, "notfound", pageData{Title: "Page not found", Page: "notfound", User: user})
	}))

	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

// securityHeaders tells the browser to run no script but the dashboard's
// own file, to load nothing from elsewhere, and not to show the pages in a
// frame. The records hold text that attackers wrote, such as a User-Agent
// with a <script>; the pages put it in as text, and these headers stop it
// even if one place did not.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requirePage sends a browser without a login to the login page, which
// brings it back to the page it asked for (U8). A user whose role is below
// least gets a page that says so, with status 403 (G3).
func (s *Server) requirePage(least string, h func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := s.auth.user(sessionToken(r))
		if user == "" {
			target := "/login"
			if r.Method == http.MethodGet && r.URL.Path != "/" {
				target += "?next=" + url.QueryEscape(r.URL.RequestURI())
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		if !allows(s.auth.users.role(user), least) {
			s.render(w, http.StatusForbidden, "forbidden", pageData{Title: "Not allowed", Page: "forbidden", User: user, Need: least})
			return
		}
		h(w, r, user)
	})
}

// maxNext is the longest address the login page goes back to.
const maxNext = 2048

// afterLogin returns where the login page sends the browser: next when it
// is a path of this dashboard, else the overview. Anything that a browser
// could read as another site is refused, so that a link to the login page
// cannot send a user elsewhere (an open redirect): "//host" and "/\host",
// which browsers treat as "//host", a scheme or a host, and control
// characters, which browsers drop from an address ("/\t/host").
func afterLogin(next string) string {
	if next == "" || len(next) > maxNext || next[0] != '/' || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return "/"
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Path == "/login" || u.Path == "/logout" {
		return "/"
	}
	return next
}

// requireAPI answers 401 to a request without a login, and 403 to a user
// whose role is below least (G3).
func (s *Server) requireAPI(least string, h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := s.auth.user(sessionToken(r))
		if user == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		if !allows(s.auth.users.role(user), least) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "your role can't do this; it needs " + least})
			return
		}
		h(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	data.Version = buildversion.Version
	if data.User != "" {
		data.Role = s.auth.users.role(data.User)
		data.Analyst = allows(data.Role, RoleAnalyst)
		data.Admin = allows(data.Role, RoleAdmin)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[name].ExecuteTemplate(w, "layout", data); err != nil {
		s.log.Printf("page %s: %v", name, err)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := afterLogin(r.URL.Query().Get("next"))
	if s.auth.user(sessionToken(r)) != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", pageData{Title: "Log in", Page: "login", Next: next})
}

// maxForm is the largest login form that is read.
const maxForm = 4 << 10

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, "login", pageData{Title: "Log in", Page: "login", Error: "The form could not be read."})
		return
	}
	name, next := r.PostForm.Get("user"), afterLogin(r.PostForm.Get("next"))
	token, result, wait := s.auth.login(name, r.PostForm.Get("password"), clientIP(r))
	// After a failed try the form keeps the user name, never the password.
	again := pageData{Title: "Log in", Page: "login", Name: name, Next: next}
	switch result {
	case loginOK:
		setSession(w, token)
		http.Redirect(w, r, next, http.StatusSeeOther)
	case loginWait:
		again.Error = fmt.Sprintf("Too many wrong passwords for this user. Try again in %d seconds.", int(wait.Seconds()+0.999))
		s.render(w, http.StatusTooManyRequests, "login", again)
	default:
		again.Error = "Wrong user name or password."
		s.render(w, http.StatusUnauthorized, "login", again)
	}
}

func (s *Server) logoutPost(w http.ResponseWriter, r *http.Request) {
	s.auth.logout(sessionToken(r), clientIP(r))
	clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// The encoder writes <, > and & as < and so on, so the answer
	// cannot be read as HTML.
	json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	if len(app) > maxAppName {
		badRequest(w, fmt.Errorf("app is longer than %d characters", maxAppName))
		return
	}
	writeJSON(w, http.StatusOK, s.store.overviewFor(rng, app))
}

// appPage serves an application's page, on the tab named tab (W3). A name
// that no application could have is a page that does not exist.
func (s *Server) appPage(tab string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, user string) {
		name := r.PathValue("name")
		if !validAppName(name) {
			s.render(w, http.StatusNotFound, "notfound", pageData{Title: "Page not found", Page: "notfound", User: user})
			return
		}
		s.render(w, http.StatusOK, "application", pageData{Title: name, Page: "application", User: user, App: name, Tab: tab, Poll: pollSeconds})
	}
}

// rulePage serves a rule's page (W6).
func (s *Server) rulePage(w http.ResponseWriter, r *http.Request, user string) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 || strconv.Itoa(id) != r.PathValue("id") {
		s.render(w, http.StatusNotFound, "notfound", pageData{Title: "Page not found", Page: "notfound", User: user})
		return
	}
	s.render(w, http.StatusOK, "rule", pageData{Title: "Rule " + strconv.Itoa(id), Page: "rule", User: user, ID: strconv.Itoa(id), Poll: pollSeconds})
}

// validAppName reports whether name could be an application's name
// (profile.NewSet), or "none".
func validAppName(name string) bool {
	if name == "" || len(name) > maxAppName {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) apiApplications(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.store.applications(rng))
}

func (s *Server) apiApplication(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	p, err := s.store.application(r.PathValue("name"), rng)
	if errors.Is(err, errNoApp) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no application of this name has records or runs in the newest configuration"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// ruleConfigs are the product configurations whose rule files the rule
// pages read: the IDS's own, then the test tab's.
func (s *Server) ruleConfigs() []string {
	var c []string
	if s.cfg.IDSConfig != "" {
		c = append(c, s.cfg.IDSConfig)
	}
	return append(c, s.cfg.TestConfigs...)
}

func (s *Server) apiRule(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 1 {
		badRequest(w, fmt.Errorf("rule %q is not a rule number", r.PathValue("id")))
		return
	}
	p, err := s.store.rule(id, rng)
	if errors.Is(err, errNoRule) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("the newest run has no rule %d", id)})
		return
	}
	if text, err := ruleText(s.ruleConfigs(), p.Rule.File, p.Rule.Line); err != nil {
		p.TextError = err.Error()
	} else {
		p.Text = text
	}
	p.TestFile = s.test.ruleFile(id)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r.URL.Query(), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.store.list(f))
}

func (s *Server) apiRecord(w http.ResponseWriter, r *http.Request) {
	line, err := s.store.load(r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such record"})
		return
	}
	if err != nil {
		s.log.Print(err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the record could not be read"})
		return
	}
	// Decoded and encoded again, so the answer has the same escaping as
	// every other one, whatever is in the file.
	var rec any
	if err := json.Unmarshal(line, &rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the record could not be read"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) apiRules(w http.ResponseWriter, r *http.Request) {
	rng, err := parseRange(r.URL.Query().Get("range"), s.now())
	if err != nil {
		badRequest(w, err)
		return
	}
	p, err := s.store.rulesPage(rng, strings.TrimSpace(r.URL.Query().Get("app")))
	if err != nil {
		badRequest(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// apiTest gives the test tab its configurations, examples and example
// files.
func (s *Server) apiTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.test.page(s.store.newestConfig()))
}

// apiTestFile gives the requests of one example file of the picker.
func (s *Server) apiTestFile(w http.ResponseWriter, r *http.Request) {
	list, err := s.test.fileExamples(r.PathValue("name"))
	switch {
	case errors.Is(err, errNoSuchFile):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such example file"})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "examples": list})
	}
}

// apiTestRun runs one test. The body is the request as raw text, at most
// maxTestText bytes, refused before more is read (C3); the choices are in
// the query: config, level, application, client and crlf.
func (s *Server) apiTestRun(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTestText)
	text, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLong *http.MaxBytesError
		if errors.As(err, &tooLong) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("the request is longer than %d bytes", maxTestText)})
			return
		}
		badRequest(w, err)
		return
	}
	q := r.URL.Query()
	tr := testRequest{Application: q.Get("application"), Client: q.Get("client"), BodyCRLF: q.Get("crlf") == "1", Text: string(text)}
	for _, n := range []struct {
		name string
		to   *int
	}{{"config", &tr.Config}, {"level", &tr.Level}} {
		if v := q.Get(n.name); v != "" {
			if *n.to, err = strconv.Atoi(v); err != nil {
				badRequest(w, fmt.Errorf("%s %q is not a number", n.name, v))
				return
			}
		}
	}
	answer, err := s.test.run(r.Context(), tr, s.store.newestConfig())
	if err != nil {
		var te *testError
		switch {
		case errors.As(err, &te):
			if te.status == http.StatusInternalServerError {
				s.log.Printf("test tab: %v", err)
			}
			writeJSON(w, te.status, map[string]string{"error": te.msg})
		default:
			// The client went away while waiting for its turn.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusOK, answer)
}

func (s *Server) apiEngine(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.enginePageAt(s.now()))
}

// Watch reads the record files for new lines until ctx ends.
func (s *Server) Watch(ctx context.Context) {
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.store.refresh(); err != nil {
				s.log.Printf("reading records: %v", err)
			}
		}
	}
}

// Serve answers HTTPS on ln until ctx ends. There is no plain HTTP: a
// browser that tries it gets an error.
func (s *Server) Serve(ctx context.Context, ln net.Listener, cert tls.Certificate) error {
	srv := &http.Server{
		Handler: s.Handler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          s.log,
	}
	go s.Watch(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// Certificate returns the certificate the dashboard serves, making its own
// when none is configured. made reports whether a new one was made.
func (s *Server) Certificate() (tls.Certificate, bool, error) {
	return certificate(s.cfg, s.now())
}

// Addr is the address the dashboard listens on.
func (s *Server) Addr() string {
	return s.cfg.Listen
}

// URL is the address to open in a browser.
func (s *Server) URL() string {
	host, port, _ := net.SplitHostPort(s.cfg.Listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host + ":" + port
}
