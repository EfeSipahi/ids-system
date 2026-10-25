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
	cfg   Config
	store *store
	auth  *auth
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
	s := &Server{
		cfg:   cfg,
		store: newStore(cfg.RecordsDir),
		auth:  newAuth(u, cfg.StateDir, time.Duration(cfg.SessionIdleMinutes)*time.Minute, now),
		now:   now,
		log:   log.New(logOut, "ids-dashboard: ", log.LstdFlags),
	}
	if err := s.loadPages(); err != nil {
		return nil, err
	}
	if err := s.store.refresh(); err != nil {
		return nil, err
	}
	return s, nil
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
}

var pageNames = []string{"overview", "alerts", "alert", "rules", "engine", "login", "notfound"}

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

	page := func(name, title string) http.Handler {
		return s.requirePage(func(w http.ResponseWriter, r *http.Request, user string) {
			s.render(w, http.StatusOK, name, pageData{Title: title, Page: name, User: user, ID: r.PathValue("id"), Poll: pollSeconds})
		})
	}
	mux.Handle("GET /{$}", page("overview", "Overview"))
	mux.Handle("GET /alerts", page("alerts", "Alerts"))
	mux.Handle("GET /alerts/{id}", page("alert", "Alert"))
	mux.Handle("GET /rules", page("rules", "Rules"))
	mux.Handle("GET /engine", page("engine", "Engine"))

	mux.Handle("GET /api/overview", s.requireAPI(s.apiOverview))
	mux.Handle("GET /api/alerts", s.requireAPI(s.apiAlerts))
	mux.Handle("GET /api/records/{id}", s.requireAPI(s.apiRecord))
	mux.Handle("GET /api/rules", s.requireAPI(s.apiRules))
	mux.Handle("GET /api/engine", s.requireAPI(s.apiEngine))

	// Everything else needs a login too, so that the dashboard says
	// nothing about what exists to someone who is not logged in.
	mux.Handle("/", s.requirePage(func(w http.ResponseWriter, r *http.Request, user string) {
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
// brings it back to the page it asked for (U8).
func (s *Server) requirePage(h func(http.ResponseWriter, *http.Request, string)) http.Handler {
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

// requireAPI answers 401 to a request without a login.
func (s *Server) requireAPI(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.user(sessionToken(r)) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		h(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	data.Version = buildversion.Version
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
	writeJSON(w, http.StatusOK, s.store.overview(rng))
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

func (s *Server) apiEngine(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.enginePage())
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
