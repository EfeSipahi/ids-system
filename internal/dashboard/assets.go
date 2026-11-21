package dashboard

// The dashboard's files for the browser: its own (app.js, app.css, the
// fonts) and IBM Carbon's web components, themes and icons (static/carbon,
// made by tools/carbon-fetch.sh; docs/development-plan-dashboard-carbon.md).
// All are built into the binary and served under /static/.
//
// Carbon adds 2.5 MB of script, so the browser keeps the files: a page
// names them under /static/<version>/, where the version is a hash of every
// file, and keeps that address for a year. A build with any file changed
// has another version, so a browser never uses an old file with a new
// page. The files without a version, such as /static/app.js, are checked
// with the server at every use.

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var (
	staticFS fs.FS
	// staticVersion is "v" and 12 hex digits of a hash of every file's
	// path and content.
	staticVersion string
	// iconSet is static/carbon/icons.svg, which every page holds once.
	iconSet template.HTML
)

var versionPart = regexp.MustCompile(`^v[0-9a-f]{12}$`)

func init() {
	var err error
	if staticFS, err = fs.Sub(webFiles, "web/static"); err != nil {
		panic(err)
	}
	h := sha256.New()
	err = fs.WalkDir(staticFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(staticFS, p)
		if err != nil {
			return err
		}
		h.Write([]byte(p + "\x00"))
		sum := sha256.Sum256(data)
		h.Write(sum[:])
		return nil
	})
	if err != nil {
		panic(err)
	}
	staticVersion = "v" + hex.EncodeToString(h.Sum(nil))[:12]
	set, err := fs.ReadFile(staticFS, "carbon/icons.svg")
	if err != nil {
		panic("static/carbon/icons.svg is missing; run tools/carbon-fetch.sh: " + err.Error())
	}
	// The file is made from IBM's icons by tools/carbonprep, which takes
	// plain shapes only.
	iconSet = template.HTML(set)
}

// staticHandler serves the files, a year in the browser under the current
// version and checked at every use otherwise. An address with another
// version, from a page loaded before the dashboard was upgraded, gets the
// current file, which the browser does not keep.
func staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/static/")
		h := w.Header()
		h.Set("Cache-Control", "no-cache")
		if first, rest, ok := strings.Cut(name, "/"); ok && versionPart.MatchString(first) {
			name = rest
			if first == staticVersion {
				h.Set("Cache-Control", "public, max-age=31536000, immutable")
			}
		}
		// Files only: no folder lists.
		if info, err := fs.Stat(staticFS, name); err != nil || info.IsDir() || name != path.Clean(name) {
			h.Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		h.Set("ETag", `"`+staticVersion+`"`)
		http.ServeFileFS(w, r, staticFS, name)
	})
}

var iconNames = regexp.MustCompile(`^[a-z0-9]+(?:-{1,2}[a-z0-9]+)*$`)

// iconHTML draws one of Carbon's icons, 16 pixels, from the set in the
// page; slot puts it into a component's slot, such as a side navigation
// link's "title-icon".
func iconHTML(name, slot string) (template.HTML, error) {
	if !iconNames.MatchString(name) || (slot != "" && !iconNames.MatchString(slot)) {
		return "", fs.ErrInvalid
	}
	if slot != "" {
		slot = ` slot="` + slot + `"`
	}
	return template.HTML(`<svg class="icon" width="16" height="16"` + slot + ` aria-hidden="true" focusable="false"><use href="#icon-` + name + `"></use></svg>`), nil
}

// navItem is a link of the side navigation; Current is true on its page,
// or on one of the pages under it.
type navItem struct {
	Href, Icon, Label string
	Current           bool
}

// pageFuncs are the templates' functions: icon draws one of Carbon's
// icons from the set that icons puts into the page, nav makes a link of
// the side navigation, and up the breadcrumb to a page's list.
var pageFuncs = template.FuncMap{
	"icon":     func(name string) (template.HTML, error) { return iconHTML(name, "") },
	"slotIcon": iconHTML,
	"icons":    func() template.HTML { return iconSet },
	"up":       func(href, label string) navItem { return navItem{Href: href, Label: label} },
	"nav": func(d pageData, href, icon, label string, pages ...string) navItem {
		item := navItem{Href: href, Icon: icon, Label: label}
		for _, p := range pages {
			item.Current = item.Current || d.Page == p
		}
		return item
	},
}
