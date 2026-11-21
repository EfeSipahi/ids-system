package dashboard

import (
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// TestStaticFiles checks how the browser keeps the files (assets.go): a
// year under this build's version, checked at every use without it, and
// no folder lists or files from outside.
func TestStaticFiles(t *testing.T) {
	d := newDashboard(t, "")
	session := d.login(t, "admin", d.password)
	page := d.do("GET", "/", nil, session).Body.String()
	for _, f := range []string{"app.js", "app.css", "carbon.js", "carbon/themes.css", "theme.js"} {
		if !strings.Contains(page, `"/static/`+staticVersion+"/"+f+`"`) {
			t.Errorf("the page does not load %s under the version", f)
		}
	}
	for path, want := range map[string]string{
		"/static/" + staticVersion + "/app.js":               "public, max-age=31536000, immutable",
		"/static/" + staticVersion + "/carbon/button.min.js": "public, max-age=31536000, immutable",
		"/static/app.js":                                       "no-cache",
		"/static/v000000000000/app.js":                         "no-cache",
		"/static/" + staticVersion + "/carbon/ui-shell.min.js": "public, max-age=31536000, immutable",
	} {
		w := d.do("GET", path, nil, nil)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != want || w.Header().Get("ETag") != `"`+staticVersion+`"` {
			t.Errorf("%s: %d, Cache-Control %q, ETag %q", path, w.Code, w.Header().Get("Cache-Control"), w.Header().Get("ETag"))
		}
		if strings.HasSuffix(path, ".js") && !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
			t.Errorf("%s: Content-Type %q; a module needs a script type", path, w.Header().Get("Content-Type"))
		}
	}
	for _, path := range []string{"/static/", "/static/carbon", "/static/carbon/", "/static/" + staticVersion + "/", "/static/nothing.js", "/static/" + staticVersion + "/../app.js"} {
		if w := d.do("GET", path, nil, nil); w.Code == http.StatusOK {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	if w := d.do("GET", "/static/"+staticVersion+"/app.js", nil, nil, "If-None-Match", `"`+staticVersion+`"`); w.Code != http.StatusNotModified {
		t.Errorf("a known version: %d, want 304", w.Code)
	}
}

// TestIconsExist checks that every icon a page or app.js names is in the
// set that tools/carbon-fetch.sh made, and that the set holds no style or
// script.
func TestIconsExist(t *testing.T) {
	set := string(iconSet)
	for _, bad := range []string{"<style", "<script", "style=", "href=", "on"} {
		if bad == "on" {
			if regexp.MustCompile(`\son[a-z]+=`).MatchString(set) {
				t.Error("the icon set has an event attribute")
			}
			continue
		}
		if strings.Contains(set, bad) {
			t.Errorf("the icon set has %s", bad)
		}
	}
	named := map[string]bool{}
	pattern := regexp.MustCompile(`(?:\{\{(?:slotIcon|icon) "|#icon-|\bicon\("|\(nav \. "[^"]*" ")([a-z0-9-]+)`)
	err := fs.WalkDir(webFiles, "web", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasPrefix(p, "web/static/carbon/") || !(strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".js")) {
			return err
		}
		data, _ := webFiles.ReadFile(p)
		for _, m := range pattern.FindAllStringSubmatch(string(data), -1) {
			named[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(named) < 10 {
		t.Fatalf("only %d icons named: %v", len(named), named)
	}
	for name := range named {
		if !strings.Contains(set, `id="icon-`+name+`"`) {
			t.Errorf("icon %s is not in carbon/icons.svg: add it to tools/carbon-fetch.sh and run it", name)
		}
	}
	if _, err := iconHTML(`x" onload="y`, ""); err == nil {
		t.Error("an icon name with a quote was taken")
	}
}
