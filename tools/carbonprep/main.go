// Command carbonprep makes two files of the dashboard's IBM Carbon parts
// from Carbon's npm packages: the theme file and the icon set.
// tools/carbon-fetch.sh downloads the packages and runs it.
//
//	go run ./tools/carbonprep -styles styles.min.css -styles-version 1.120.0 \
//	    -icons svg -icons-version 11.92.0 -names "add copy" -out DIR
//
// themes.css holds the custom properties (--cds-…) of Carbon's g10 theme,
// for light, and g100, for dark, from @carbon/styles: the colours the
// components read. The light theme is the default; the dark one applies
// when the system is dark and the user chose no theme, or when the user
// chose dark (data-theme="dark" on the root). The classes theme-g10 and
// theme-g100 make a part of a page light or dark whatever the page's
// theme, as Carbon's dark header is.
//
// icons.svg is a set of <symbol id="icon-NAME"> from @carbon/icons, the
// 16-pixel drawing where Carbon has one, else the 32-pixel one. The
// dashboard puts it into every page once and draws an icon with
// <use href="#icon-NAME">, so that icons take the text colour and load
// nothing.
//
// The icons named with -css-icons are also written as files of their own,
// NAME-g10.svg and NAME-g100.svg, in the icon colour of each theme: a
// stylesheet draws them as a background, such as the arrow of a select,
// where an icon can't take the text colour.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	styles := flag.String("styles", "", "@carbon/styles' css/styles.min.css")
	stylesVersion := flag.String("styles-version", "", "the version of @carbon/styles")
	icons := flag.String("icons", "", "@carbon/icons' svg folder")
	iconsVersion := flag.String("icons-version", "", "the version of @carbon/icons")
	names := flag.String("names", "", "the icons to take, separated by spaces")
	cssIcons := flag.String("css-icons", "", "icons to write as files of their own too, separated by spaces")
	out := flag.String("out", "", "the folder to write themes.css and icons.svg to")
	flag.Parse()
	if *styles == "" || *icons == "" || *out == "" || *stylesVersion == "" || *iconsVersion == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*styles, *stylesVersion, *icons, *iconsVersion, strings.Fields(*names), strings.Fields(*cssIcons), *out); err != nil {
		fmt.Fprintln(os.Stderr, "carbonprep:", err)
		os.Exit(1)
	}
}

func run(stylesPath, stylesVersion, iconsDir, iconsVersion string, names, cssIcons []string, out string) error {
	css, err := os.ReadFile(stylesPath)
	if err != nil {
		return err
	}
	themes, err := themeFile(string(css), stylesVersion)
	if err != nil {
		return err
	}
	sprite, err := iconFile(iconsDir, iconsVersion, names)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "themes.css"), []byte(themes), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "icons.svg"), []byte(sprite), 0o644); err != nil {
		return err
	}
	// The icon colour (icon-primary) of each theme.
	colours := map[string]string{}
	for _, theme := range []string{"g10", "g100"} {
		m := regexp.MustCompile(`(?:^|[;{])` + "--cds-icon-primary:(#[0-9a-fA-F]{3,8})").FindStringSubmatch(themeBlock(themes, theme))
		if m == nil {
			return fmt.Errorf("no --cds-icon-primary in the %s theme", theme)
		}
		colours[theme] = m[1]
	}
	for _, name := range cssIcons {
		inner, viewBox, err := readIcon(iconsDir, name)
		if err != nil {
			return err
		}
		for _, theme := range []string{"g10", "g100"} {
			file := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="%s" fill="%s">%s</svg>`+"\n", viewBox, colours[theme], inner)
			if err := os.WriteFile(filepath.Join(out, name+"-"+theme+".svg"), []byte(file), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// themeBlock is the custom properties themeFile wrote for a theme: the
// rule of :root,.theme-g10 or of :root[data-theme="dark"],.theme-g100.
func themeBlock(themes, theme string) string {
	start := map[string]string{"g10": ":root,.theme-g10{", "g100": `:root[data-theme="dark"],.theme-g100{`}[theme]
	i := strings.Index(themes, start)
	if i < 0 {
		return ""
	}
	block := themes[i+len(start):]
	if end := strings.IndexByte(block, '}'); end >= 0 {
		block = block[:end]
	}
	return block
}

// tokens are custom properties in the order first set; a later value of
// the same property replaces the earlier one, as in CSS.
type tokens struct {
	names  []string
	values map[string]string
}

func (t *tokens) set(name, value string) {
	if t.values == nil {
		t.values = map[string]string{}
	}
	if _, ok := t.values[name]; !ok {
		t.names = append(t.names, name)
	}
	t.values[name] = value
}

func (t *tokens) String() string {
	var b strings.Builder
	for _, n := range t.names {
		b.WriteString(n + ":" + t.values[n] + ";")
	}
	return b.String()
}

// themeFile takes the custom properties of :root and of the themes g10
// and g100 out of Carbon's stylesheet. The ones of :root, such as
// --cds-layer: var(--cds-layer-01), are set again in each theme zone: a
// var() is worked out where the property is set, so without that a dark
// zone would inherit the light page's layer.
func themeFile(css, version string) (string, error) {
	var root, g10, g100 tokens
	rules, err := topRules(css)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		var targets []*tokens
		for _, sel := range splitTop(r.selector, ',') {
			switch strings.TrimSpace(sel) {
			case ":root":
				targets = append(targets, &root)
			case ".cds--g10":
				targets = append(targets, &g10)
			case ".cds--g100":
				targets = append(targets, &g100)
			}
		}
		if len(targets) == 0 {
			continue
		}
		for _, decl := range splitTop(r.body, ';') {
			name, value, ok := strings.Cut(decl, ":")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if !ok || !strings.HasPrefix(name, "--cds-") || value == "" {
				continue
			}
			for _, t := range targets {
				t.set(name, value)
			}
		}
	}
	if len(g10.names) < 100 || len(g100.names) < 100 {
		return "", fmt.Errorf("the stylesheet has %d properties for g10 and %d for g100; is it @carbon/styles' styles.min.css?", len(g10.names), len(g100.names))
	}
	return fmt.Sprintf(`/* IBM Carbon Design System's themes g10 (light) and g100 (dark): the
   custom properties of @carbon/styles %s (Apache-2.0, Copyright IBM Corp.;
   LICENSE in this folder), made by tools/carbon-fetch.sh. Do not edit this
   file: run the script again. */
:root,.theme-g10,.theme-g100{%s}
:root,.theme-g10{color-scheme:light;%s}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;%s}}
:root[data-theme="dark"],.theme-g100{color-scheme:dark;%s}
`, version, root.String(), g10.String(), g100.String(), g100.String()), nil
}

type rule struct{ selector, body string }

// topRules lists a stylesheet's style rules outside at-rules: Carbon's
// themes are plain rules, and what is inside @media, @font-face or
// @keyframes is not wanted here.
func topRules(css string) ([]rule, error) {
	var rules []rule
	i := 0
	for i < len(css) {
		open := indexOutside(css, i, '{')
		if open < 0 {
			break
		}
		end, err := matching(css, open)
		if err != nil {
			return nil, err
		}
		selector := strings.TrimSpace(stripComments(css[i:open]))
		if !strings.HasPrefix(selector, "@") {
			rules = append(rules, rule{selector, css[open+1 : end]})
		}
		i = end + 1
	}
	return rules, nil
}

var comments = regexp.MustCompile(`(?s)/\*.*?\*/`)

func stripComments(s string) string { return comments.ReplaceAllString(s, "") }

// indexOutside finds c from i, outside strings and comments.
func indexOutside(s string, i int, c byte) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			i = skipString(s, i)
		case '/':
			if i+1 < len(s) && s[i+1] == '*' {
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					return -1
				}
				i += end + 3
			}
		case c:
			return i
		}
	}
	return -1
}

// skipString returns the index of the quote that closes the string that
// starts at i.
func skipString(s string, i int) int {
	q := s[i]
	for i++; i < len(s); i++ {
		if s[i] == '\\' {
			i++
		} else if s[i] == q {
			return i
		}
	}
	return len(s)
}

// matching returns the index of the brace that closes the one at open.
func matching(s string, open int) (int, error) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			i = skipString(s, i)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errors.New("the stylesheet has a block that does not close")
}

// splitTop splits s at sep where sep is outside parentheses and strings.
func splitTop(s string, sep byte) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\'':
			i = skipString(s, i)
		case '(':
			depth++
		case ')':
			depth--
		case sep:
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

var (
	svgOpen  = regexp.MustCompile(`(?s)^\s*(?:<\?xml[^>]*>\s*)?<svg\b([^>]*)>`)
	viewBox  = regexp.MustCompile(`\bviewBox="([0-9. ]+)"`)
	unwanted = regexp.MustCompile(`(?s)<title>.*?</title>|<defs>.*?</defs>|<[a-z]+\b[^>]*(?:Transparent Rectangle|fill:\s*none|class="cls-)[^>]*/>`)
	allowed  = regexp.MustCompile(`^(?:\s*<(?:path|circle|rect|polygon|ellipse|line|polyline)(?:\s+[a-zA-Z-]+="[-0-9A-Za-z.,#()\s]*")*\s*/>)*\s*$`)
	iconName = regexp.MustCompile(`^[a-z0-9]+(?:-{1,2}[a-z0-9]+)*$`)
)

// iconFile makes the set of icons.
func iconFile(dir, version string, names []string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- IBM Carbon Design System's icons, from @carbon/icons %s (Apache-2.0,\n     Copyright IBM Corp.; LICENSE in this folder), made by tools/carbon-fetch.sh.\n     Do not edit this file: run the script again. -->\n", version)
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" class="icon-set" aria-hidden="true" focusable="false">` + "\n")
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		inner, vb, err := readIcon(dir, name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, `<symbol id="icon-%s" viewBox="%s">%s</symbol>`+"\n", name, vb, inner)
	}
	b.WriteString("</svg>\n")
	return b.String(), nil
}

// readIcon reads one of Carbon's icons: its shapes and its viewBox. It
// takes the icon only when it is shapes with plain attributes: a style, a
// script or a link in an icon file would end up in every page.
func readIcon(dir, name string) (inner, vb string, err error) {
	if !iconName.MatchString(name) {
		return "", "", fmt.Errorf("%q is not an icon name", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, "16", name+".svg"))
	if errors.Is(err, os.ErrNotExist) {
		data, err = os.ReadFile(filepath.Join(dir, "32", name+".svg"))
	}
	if err != nil {
		return "", "", fmt.Errorf("icon %s: %w", name, err)
	}
	m := svgOpen.FindSubmatchIndex(data)
	if m == nil {
		return "", "", fmt.Errorf("icon %s: no <svg> element", name)
	}
	box := viewBox.FindSubmatch(data[m[2]:m[3]])
	end := bytes.LastIndex(data, []byte("</svg>"))
	if box == nil || end < m[1] {
		return "", "", fmt.Errorf("icon %s: no viewBox, or no end", name)
	}
	inner = unwanted.ReplaceAllString(string(data[m[1]:end]), "")
	if !allowed.MatchString(inner) {
		return "", "", fmt.Errorf("icon %s holds more than plain shapes: %.200s", name, inner)
	}
	return strings.TrimSpace(inner), string(box[1]), nil
}
