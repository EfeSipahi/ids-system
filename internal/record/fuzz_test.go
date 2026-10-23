package record

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

var update = flag.Bool("update", false, "write the golden file again")

// TestLineFormat pins the record format, the contract between the IDS and
// the dashboard (docs/records-format.md). A change here is a change of the
// contract and needs a new schema number when a reader would misread it.
func TestLineFormat(t *testing.T) {
	_, line := build(t, secretRequest(), true)
	golden := filepath.Join("testdata", "request-record.json")
	if *update {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, line, "", "  "); err != nil {
			t.Fatal(err)
		}
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, append(pretty.Bytes(), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')
	if !bytes.Equal(compact.Bytes(), line) {
		t.Errorf("the record line changed:\n got %s\nwant %s", line, compact.Bytes())
	}
}

// secretChars are what a fuzzed secret may hold: printable characters that
// a header value can carry, attack characters among them.
const secretChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '<>();/-_.!*@$"

// FuzzSecretsAreMasked: one secret, put in a password parameter of the
// query, a form field, a cookie and the Authorization header, never
// appears in the record, whatever else the request holds. The test rules
// match the secret in all these places and in the whole query and body.
func FuzzSecretsAreMasked(f *testing.F) {
	f.Add("hunter2 union select", "/login?q=1", "note=hello")
	f.Add("x' union select 1 <script>", "/a/b?c", "")
	f.Add("UNION SELECT pass", "/", "a=union+select&b")
	rules := loadRules(f)
	b := testBuilder(true)
	f.Fuzz(func(t *testing.T, raw, target, extra string) {
		var kept strings.Builder
		for _, r := range raw {
			if strings.ContainsRune(secretChars, r) {
				kept.WriteRune(r)
			}
		}
		// The markers make the secret a text that cannot be in the
		// record by chance.
		secret := "Zx" + kept.String() + "Qk"
		if len(secret) < 8 || len(secret) > 80 {
			return
		}
		if !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \t\r\n#") || !utf8.ValidString(target) || !utf8.ValidString(extra) {
			return
		}
		escaped := url.QueryEscape(secret)
		for _, s := range []string{target, extra} {
			// A secret in the path or in a field without a secret name is
			// recorded by design (known limit).
			if containsFold(s, secret) || containsFold(s, escaped) || containsFold(s, "zx") {
				return
			}
		}
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		req := httpmodel.New(httpmodel.Received{
			Method:  "POST",
			Target:  target + sep + "password=" + escaped,
			Version: "HTTP/1.1",
			Headers: []httpmodel.Header{
				{Name: "Host", Value: "shop.example.com"},
				{Name: "Cookie", Value: "sid=" + escaped},
				{Name: "Authorization", Value: "Bearer " + secret},
				{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			},
			Body: []byte(extra + "&pwd=" + escaped),
		})
		res := rules.Evaluate(req)
		line, err := marshal(b.build(res.Request, res, "id", "run", time.Time{}))
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, line)
		}
		walkStrings(v, func(s string) {
			if containsFold(s, secret) || containsFold(s, escaped) {
				t.Fatalf("secret %q is in %q\nrecord: %s", secret, s, line)
			}
		})
	})
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func walkStrings(v any, fn func(string)) {
	switch v := v.(type) {
	case string:
		fn(v)
	case []any:
		for _, x := range v {
			walkStrings(x, fn)
		}
	case map[string]any:
		for k, x := range v {
			fn(k)
			walkStrings(x, fn)
		}
	}
}
