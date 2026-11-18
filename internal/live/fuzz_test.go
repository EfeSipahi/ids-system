package live

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// secretChars are what a fuzzed secret may hold: printable characters that
// a header value can carry, attack characters among them.
const secretChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '<>();/-_.!*@$"

// FuzzLiveSecretsAreMasked: one secret, put in a password parameter, a
// cookie, the Authorization header, and the profile's secret JSON field and
// header, never reaches the records of a live copy, whatever else the copy
// holds. The copy goes through a frame and back, as from a copier, and the
// records have full_requests on.
func FuzzLiveSecretsAreMasked(f *testing.F) {
	f.Add("hunter2 union select", "/api/pay?q=1", "1 union select 2", "shop")
	f.Add("x' union select 1 <script>", "/search?c", "", "")
	f.Add("UNION SELECT pass", "/", "a", "shop2")
	rs := loadRules(f)
	apps := testApps(f, rs)
	dir := filepath.Join(f.TempDir(), "records")
	rec, err := record.OpenWith(record.Config{Dir: dir, FullRequests: true}, record.Engine{Version: "test", CRS: "TEST/1", ParanoiaLevel: 1, Config: "sha256:test"},
		rs.Statuses(), apps, &record.Input{Kind: record.InputLive, Socket: "/fuzz.sock"})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { rec.Close() })
	a := &Analyzer{Rules: rs, Apps: apps, Recorder: rec}
	file, err := os.Open(filepath.Join(dir, record.CurrentFile))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { file.Close() })

	f.Fuzz(func(t *testing.T, raw, target, note, application string) {
		var kept strings.Builder
		for _, r := range raw {
			if strings.ContainsRune(secretChars, r) {
				kept.WriteRune(r)
			}
		}
		// The markers make the secret a text that cannot be in the record
		// by chance.
		secret := "Zx" + kept.String() + "Qk"
		if len(secret) < 8 || len(secret) > 80 {
			return
		}
		if !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \t\r\n#") || !utf8.ValidString(target) ||
			!utf8.ValidString(note) || !utf8.ValidString(application) || len(application) > copyframe.MaxTextSize {
			return
		}
		escaped := url.QueryEscape(secret)
		for _, s := range []string{target, note, application} {
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
		body, err := json.Marshal(map[string]any{"card": map[string]string{"number": secret}, "note": note})
		if err != nil {
			return
		}
		cp := testCopy(1, "shop.example.com", target+sep+"password="+escaped)
		cp.Method = "POST"
		cp.Meta.Application = application
		cp.Headers = append(cp.Headers,
			copyframe.Header{Name: "Cookie", Value: "sid=" + escaped},
			copyframe.Header{Name: "Authorization", Value: "Bearer " + secret},
			copyframe.Header{Name: "X-Key", Value: secret},
			copyframe.Header{Name: "Content-Type", Value: "application/json"})
		cp.Body = body
		cp.Meta.Request.BodyLength = int64(len(body))
		frame, err := copyframe.AppendCopy(nil, cp)
		if err != nil {
			return // the application name is not printable text
		}
		fr, err := copyframe.NewReader(bytes.NewReader(frame), 1<<20).Next()
		if err != nil {
			t.Fatalf("a frame the copier writes can't be read: %v", err)
		}
		if err := a.Analyze(fr.Copy); err != nil {
			t.Fatal(err)
		}

		lines, err := io.ReadAll(file) // what this copy added
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(lines), []byte("\n")) {
			if len(line) == 0 {
				continue
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
		}
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
