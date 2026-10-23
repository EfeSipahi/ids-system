package engine

import (
	"strings"
	"testing"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
)

// The benchmarks measure the rule layer alone, with the full rule set of
// the configuration: parsing a request and running every rule on it. Run
// them with:
//
//	go test -run xxx -bench . -benchmem ./internal/engine/

func benchRuleSet(b *testing.B) *RuleSet {
	b.Helper()
	cfg, err := readConfig(firstEngineConfig)
	if err != nil {
		b.Fatal(err)
	}
	rs, err := Load(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return rs
}

var benchHeaders = []httpmodel.Header{
	{Name: "Host", Value: "shop.example.com"},
	{Name: "User-Agent", Value: "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"},
	{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{Name: "Accept-Language", Value: "tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3"},
	{Name: "Accept-Encoding", Value: "gzip, deflate, br"},
	{Name: "Referer", Value: "https://shop.example.com/urunler?kategori=kitap"},
	{Name: "Cookie", Value: "session=8f2c1d9a7b3e4f60; theme=dark; _ga=GA1.2.1234567890.1700000000"},
}

func benchRequests() map[string]httpmodel.Received {
	form := append(append([]httpmodel.Header{}, benchHeaders...), httpmodel.Header{Name: "Content-Type", Value: "application/x-www-form-urlencoded"})
	jsonHeaders := append(append([]httpmodel.Header{}, benchHeaders...), httpmodel.Header{Name: "Content-Type", Value: "application/json"})
	return map[string]httpmodel.Received{
		"normal GET": {Method: "GET", Target: "/urunler/ara?q=go+programlama+kitabi&sayfa=2&sirala=fiyat", Headers: benchHeaders},
		"normal POST form": {Method: "POST", Target: "/sepet/ekle", Headers: form,
			Body: []byte("urun_id=48213&adet=2&not=L%C3%BCtfen+hediye+paketi+yap%C4%B1n&kupon=YAZ2026")},
		"normal POST json": {Method: "POST", Target: "/api/siparis", Headers: jsonHeaders,
			Body: []byte(`{"musteri": {"ad": "Efe", "eposta": "efe@example.com"}, "urunler": [{"id": 48213, "adet": 2}, {"id": 5120, "adet": 1}], "not": "Kapıya bırakın"}`)},
		"attack GET": {Method: "GET", Target: "/urunler/ara?q=1%27+UNION+SELECT+username%2Cpassword+FROM+users--&dosya=../../../etc/passwd", Headers: benchHeaders},
		"large POST form": {Method: "POST", Target: "/yorum", Headers: form,
			Body: []byte("baslik=Harika&yorum=" + strings.Repeat("Bu+kitap+gercekten+cok+faydali+oldu.+", 250))},
	}
}

func BenchmarkEvaluate(b *testing.B) {
	rs := benchRuleSet(b)
	for name, rec := range benchRequests() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(rec.Target) + len(rec.Body)))
			for i := 0; i < b.N; i++ {
				rs.Evaluate(httpmodel.New(rec))
			}
		})
	}
}

// BenchmarkEvaluateParallel runs the same work on all CPUs at once, with one
// shared rule set, as M21 intends.
func BenchmarkEvaluateParallel(b *testing.B) {
	rs := benchRuleSet(b)
	rec := benchRequests()["normal GET"]
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rs.Evaluate(httpmodel.New(rec))
		}
	})
}

// BenchmarkLoad measures what happens once at startup: reading and
// compiling every rule file.
func BenchmarkLoad(b *testing.B) {
	cfg, err := readConfig(firstEngineConfig)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Load(cfg); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzEvaluate sends requests built from random text through the whole
// rule layer. Nothing an attacker sends may make it panic, and the same
// request must always give the same result. Without -fuzz the seeds run as
// an ordinary test.
func FuzzEvaluate(f *testing.F) {
	f.Add("/get?a=../../etc/passwd", "session=1; x=<script>", "a=1' OR '1'='1", "application/x-www-form-urlencoded")
	f.Add("/a/%2e%2e/b?%u2019=1", "", `{"a": ["<svg onload=alert(1)>", null]}`, "application/json")
	f.Add("/x", "=;;", "<a b='c'>d</a", "application/xml")
	f.Add("/", "a", "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../x\"\r\n\r\nz\r\n--B--", "multipart/form-data; boundary=B")

	cfg, err := readConfig(firstEngineConfig)
	if err != nil {
		f.Fatal(err)
	}
	rs, err := Load(cfg)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, target, cookie, body, contentType string) {
		rec := httpmodel.Received{
			Method: "POST",
			Target: target,
			Headers: []httpmodel.Header{
				{Name: "Cookie", Value: cookie},
				{Name: "Content-Type", Value: contentType},
				{Name: "X-Test", Value: body},
			},
			Body: []byte(body),
		}
		first := rs.Evaluate(httpmodel.New(rec))
		second := rs.Evaluate(httpmodel.New(rec))
		if len(first.Matches) != len(second.Matches) || first.Score("blocking_inbound_anomaly_score") != second.Score("blocking_inbound_anomaly_score") {
			t.Errorf("two runs on the same request differ: %d and %d matches", len(first.Matches), len(second.Matches))
		}
		if first.Score("blocking_inbound_anomaly_score") < 0 {
			t.Errorf("negative score")
		}
	})
}
