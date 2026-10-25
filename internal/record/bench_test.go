package record_test

import (
	"testing"

	"github.com/EfeSipahi/ids-system/internal/config"
	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/offline"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// The cost of a record next to the cost of the analysis, on the seven
// requests of secrets.json: attacks at secrets, with 2 to 7 findings each,
// all written (R1), with the product configuration (CRS 4.30.0, level 1).
//
//	go test ./internal/record/ -run '^$' -bench . -benchmem

func loadBench(b *testing.B) (*engine.RuleSet, *config.Product, []offline.Example) {
	b.Helper()
	cfg, err := config.Load("../../configs/crs-first-engine.json")
	if err != nil {
		b.Fatal(err)
	}
	rules, err := engine.Load(cfg.Config)
	if err != nil {
		b.Fatal(err)
	}
	examples, err := offline.LoadFile("../../testdata/requests/secrets.json")
	if err != nil {
		b.Fatal(err)
	}
	return rules, cfg, examples
}

func BenchmarkEvaluate(b *testing.B) {
	rules, _, examples := loadBench(b)
	i := 0
	for b.Loop() {
		rules.Evaluate(examples[i%len(examples)].Request)
		i++
	}
}

func BenchmarkAdd(b *testing.B) {
	for _, full := range []bool{false, true} {
		name := "default"
		if full {
			name = "full_requests"
		}
		b.Run(name, func(b *testing.B) {
			rules, cfg, examples := loadBench(b)
			results := make([]*engine.Result, len(examples))
			for i, ex := range examples {
				results[i] = rules.Evaluate(ex.Request)
			}
			rc := *cfg.Records
			rc.Dir = b.TempDir()
			rc.FullRequests = full
			rec, err := record.Open(rc, record.NewEngine(rules, "sha256:bench"), rules.Statuses(), nil)
			if err != nil {
				b.Fatal(err)
			}
			defer rec.Close()
			i := 0
			for b.Loop() {
				res := results[i%len(results)]
				if err := rec.Add(res.Request, res, nil); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}
