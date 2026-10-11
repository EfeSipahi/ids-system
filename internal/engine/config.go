package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Config says which rule files to load and which rules in them not to run.
type Config struct {
	// Files are the rule files, loaded in this order. The order matters:
	// the setup file must come before the rules that read its settings.
	Files []string `json:"files"`

	// Exclude lists rules that are in the files but must not run. Every
	// other rule must be fully supported, or loading fails.
	Exclude []Exclusion `json:"exclude"`
}

// Exclusion names one rule that is left out, and why. The reason is
// required: it is what the startup report shows for that rule.
type Exclusion struct {
	ID     int    `json:"id"`
	Reason string `json:"reason"`
}

// LoadConfig reads a JSON configuration file. Relative paths in Files are
// taken from the directory of the configuration file.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("%s: invalid JSON: unexpected content after the configuration", path)
	}

	dir := filepath.Dir(path)
	for i, file := range cfg.Files {
		if !filepath.IsAbs(file) {
			cfg.Files[i] = filepath.Join(dir, file)
		}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) validate() error {
	if len(c.Files) == 0 {
		return errors.New("no rule files are listed")
	}
	seen := map[int]bool{}
	for _, ex := range c.Exclude {
		switch {
		case ex.ID <= 0:
			return fmt.Errorf("exclusion with invalid rule id %d", ex.ID)
		case ex.Reason == "":
			return fmt.Errorf("exclusion of rule %d has no reason", ex.ID)
		case seen[ex.ID]:
			return fmt.Errorf("rule %d is excluded twice", ex.ID)
		}
		seen[ex.ID] = true
	}
	return nil
}
