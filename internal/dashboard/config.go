// Package dashboard is the web dashboard of the IDS (V1–V7, main plan
// section 11.22). It reads the record files that the IDS writes and shows
// them to logged-in users over HTTPS. It only reads: nothing in it changes
// a record or a setting of the IDS (V2).
package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// Config is the dashboard's configuration file.
type Config struct {
	// Listen is the address to listen on, such as "127.0.0.1:8443". The
	// dashboard always uses HTTPS.
	Listen string `json:"listen"`
	// RecordsDir is the directory the IDS writes its records to.
	RecordsDir string `json:"records_dir"`
	// StateDir holds what the dashboard keeps itself: the users, the
	// certificate it made, and the log of logins.
	StateDir string `json:"state_dir"`
	// TLSCert and TLSKey are PEM files of a certificate to use. When both
	// are empty the dashboard makes its own.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// SessionIdleMinutes is how long a login lasts without use.
	SessionIdleMinutes int `json:"session_idle_minutes"`
}

// The defaults for settings that are left out.
const (
	DefaultListen      = "127.0.0.1:8443"
	DefaultIdleMinutes = 60
)

// LoadConfig reads a configuration file. Relative paths in it start at the
// directory of the file.
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
	for _, p := range []*string{&cfg.RecordsDir, &cfg.StateDir, &cfg.TLSCert, &cfg.TLSKey} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) withDefaults() Config {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.SessionIdleMinutes == 0 {
		c.SessionIdleMinutes = DefaultIdleMinutes
	}
	return c
}

func (c Config) validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("listen %q: the port must be 1 to 65535", c.Listen)
	}
	if host != "" && host != "localhost" && net.ParseIP(host) == nil {
		return fmt.Errorf("listen %q: the host must be an IP address or localhost", c.Listen)
	}
	switch {
	case c.RecordsDir == "":
		return errors.New("records_dir is missing")
	case c.StateDir == "":
		return errors.New("state_dir is missing")
	case (c.TLSCert == "") != (c.TLSKey == ""):
		return errors.New("tls_cert and tls_key must be given together, or both left empty")
	case c.SessionIdleMinutes < 1 || c.SessionIdleMinutes > 24*60:
		return fmt.Errorf("session_idle_minutes %d must be 1 to 1440", c.SessionIdleMinutes)
	}
	return nil
}
