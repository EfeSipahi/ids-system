// Package config reads the product configuration: the engine settings and
// the settings of the parts around it, such as the records.
//
// The file is one JSON object. The engine fields ("files", "exclude",
// "paranoia_level") are at the top, as before; "request_body_limit",
// "records", "applications" and "require_profile" are optional. Unknown fields are an error, so a
// misspelled setting cannot be ignored.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// Product is the whole configuration.
type Product struct {
	engine.Config

	// RequestBodyLimit is the largest part of a request body that is
	// inspected, in bytes, 1 to httpmodel.MaxBodyLimit (T3). Left out, it
	// is httpmodel.DefaultBodyLimit. Of a longer body, the first part is
	// inspected and the request shows "partly inspected".
	RequestBodyLimit *int `json:"request_body_limit"`

	// Records is nil when the file has no "records" section; then no
	// records are written.
	Records *record.Config `json:"records"`

	// Applications are the applications with a hand-written profile (A04,
	// F2). Their profiles are read by Load; their exceptions are checked
	// against the rules by profile.NewSet.
	Applications []profile.AppConfig `json:"applications"`
	// RequireProfile makes a request of no application a finding (F7).
	RequireProfile bool `json:"require_profile"`

	// raw is the file as read, for the fingerprint.
	raw []byte
}

// Load reads the configuration file at path. Relative paths in it start at
// the directory of the file.
func Load(path string) (*Product, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	p := &Product{raw: raw}
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: invalid JSON: unexpected content after the configuration", path)
	}

	if l := p.RequestBodyLimit; l != nil && (*l < 1 || *l > httpmodel.MaxBodyLimit) {
		return nil, fmt.Errorf("%s: request_body_limit %d is not 1 to %d bytes", path, *l, httpmodel.MaxBodyLimit)
	}
	dir := filepath.Dir(path)
	if err := p.Config.Prepare(dir); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Records != nil {
		if p.Records.Dir != "" && !filepath.IsAbs(p.Records.Dir) {
			p.Records.Dir = filepath.Join(dir, p.Records.Dir)
		}
		if err := p.Records.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	for i := range p.Applications {
		app := &p.Applications[i]
		if app.Profile == "" {
			return nil, fmt.Errorf("%s: applications[%d]: profile is missing; name the application's profile file", path, i)
		}
		if !filepath.IsAbs(app.Profile) {
			app.Profile = filepath.Join(dir, app.Profile)
		}
		loaded, err := profile.Load(app.Profile)
		if err != nil {
			return nil, fmt.Errorf("%s: applications[%d] (%s): %w", path, i, app.Name, err)
		}
		app.Loaded = loaded
	}
	if p.RequireProfile && len(p.Applications) == 0 {
		return nil, fmt.Errorf("%s: require_profile is on, but there are no applications", path)
	}
	return p, nil
}

// Fingerprint identifies the configuration together with every rule file
// and profile file it loads and the paranoia level the rules run at, which
// a command-line flag may have changed. It is "sha256:" and 64 hex digits.
// A change to any of these files changes it, even when the configuration
// file is the same. A configuration without applications has the same
// fingerprint as before profiles existed.
func (p *Product) Fingerprint(level int) (string, error) {
	h := sha256.New()
	part(h, p.raw)
	for _, file := range p.Files {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		part(h, []byte(filepath.Base(file)))
		part(h, data)
	}
	part(h, binary.BigEndian.AppendUint32(nil, uint32(level)))
	for _, app := range p.Applications {
		data, err := os.ReadFile(app.Profile)
		if err != nil {
			return "", err
		}
		part(h, []byte(app.Name))
		part(h, data)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// part adds data with its length in front, so that two different lists of
// parts can never give the same bytes.
func part(h hash.Hash, data []byte) {
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(data))))
	h.Write(data)
}

// Parsing returns the options with which the inputs read each request.
func (p *Product) Parsing() httpmodel.Options {
	if p.RequestBodyLimit == nil {
		return httpmodel.Options{}
	}
	return httpmodel.Options{BodyLimit: *p.RequestBodyLimit}
}
