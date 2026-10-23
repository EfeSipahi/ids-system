// Package config reads the product configuration: the engine settings and
// the settings of the parts around it, such as the records.
//
// The file is one JSON object. The engine fields ("files", "exclude",
// "paranoia_level") are at the top, as before; "records" is optional.
// Unknown fields are an error, so a misspelled setting cannot be ignored.
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
	"github.com/EfeSipahi/ids-system/internal/record"
)

// Product is the whole configuration.
type Product struct {
	engine.Config

	// Records is nil when the file has no "records" section; then no
	// records are written.
	Records *record.Config `json:"records"`

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
	return p, nil
}

// Fingerprint identifies the configuration together with every rule file
// it loads and the paranoia level the rules run at, which a command-line
// flag may have changed. It is "sha256:" and 64 hex digits. A change to
// any rule file changes it, even when the configuration file is the same.
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
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// part adds data with its length in front, so that two different lists of
// parts can never give the same bytes.
func part(h hash.Hash, data []byte) {
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(data))))
	h.Write(data)
}
