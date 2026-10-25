// Package record writes what the IDS found to files that people and other
// programs can read later, such as the dashboard (A09, R1–R7).
//
// A record file holds one JSON object per line. Every line has a "type":
//
//   - "start": written when the IDS starts, and again at the top of each new
//     file. It says which engine, rules and settings produced the records
//     after it.
//   - "request": one request with a finding or an incomplete analysis (R1).
//   - "counts": how many requests were analysed in a time window, including
//     the ones that got no record.
//
// docs/records-format.md describes the format for other programs.
//
// What is written follows R4 (main plan section 11.22): who sent a request
// and where it went are kept, secrets are masked, and the full request is
// only written when the configuration asks for it.
package record

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/result"
)

// Schema is the version of the record format. It changes when a field
// changes its meaning, so a reader can tell old records from new ones.
const Schema = 1

// DecidedBy says which layers an alert decision is based on. Until the
// decision mechanism exists (K3) an alert is the rule layer's score at or
// above its threshold (R2).
const DecidedBy = "rule layer only"

// The record types.
const (
	TypeStart   = "start"
	TypeRequest = "request"
	TypeCounts  = "counts"
)

// Engine identifies the code, rules and settings that produced a record
// (R7).
type Engine struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	// CRS is the rule set's SecComponentSignature, such as
	// "OWASP_CRS/4.30.0".
	CRS           string `json:"crs"`
	ParanoiaLevel int    `json:"paranoia_level"`
	// Config is a fingerprint of the configuration file and every rule
	// file it loads, such as "sha256:9f2c...". Two records with the same
	// fingerprint were produced by the same rules and settings.
	Config string `json:"config"`
}

// Start is the first record of a run, and of every file.
type Start struct {
	Type   string    `json:"type"`
	Schema int       `json:"schema"`
	Run    string    `json:"run"`
	Time   time.Time `json:"time"`
	Engine Engine    `json:"engine"`
	// Rules lists every rule of the loaded files, active or not.
	Rules []Rule `json:"rules"`
}

// Rule is the status of one rule.
type Rule struct {
	ID    int    `json:"id"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Phase int    `json:"phase"`
	// ParanoiaLevel is 0 for a rule that belongs to no level, such as a
	// setup or scoring rule.
	ParanoiaLevel int `json:"paranoia_level,omitempty"`
	// Msg is the rule's msg text as written in its file, with macros
	// unexpanded. It is rule text, never request content.
	Msg    string `json:"msg,omitempty"`
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
}

// Request is the record of one request.
type Request struct {
	Type   string    `json:"type"`
	Schema int       `json:"schema"`
	ID     string    `json:"id"`
	Run    string    `json:"run"`
	Time   time.Time `json:"time"`

	// Alert is true when the score reached the threshold (R2).
	Alert     bool   `json:"alert"`
	DecidedBy string `json:"decided_by"`

	Client   Client          `json:"client"`
	Server   Server          `json:"server"`
	HTTP     HTTP            `json:"request"`
	Analysis result.Analysis `json:"analysis"`
	Findings []Finding       `json:"findings"`
	Score    result.Score    `json:"score"`
	Engine   Engine          `json:"engine"`

	// Full is only set for an alert when the configuration turns on
	// full_requests.
	Full *Full `json:"full,omitempty"`
}

// Client is who sent the request. IP is empty when it is not known.
type Client struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// Server is where the request was sent: the Host header and the address.
type Server struct {
	Host string `json:"host,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
}

// HTTP is the request line and the headers that describe the request,
// with secrets masked.
type HTTP struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Query       string   `json:"query,omitempty"`
	Version     string   `json:"version,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
	Referer     string   `json:"referer,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	BodyLength  int      `json:"body_length"`
	HeaderNames []string `json:"header_names"`
	// Cookies are the cookies of the request with a hash in place of
	// each value.
	Cookies []Cookie `json:"cookies,omitempty"`
}

// Cookie is one cookie. Hash is a keyed hash of its value: the same value
// gives the same hash, so the requests of one session can be linked, and
// the value itself is not written.
type Cookie struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// Finding is one rule match.
type Finding struct {
	RuleID   int    `json:"rule_id"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message"`
	Location string `json:"location,omitempty"`
	// Matched is the value the rule matched, after the rule's
	// transformations, and Data the rule's logdata text. Both are cut to
	// a fixed length and masked when they come from a secret.
	Matched string   `json:"matched,omitempty"`
	Data    string   `json:"data,omitempty"`
	Action  string   `json:"action"`
	Tags    []string `json:"tags,omitempty"`
}

// Full is the whole request, for an investigation. Secret header values
// are masked here too.
type Full struct {
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body,omitempty"`
}

// Counts says how many requests were analysed between From and To.
type Counts struct {
	Type     string    `json:"type"`
	Schema   int       `json:"schema"`
	Run      string    `json:"run"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Analysed int       `json:"analysed"`
	// Recorded counts the requests that got a record, Alerts those whose
	// score reached the threshold, and Incomplete those that could not be
	// inspected completely.
	Recorded   int `json:"recorded"`
	Alerts     int `json:"alerts"`
	Incomplete int `json:"incomplete"`
}

// Config is the "records" section of the configuration.
type Config struct {
	// Dir is the directory of the record files. A relative path starts at
	// the directory of the configuration file.
	Dir string `json:"dir"`
	// MaxFileMB is the size at which a file is closed and a new one
	// started. KeepFiles is how many files are kept, the current one
	// included; older ones are deleted (R5).
	MaxFileMB int `json:"max_file_mb"`
	KeepFiles int `json:"keep_files"`
	// FullRequests adds all headers and the body to the record of every
	// alert. It is off by default (R4).
	FullRequests bool `json:"full_requests"`
	// SecretNames are more parameter names whose values are masked, in
	// addition to the built-in ones. A name matches when it contains one
	// of these, in any case.
	SecretNames []string `json:"secret_names"`
}

// The defaults for settings that are left out.
const (
	DefaultMaxFileMB = 10
	DefaultKeepFiles = 10
)

// WithDefaults returns c with the settings that were left out filled in.
func (c Config) WithDefaults() Config {
	if c.MaxFileMB == 0 {
		c.MaxFileMB = DefaultMaxFileMB
	}
	if c.KeepFiles == 0 {
		c.KeepFiles = DefaultKeepFiles
	}
	return c
}

// Validate checks the settings, with the defaults filled in.
func (c Config) Validate() error {
	c = c.WithDefaults()
	switch {
	case c.Dir == "":
		return errors.New("records: dir is missing")
	case c.MaxFileMB < 1 || c.MaxFileMB > 1024:
		return fmt.Errorf("records: max_file_mb %d must be 1 to 1024", c.MaxFileMB)
	case c.KeepFiles < 1 || c.KeepFiles > 1000:
		return fmt.Errorf("records: keep_files %d must be 1 to 1000", c.KeepFiles)
	}
	for _, name := range c.SecretNames {
		if strings.TrimSpace(name) == "" {
			return errors.New("records: secret_names contains an empty name")
		}
	}
	return nil
}
