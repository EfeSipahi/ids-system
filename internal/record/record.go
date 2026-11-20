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
//   - "gap": requests of a live input that were not analysed, such as the
//     ones a full queue dropped (T7, T8).
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

	"github.com/EfeSipahi/ids-system/internal/profile"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// Schema is the version of the record format. It changes when a field
// changes its meaning, so a reader can tell old records from new ones.
const Schema = 1

// DecidedBy says which layers an alert decision is based on. Until the
// decision mechanism exists (K3) an alert is the rule layer's score at or
// above its threshold (R2). DecidedByProfile is for a request of an
// application whose profile is in "alert" mode: a profile finding makes it
// an alert too (F6).
const (
	DecidedBy        = "rule layer only"
	DecidedByProfile = "rule and profile layers"
)

// The record types.
const (
	TypeStart   = "start"
	TypeRequest = "request"
	TypeCounts  = "counts"
	TypeGap     = "gap"
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

	// Applications are the applications with a profile, with their level
	// and their rule exceptions (F9, F11), and RequireProfile says whether
	// a request of no application is a finding (F7). Both are left out
	// when the configuration has no applications.
	Applications   []result.AppStartup `json:"applications,omitempty"`
	RequireProfile bool                `json:"require_profile,omitempty"`

	// Input says where the run's requests come from. It is left out for
	// request files (ids-offline).
	Input *Input `json:"input,omitempty"`
}

// Input is the source of a run's requests.
type Input struct {
	// Kind is InputLive, copies from a proxy's copiers (A01), or
	// InputReplay, request files replayed on their own clock.
	Kind string `json:"kind"`
	// Socket is the Unix socket the copies arrive on.
	Socket string `json:"socket,omitempty"`
	// Replayed is when a replay was run. The run's records carry the
	// requests' own times, not this one.
	Replayed time.Time `json:"replayed,omitzero"`
}

const (
	// InputLive is the kind of a live input, ids-live.
	InputLive = "live"
	// InputReplay is the kind of a replay: ids-offline -replay, which
	// writes each record at the time its request carries.
	InputReplay = "replay"
)

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

	// Alert is true when the score reached the threshold (R2), or when
	// the application's profile is in "alert" mode and found something
	// (F6). AlertBy names which: "rules", "profile" or both.
	Alert     bool     `json:"alert"`
	AlertBy   []string `json:"alert_by,omitempty"`
	DecidedBy string   `json:"decided_by"`

	// Application and Profile are set when the configuration has
	// applications (F9). Application.ParanoiaLevel is the level the
	// request's rules ran at (F11).
	Application *result.Application `json:"application,omitempty"`
	Profile     *Profile            `json:"profile,omitempty"`

	// Proxy names the request at the proxy that copied it, so that it can
	// be found in the proxy's logs. It is set for a live input only, as
	// are Connection, TLS and Response.
	Proxy *Proxy `json:"proxy,omitempty"`

	// Client is who sent the request: for a live input, the client as the
	// proxy determined it (T5); Connection is then the address the
	// proxy's connection came from, which is a proxy in front of it when
	// there is one.
	Client     Client  `json:"client"`
	Connection *Client `json:"connection,omitempty"`
	Server     Server  `json:"server"`
	// TLS is set when the request came over TLS (T10).
	TLS      *TLS            `json:"tls,omitempty"`
	HTTP     HTTP            `json:"request"`
	Response *Response       `json:"response,omitempty"`
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

// Proxy names a request at the proxy that copied it.
type Proxy struct {
	// RequestID is the proxy's ID of the request, such as Caddy's request
	// UUID.
	RequestID string `json:"request_id"`
	// Received is when the proxy received the request. The record's own
	// time is when the IDS analysed it.
	Received time.Time `json:"received"`
}

// TLS describes the TLS session a request came over (T10). It is a record
// field only, not an input of any detection layer.
type TLS struct {
	// Version is the protocol, such as "TLS 1.3", and Cipher the cipher
	// suite, such as "TLS_AES_128_GCM_SHA256".
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	// ServerName is the name the client asked for (SNI), and ALPN the
	// protocol the two sides agreed on, such as "h2".
	ServerName string `json:"server_name,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
}

// Response describes the response the application sent (C6). Its body is
// not analysed until the response rules exist (K8).
type Response struct {
	Status int `json:"status"`
	// ContentType and Encoding are the response's Content-Type and
	// Content-Encoding headers.
	ContentType string `json:"content_type,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	// BodyLength is how many body bytes the application sent, and
	// BodyCopied how many of them the copier copied (T4).
	BodyLength int64 `json:"body_length"`
	BodyCopied int   `json:"body_copied"`
	// Note says why the copied body is not the whole body: "type not
	// copied", "not finished", "upgraded" or "handler error".
	Note string `json:"note,omitempty"`
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

// Profile is what the profile layer found in one request (F6). Findings
// never hold a value of the request (M11). At most 64 are kept; Omitted
// counts the rest. BodyChecked is false when the body was not read to its
// end, so its parameters were not judged (M05).
type Profile struct {
	Findings    []profile.Finding `json:"findings"`
	Omitted     int               `json:"omitted,omitempty"`
	BodyChecked bool              `json:"body_checked"`
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
	// Recorded counts the requests that got a record, Alerts those that
	// are alerts, and Incomplete those that could not be inspected
	// completely.
	Recorded   int `json:"recorded"`
	Alerts     int `json:"alerts"`
	Incomplete int `json:"incomplete"`
	// NoProfile counts the requests of no application, when the
	// configuration has applications.
	NoProfile int `json:"no_profile,omitempty"`

	// UnknownApplications counts, by name, the requests for which the
	// proxy named an application that the configuration does not have
	// (T6). They count as requests of no application.
	UnknownApplications map[string]int `json:"unknown_applications,omitempty"`
	// Copiers is the most copiers that were connected at the same time in
	// the period. It is set for a live input only, where 0 tells "no proxy
	// is sending" from "no requests come".
	Copiers *int `json:"copiers,omitempty"`
}

// Gap counts requests of a live input that were not analysed (T7, T8):
// Missed requests that reached the proxy between From and To.
type Gap struct {
	Type   string    `json:"type"`
	Schema int       `json:"schema"`
	Run    string    `json:"run"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Missed int64     `json:"missed"`
	// Reason says why, such as "queue full", "not connected" or "refused
	// by the IDS".
	Reason string `json:"reason"`
	// Source says who did not pass the copies on: GapCopier, the proxy's
	// copier, or GapIDS, the IDS itself.
	Source string `json:"source"`
}

// The sources of a gap.
const (
	GapCopier = "copier"
	GapIDS    = "ids"
)

// The reasons of a gap whose source is the IDS. A copier's reasons are
// those of its missed frames (docs/copy-format.md).
const (
	// ReasonQueueFull: the IDS's queue was full, so the copy was dropped.
	ReasonQueueFull = "queue full"
	// ReasonStopped: the IDS stopped before it analysed the copy.
	ReasonStopped = "IDS stopped"
)

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
