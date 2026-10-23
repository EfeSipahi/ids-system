package record

import (
	"strings"
	"time"

	"github.com/EfeSipahi/ids-system/internal/engine"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/result"
)

// Wanted reports whether a request gets a record: when a rule matched, or
// when the request could not be inspected completely (R1, M05). Other
// requests are only counted.
func Wanted(req *httpmodel.Request, res *engine.Result) bool {
	return len(res.Matches) > 0 || !req.Status.Body.Complete()
}

// builder turns the engine's result for one request into a record.
type builder struct {
	masker
	full   bool
	engine Engine
}

// build makes the record of req. res must be the result of evaluating req.
func (b builder) build(req *httpmodel.Request, res *engine.Result, id, run string, now time.Time) Request {
	s := b.collect(req)
	rec := Request{
		Type:      TypeRequest,
		Schema:    Schema,
		ID:        id,
		Run:       run,
		Time:      now.UTC(),
		DecidedBy: DecidedBy,
		Client:    Client{IP: req.Received.RemoteAddr, Port: req.Received.RemotePort},
		Server: Server{
			Host: s.text(first(req.HeaderValues("Host")), maxHost),
			IP:   req.Received.LocalAddr,
			Port: req.Received.LocalPort,
		},
		HTTP:     b.http(req, s),
		Analysis: result.NewAnalysis(req),
		Findings: []Finding{},
		Score:    result.NewScore(res),
		Engine:   b.engine,
	}
	rec.Alert = rec.Score.Exceeded
	for _, m := range res.Matches {
		rec.Findings = append(rec.Findings, b.finding(m, s))
	}
	if b.full && rec.Alert {
		rec.Full = b.fullRequest(req, s)
	}
	return rec
}

func (b builder) http(req *httpmodel.Request, s secrets) HTTP {
	h := HTTP{
		Method:      s.text(req.Received.Method, maxHeaderName),
		Path:        s.text(req.Parsed.Path, maxPath),
		Query:       s.text(b.maskQuery(req.Parsed.RawQuery), maxQuery),
		Version:     s.text(req.Received.Version, maxHeaderName),
		UserAgent:   s.text(first(req.HeaderValues("User-Agent")), maxUserAgent),
		Referer:     s.text(b.maskURL(first(req.HeaderValues("Referer"))), maxReferer),
		ContentType: s.text(first(req.HeaderValues("Content-Type")), maxContentType),
		BodyLength:  len(req.Received.Body),
		HeaderNames: []string{},
	}
	for i, header := range req.Received.Headers {
		if i == maxHeaders {
			h.HeaderNames = append(h.HeaderNames, "…")
			break
		}
		h.HeaderNames = append(h.HeaderNames, s.text(header.Name, maxHeaderName))
	}
	for i, c := range req.Parsed.Cookies {
		if i == maxCookies {
			break
		}
		h.Cookies = append(h.Cookies, Cookie{Name: s.text(c.Name, maxHeaderName), Hash: b.cookieHash(c.Value)})
	}
	return h
}

func (b builder) finding(m engine.Match, s secrets) Finding {
	text := s.text
	if wholeLocation(m.VarName) {
		text = s.wholeText
	}
	f := Finding{
		RuleID:   m.RuleID,
		Severity: m.Severity,
		Message:  text(m.Message, maxMessage),
		Location: s.text(m.VarName, maxHeaderName),
		Matched:  text(m.Value, maxMatched),
		Data:     text(m.Data, maxMatched),
		Action:   m.Action,
		Tags:     m.Tags,
	}
	if b.secretLocation(m.VarName) {
		// The matched value is the secret itself; the rule and the place
		// are enough to know what happened.
		if m.Value != "" {
			f.Matched = Masked
		}
		if m.Data != "" {
			f.Data = Masked
		}
		if m.MessageSensitive {
			f.Message = result.Hidden
		}
	}
	return f
}

func (b builder) fullRequest(req *httpmodel.Request, s secrets) *Full {
	full := &Full{Headers: [][2]string{}}
	for _, h := range req.Received.Headers {
		value := Masked
		if !isSecretHeader(h.Name) {
			value = s.text(h.Value, maxHeaderValue)
		}
		full.Headers = append(full.Headers, [2]string{s.text(h.Name, maxHeaderName), value})
	}
	full.Body = s.wholeText(b.maskBody(req), maxBody)
	return full
}

// maskBody returns the body with the values of secret form fields masked.
// Secret values in other body formats are removed by the secrets pass,
// which knows them from the parsed fields.
func (b builder) maskBody(req *httpmodel.Request) string {
	body := string(req.Received.Body)
	if req.Status.BodyFormat == "form" {
		return b.maskQuery(body)
	}
	return body
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
