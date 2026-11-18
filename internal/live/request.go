package live

import (
	"strings"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/record"
)

// Request turns a copy into the common request (M01), read with opt. The
// client is the one the proxy determined (T5); no header is read for it.
func Request(c *copyframe.Copy, opt httpmodel.Options) *httpmodel.Request {
	m := c.Meta
	rec := httpmodel.Received{
		Method:         c.Method,
		Target:         c.Target,
		Version:        c.Proto,
		Body:           c.Body,
		BodyUnfinished: !m.Request.BodyComplete,
		RemoteAddr:     m.Client.IP,
		RemotePort:     m.Client.Port,
		LocalAddr:      m.Server.IP,
		LocalPort:      m.Server.Port,
	}
	// The copier's limit cut the body (T3); the parser says so.
	if m.Request.BodyLength > int64(len(c.Body)) {
		rec.BodyLength = m.Request.BodyLength
	}
	if len(c.Headers) > 0 {
		rec.Headers = make([]httpmodel.Header, len(c.Headers))
		for i, h := range c.Headers {
			rec.Headers[i] = httpmodel.Header{Name: h.Name, Value: h.Value}
		}
	}
	return httpmodel.NewWith(rec, opt)
}

// NewLive returns what the records keep of a copy besides the request: the
// proxy's ID and time, the connection, TLS and the response (T10, C6). The
// response's body is carried but not read until the response rules (K8).
func NewLive(c *copyframe.Copy) *record.Live {
	m := c.Meta
	l := &record.Live{
		Proxy:      record.Proxy{RequestID: m.ID, Received: m.Time},
		Connection: record.Client{IP: m.Connection.IP, Port: m.Connection.Port},
	}
	if t := m.TLS; t != nil {
		l.TLS = &record.TLS{Version: t.Version, Cipher: t.Cipher, ServerName: t.ServerName, ALPN: t.ALPN}
	}
	if r := m.Response; r != nil {
		l.Response = &record.Response{
			Status:      r.Status,
			ContentType: header(c.ResponseHeaders, "Content-Type"),
			Encoding:    header(c.ResponseHeaders, "Content-Encoding"),
			BodyLength:  r.BodyLength,
			BodyCopied:  len(c.ResponseBody),
			Note:        r.Note,
		}
	}
	return l
}

// header returns the first value of the header called name, or "".
func header(headers []copyframe.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return strings.TrimSpace(h.Value)
		}
	}
	return ""
}
