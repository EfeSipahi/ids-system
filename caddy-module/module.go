// Package idscopy is the Caddy module ids_copy: it copies each request and
// its response to the IDS, ids-live, over a Unix socket, without ever
// making the request wait (A01, decisions T1–T12 of
// docs/development-plan-proxy.md). The frames are those of
// docs/copy-format.md.
//
//	ids_copy {
//		application shop
//		socket /run/ids/copy.sock
//	}
//
// The handler runs first among Caddy's handlers, so it sees the request
// before any rewrite. It copies the request body as the application reads
// it, and the response body for text types, each up to a limit, and puts
// the copy in a queue when the response ends. When the queue is full or
// ids-live can't be reached, the copy is dropped and counted, and the count
// reaches ids-live as a missed frame once it can (T7, T8).
package idscopy

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
	"go.uber.org/zap"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
)

func init() {
	caddy.RegisterModule(Copier{})
	httpcaddyfile.RegisterHandlerDirective("ids_copy", parseCaddyfile)
	// First of all handlers, before "tracing", the first one of Caddy's
	// standard order, so that no other handler changes the request first.
	httpcaddyfile.RegisterDirectiveOrder("ids_copy", httpcaddyfile.Before, "tracing")
}

// Defaults of the settings (T3, T4, T7, C7). The queue's limits and
// MaxWait are first values, to be measured in the lab (T9).
const (
	DefaultRequestBodyLimit  = 13107200 // Coraza's SecRequestBodyLimit
	DefaultResponseBodyLimit = 524288   // Coraza's SecResponseBodyLimit
	DefaultQueueCopies       = 1000
	DefaultQueueMB           = 64
	DefaultMaxWait           = 10 * time.Second
)

// DefaultResponseTypes are the response types whose body is copied (T4).
var DefaultResponseTypes = []string{"text/plain", "text/html", "text/xml"}

// maxSocketPath is the longest socket path Linux allows.
const maxSocketPath = 107

// Copier is the ids_copy handler.
type Copier struct {
	// Application names the application for the IDS's profiles (T6). Left
	// out, the IDS finds it by Host and path.
	Application string `json:"application,omitempty"`
	// Socket is the Unix socket ids-live listens on.
	Socket string `json:"socket,omitempty"`
	// RequestBodyLimit and ResponseBodyLimit are how many body bytes are
	// copied, in bytes. The rest is counted, not copied.
	RequestBodyLimit  int64 `json:"request_body_limit,omitempty"`
	ResponseBodyLimit int64 `json:"response_body_limit,omitempty"`
	// ResponseTypes are the media types whose response body is copied.
	ResponseTypes []string `json:"response_types,omitempty"`
	// QueueCopies and QueueMB limit the copies waiting to be sent. They
	// belong to the socket: copiers of the same socket share one queue,
	// and the limits of the one provisioned last hold, so after a reload
	// those of the new configuration.
	QueueCopies int `json:"queue_copies,omitempty"`
	QueueMB     int `json:"queue_mb,omitempty"`
	// MaxWait is how long a copy waits for the response to end. After it,
	// the copy is sent with what was copied so far, marked "not
	// finished" (C7).
	MaxWait caddy.Duration `json:"max_wait,omitempty"`

	types  map[string]bool
	sender *sender
	logger *zap.Logger
}

// CaddyModule returns the module's information.
func (Copier) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ids_copy",
		New: func() caddy.Module { return new(Copier) },
	}
}

// Provision fills in the defaults and joins the sender of the socket.
func (c *Copier) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger()
	c.withDefaults()
	c.types = map[string]bool{}
	for _, t := range c.ResponseTypes {
		c.types[strings.ToLower(t)] = true
	}
	if err := c.Validate(); err != nil {
		return err
	}
	s, err := joinSender(c.Socket, c.QueueCopies, int64(c.QueueMB)<<20, c.logger)
	if err != nil {
		return err
	}
	c.sender = s
	return nil
}

func (c *Copier) withDefaults() {
	if c.RequestBodyLimit == 0 {
		c.RequestBodyLimit = DefaultRequestBodyLimit
	}
	if c.ResponseBodyLimit == 0 {
		c.ResponseBodyLimit = DefaultResponseBodyLimit
	}
	if c.ResponseTypes == nil {
		c.ResponseTypes = DefaultResponseTypes
	}
	if c.QueueCopies == 0 {
		c.QueueCopies = DefaultQueueCopies
	}
	if c.QueueMB == 0 {
		c.QueueMB = DefaultQueueMB
	}
	if c.MaxWait == 0 {
		c.MaxWait = caddy.Duration(DefaultMaxWait)
	}
}

// Validate checks the settings, with the defaults filled in.
func (c *Copier) Validate() error {
	switch {
	case c.Socket == "":
		return errors.New("ids_copy: socket is missing")
	case strings.HasPrefix(c.Socket, "@"):
		return fmt.Errorf("ids_copy: socket %q: abstract sockets are not supported; give a file path", c.Socket)
	case len(c.Socket) > maxSocketPath:
		return fmt.Errorf("ids_copy: socket %q is %d bytes long; Linux allows at most %d", c.Socket, len(c.Socket), maxSocketPath)
	case c.Application != "" && !printable(c.Application, copyframe.MaxTextSize):
		return fmt.Errorf("ids_copy: application %q must be at most %d bytes of printable text", c.Application, copyframe.MaxTextSize)
	case c.RequestBodyLimit < 1 || c.RequestBodyLimit > 1<<30:
		return fmt.Errorf("ids_copy: request_body_limit %d must be 1 byte to 1 GiB", c.RequestBodyLimit)
	case c.ResponseBodyLimit < 1 || c.ResponseBodyLimit > 1<<30:
		return fmt.Errorf("ids_copy: response_body_limit %d must be 1 byte to 1 GiB", c.ResponseBodyLimit)
	case c.QueueCopies < 1 || c.QueueCopies > 1_000_000:
		return fmt.Errorf("ids_copy: queue_copies %d must be 1 to 1000000", c.QueueCopies)
	case c.QueueMB < 1 || c.QueueMB > 16384:
		return fmt.Errorf("ids_copy: queue_mb %d must be 1 to 16384", c.QueueMB)
	case c.MaxWait < 0:
		return fmt.Errorf("ids_copy: max_wait %v is negative", time.Duration(c.MaxWait))
	}
	for _, t := range c.ResponseTypes {
		if media, _, err := mime.ParseMediaType(t); err != nil || media != strings.ToLower(t) || !strings.Contains(media, "/") {
			return fmt.Errorf("ids_copy: response_types: %q is not a media type such as text/plain", t)
		}
	}
	return nil
}

// Cleanup leaves the sender, which stops when no configuration uses it.
func (c *Copier) Cleanup() error {
	if c.sender == nil {
		return nil
	}
	_, err := senders.Delete(c.Socket)
	return err
}

// ServeHTTP copies the request and its response. The request never waits
// for the IDS: the copy is only put in the queue.
func (c *Copier) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ex := newExchange(c, r)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &bodyReader{ReadCloser: r.Body, ex: ex}
	}
	timer := time.AfterFunc(time.Duration(c.MaxWait), ex.timeout)
	err := next.ServeHTTP(&responseWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}, ex: ex}, r)
	timer.Stop()
	ex.finish(err)
	return err
}

// UnmarshalCaddyfile reads the ids_copy block:
//
//	ids_copy [<matcher>] {
//		application <name>
//		socket <path>
//		request_body_limit <size>
//		response_body_limit <size>
//		response_types <type>...
//		queue_copies <count>
//		queue_mb <megabytes>
//		max_wait <duration>
//	}
func (c *Copier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // the directive's name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		name := d.Val()
		args := d.RemainingArgs()
		one := func() (string, error) {
			if len(args) != 1 {
				return "", d.ArgErr()
			}
			return args[0], nil
		}
		var err error
		switch name {
		case "application":
			c.Application, err = one()
		case "socket":
			c.Socket, err = one()
		case "request_body_limit", "response_body_limit":
			var v string
			if v, err = one(); err == nil {
				var n uint64
				if n, err = humanize.ParseBytes(v); err != nil || n > 1<<30 {
					return d.Errf("%s: %q is not a size of at most 1 GiB, such as 512KiB", name, v)
				}
				if name == "request_body_limit" {
					c.RequestBodyLimit = int64(n)
				} else {
					c.ResponseBodyLimit = int64(n)
				}
			}
		case "response_types":
			if len(args) == 0 {
				return d.ArgErr()
			}
			c.ResponseTypes = args
		case "queue_copies", "queue_mb":
			var v string
			if v, err = one(); err == nil {
				var n int
				if _, err := fmt.Sscan(v, &n); err != nil {
					return d.Errf("%s: %q is not a number", name, v)
				}
				if name == "queue_copies" {
					c.QueueCopies = n
				} else {
					c.QueueMB = n
				}
			}
		case "max_wait":
			var v string
			if v, err = one(); err == nil {
				var dur time.Duration
				if dur, err = caddy.ParseDuration(v); err != nil {
					return d.Errf("max_wait: %v", err)
				}
				c.MaxWait = caddy.Duration(dur)
			}
		default:
			return d.Errf("unknown setting %q", name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	c := new(Copier)
	// Caddy has reset the dispenser to the directive's name, which
	// UnmarshalCaddyfile reads first.
	err := c.UnmarshalCaddyfile(h.Dispenser)
	return c, err
}

// printable reports whether s is UTF-8 without control characters and at
// most max bytes long, as the copy format wants its short texts.
func printable(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

var (
	_ caddy.Provisioner           = (*Copier)(nil)
	_ caddy.Validator             = (*Copier)(nil)
	_ caddy.CleanerUpper          = (*Copier)(nil)
	_ caddyhttp.MiddlewareHandler = (*Copier)(nil)
	_ caddyfile.Unmarshaler       = (*Copier)(nil)
)
