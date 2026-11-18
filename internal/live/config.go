// Package live is the input adapter for copies of live traffic (A01, M01):
// a proxy's copier sends each request and its response over a Unix socket
// in the frames of package copyframe, and the IDS analyses them as
// ids-offline analyses requests from files. docs/copy-format.md describes
// the frames; docs/development-plan-proxy.md the decisions T1–T12.
//
// The site never waits for the IDS (M09): copies wait in a queue with a
// size limit, and when it is full they are dropped and counted (T7). A
// count of copies that were not analysed becomes a gap record, whether the
// copier or the IDS dropped them (T8).
package live

import (
	"errors"
	"fmt"
	"strings"
)

// Config is the "live" section of the product configuration.
type Config struct {
	// Socket is the path of the Unix socket the copiers connect to. A
	// relative path starts at the directory of the configuration file.
	Socket string `json:"socket"`
	// Workers is how many copies are analysed at the same time.
	Workers int `json:"workers"`
	// QueueCopies and QueueMB limit the copies that wait for a worker or
	// are being analysed: a copy that would pass either limit is dropped
	// and counted (T7).
	QueueCopies int `json:"queue_copies"`
	QueueMB     int `json:"queue_mb"`
	// MaxFrameMB is the largest frame a copier may send. A larger one is
	// refused and its connection closed (docs/copy-format.md).
	MaxFrameMB int `json:"max_frame_mb"`
}

// The defaults for settings that are left out. The queue's limits are
// first values, to be measured in the lab (T7, T9).
const (
	DefaultWorkers     = 2
	DefaultQueueCopies = 1000
	DefaultQueueMB     = 64
	DefaultMaxFrameMB  = 16
)

// MaxSocketPath is the longest socket path Linux allows: its sun_path holds
// 108 bytes, the closing zero byte included.
const MaxSocketPath = 107

// WithDefaults returns c with the settings that were left out filled in.
func (c Config) WithDefaults() Config {
	if c.Workers == 0 {
		c.Workers = DefaultWorkers
	}
	if c.QueueCopies == 0 {
		c.QueueCopies = DefaultQueueCopies
	}
	if c.QueueMB == 0 {
		c.QueueMB = DefaultQueueMB
	}
	if c.MaxFrameMB == 0 {
		c.MaxFrameMB = DefaultMaxFrameMB
	}
	return c
}

// Validate checks the settings, with the defaults filled in.
func (c Config) Validate() error {
	c = c.WithDefaults()
	switch {
	case c.Socket == "":
		return errors.New("live: socket is missing")
	case strings.HasPrefix(c.Socket, "@"):
		// Linux reads such a name as an abstract socket, which has no file
		// and so no permissions: anyone on the machine could send copies.
		return fmt.Errorf("live: socket %q: abstract sockets (a name starting with @) are not supported; give a file path", c.Socket)
	case len(c.Socket) > MaxSocketPath:
		return fmt.Errorf("live: socket %q is %d bytes long; Linux allows at most %d. Choose a shorter path, such as /run/ids/copy.sock", c.Socket, len(c.Socket), MaxSocketPath)
	case c.Workers < 1 || c.Workers > 256:
		return fmt.Errorf("live: workers %d must be 1 to 256", c.Workers)
	case c.QueueCopies < 1 || c.QueueCopies > 1_000_000:
		return fmt.Errorf("live: queue_copies %d must be 1 to 1000000", c.QueueCopies)
	case c.QueueMB < 1 || c.QueueMB > 16384:
		return fmt.Errorf("live: queue_mb %d must be 1 to 16384", c.QueueMB)
	case c.MaxFrameMB < 1 || c.MaxFrameMB > 1024:
		return fmt.Errorf("live: max_frame_mb %d must be 1 to 1024", c.MaxFrameMB)
	case c.MaxFrameMB > c.QueueMB:
		return fmt.Errorf("live: max_frame_mb %d is more than queue_mb %d, so a copy that is allowed could never be queued", c.MaxFrameMB, c.QueueMB)
	}
	return nil
}
