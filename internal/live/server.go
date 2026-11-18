package live

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
	"github.com/EfeSipahi/ids-system/internal/record"
	"github.com/EfeSipahi/ids-system/internal/result"
	"github.com/EfeSipahi/ids-system/internal/version"
)

// Program is the name ids-live gives itself in its hello frames.
const Program = "ids-live"

// helloTimeout is how long a copier may take to send its hello frame, and
// the IDS to send its own.
const helloTimeout = 10 * time.Second

// flushInterval is how often the counts and the gaps are written, also
// when no request comes (docs/records-format.md, section 5).
const flushInterval = time.Minute

// Server reads copies from copiers over a Unix socket and hands them to
// workers. Create one with Listen, run Serve, and end with Shutdown.
type Server struct {
	cfg      Config
	ln       *net.UnixListener
	recorder *record.Recorder
	analyze  func(*copyframe.Copy) error
	log      *log.Logger

	// The queue holds the copies that wait for a worker. queued and
	// queuedBytes also count the copies being analysed, so the limits
	// bound everything ids-live holds (T7).
	queue       chan item
	qmu         sync.Mutex
	queued      int
	queuedBytes int64
	qclosed     bool

	mu      sync.Mutex
	conns   map[*net.UnixConn]bool
	copiers int
	closing bool
	// dropped counts the copies a full queue dropped, and stopped the
	// ones not analysed because ids-live stopped, until they are written
	// as gaps.
	dropped, stopped gapCount
	// lastError and quiet limit error messages to one a minute.
	lastError time.Time
	quiet     int

	// halt makes the workers skip the copies still queued, when the
	// shutdown's deadline has passed.
	halt    atomic.Bool
	readers sync.WaitGroup
	workers sync.WaitGroup
	done    chan struct{}
	flusher sync.WaitGroup

	stats struct {
		received, analysed, failed, dropped, stopped, missed atomic.Int64
	}
}

type item struct {
	copy *copyframe.Copy
	size int64
}

// gapCount counts copies that were not analysed, with the first and last
// time the proxy received one of them.
type gapCount struct {
	from, to time.Time
	n        int64
}

func (g *gapCount) add(t time.Time) {
	if g.n == 0 || t.Before(g.from) {
		g.from = t
	}
	if g.n == 0 || t.After(g.to) {
		g.to = t
	}
	g.n++
}

// Stats counts what a server did since it started.
type Stats struct {
	// Received counts the copies read from copiers, and Analysed those
	// that were analysed and recorded. Failed counts copies that were
	// analysed but whose record could not be written.
	Received, Analysed, Failed int64
	// Dropped counts the copies a full queue dropped (T7), Stopped those
	// not analysed because ids-live stopped, and Missed the copies the
	// copiers reported as not sent (T8). Each of them is in a gap record.
	Dropped, Stopped, Missed int64
}

// Listen opens the socket of cfg and starts the workers, which call
// analyze for each copy. Gaps and the number of connected copiers go to
// rec, whose counts it flushes every minute. Messages go to logger; they
// never hold a value of a request.
func Listen(cfg Config, rec *record.Recorder, analyze func(*copyframe.Copy) error, logger *log.Logger) (*Server, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ln, err := listen(cfg.Socket)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		ln:       ln,
		recorder: rec,
		analyze:  analyze,
		log:      logger,
		queue:    make(chan item, cfg.QueueCopies),
		conns:    map[*net.UnixConn]bool{},
		done:     make(chan struct{}),
	}
	rec.SetCopiers(0)
	for range cfg.Workers {
		s.workers.Add(1)
		go s.work()
	}
	s.flusher.Add(1)
	go s.flushEvery(flushInterval)
	return s, nil
}

// Serve accepts copiers until Shutdown. It returns nil after Shutdown and
// the error otherwise.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return nil
			}
			return fmt.Errorf("socket %s: %w", s.cfg.Socket, err)
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = true
		s.readers.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

// serve reads the frames of one copier.
func (s *Server) serve(conn *net.UnixConn) {
	defer s.readers.Done()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()

	r := copyframe.NewReader(conn, int64(s.cfg.MaxFrameMB)<<20)
	hello, err := s.greet(conn, r)
	if err != nil {
		s.log.Printf("a copier was refused: %s", printable(err))
		return
	}
	s.log.Printf("copier connected: %s", hello)
	s.addCopier(1)
	defer s.addCopier(-1)

	for {
		f, err := r.Next()
		if err != nil {
			s.log.Printf("copier disconnected (%s): %s", hello, disconnectReason(err))
			return
		}
		switch f.Type {
		case copyframe.TypeCopy:
			s.stats.received.Add(1)
			s.enqueue(f.Copy, f.Size)
		case copyframe.TypeMissed:
			m := f.Missed
			s.stats.missed.Add(m.Count)
			if err := s.recorder.Gap(m.From, m.To, m.Count, m.Reason, record.GapCopier); err != nil {
				s.logError(err)
			}
		case copyframe.TypeHello:
			s.log.Printf("copier disconnected (%s): a second hello frame", hello)
			return
		}
		// Frames of other types are skipped (docs/copy-format.md).
	}
}

// greet reads the copier's hello frame and answers with the IDS's own. A
// copier that speaks another format version gets a hello with an error,
// and is refused. It returns the copier's name and version.
func (s *Server) greet(conn *net.UnixConn, r *copyframe.Reader) (string, error) {
	conn.SetDeadline(time.Now().Add(helloTimeout))
	defer conn.SetDeadline(time.Time{})
	f, err := r.Next()
	if err != nil {
		return "", fmt.Errorf("no hello frame: %s", disconnectReason(err))
	}
	if f.Type != copyframe.TypeHello {
		return "", fmt.Errorf("the first frame is a %s frame, not a hello frame", f.Type)
	}
	name := f.Hello.Program
	if f.Hello.Version != "" {
		name += " " + f.Hello.Version
	}
	reply := copyframe.Hello{Format: copyframe.Version, Program: Program, Version: version.Version, MaxFrame: int64(s.cfg.MaxFrameMB) << 20}
	if f.Hello.Format != copyframe.Version {
		reply.Error = fmt.Sprintf("%s speaks copy format %d; the copier speaks %d", Program, copyframe.Version, f.Hello.Format)
	}
	frame, err := copyframe.AppendHello(nil, reply)
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(frame); err != nil {
		return "", fmt.Errorf("%s: the hello frame cannot be sent: %w", name, err)
	}
	if reply.Error != "" {
		return "", fmt.Errorf("%s: %s", name, reply.Error)
	}
	return name, nil
}

// disconnectReason says why reading frames stopped.
func disconnectReason(err error) string {
	var tooLarge *copyframe.TooLargeError
	switch {
	case errors.Is(err, io.EOF):
		return "the connection was closed"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "the connection was closed inside a frame"
	case errors.As(err, &tooLarge):
		return printable(err) + " (live.max_frame_mb); the connection was closed"
	case errors.Is(err, net.ErrClosed):
		return "ids-live is stopping"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "the time ran out"
	}
	return "a frame breaks the copy format: " + printable(err) + "; the connection was closed"
}

// printable makes an error message safe to log: the copier's frames carry
// request content, so a message is cut and escaped like a record text.
func printable(err error) string {
	msg := result.Printable(err.Error())
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

func (s *Server) addCopier(delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.copiers += delta
	s.recorder.SetCopiers(s.copiers)
}

// enqueue puts a copy in the queue, or drops and counts it when the queue
// is full (T7). It never waits, so a slow analysis never slows the copier.
func (s *Server) enqueue(c *copyframe.Copy, size int64) {
	s.qmu.Lock()
	queued := false
	if !s.qclosed && s.queued < s.cfg.QueueCopies && s.queuedBytes+size <= int64(s.cfg.QueueMB)<<20 {
		// The channel holds QueueCopies items, so this never blocks.
		s.queue <- item{c, size}
		s.queued++
		s.queuedBytes += size
		queued = true
	}
	closed := s.qclosed
	s.qmu.Unlock()
	if queued {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed {
		s.stopped.add(c.Meta.Time)
		s.stats.stopped.Add(1)
	} else {
		s.dropped.add(c.Meta.Time)
		s.stats.dropped.Add(1)
	}
}

// work analyses copies until the queue is closed.
func (s *Server) work() {
	defer s.workers.Done()
	for it := range s.queue {
		switch {
		case s.halt.Load():
			s.mu.Lock()
			s.stopped.add(it.copy.Meta.Time)
			s.mu.Unlock()
			s.stats.stopped.Add(1)
		default:
			if err := s.analyzeOne(it.copy); err != nil {
				s.stats.failed.Add(1)
				s.logError(err)
			} else {
				s.stats.analysed.Add(1)
			}
		}
		s.qmu.Lock()
		s.queued--
		s.queuedBytes -= it.size
		s.qmu.Unlock()
	}
}

// analyzeOne analyses one copy. A panic in the analysis ends that copy's
// analysis only, so that one request can't stop the IDS.
func (s *Server) analyzeOne(c *copyframe.Copy) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("the analysis of a copy stopped with an internal error: %v", v)
		}
	}()
	return s.analyze(c)
}

// flushEvery writes the gaps and the counts every interval, until
// Shutdown.
func (s *Server) flushEvery(interval time.Duration) {
	defer s.flusher.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.flush()
		case <-s.done:
			return
		}
	}
}

// flush writes the gaps counted since the last flush, then the counts.
func (s *Server) flush() {
	s.writeGaps()
	if err := s.recorder.Flush(); err != nil {
		s.logError(err)
	}
}

// writeGaps writes a gap record for the copies the IDS dropped or did not
// analyse since the last one.
func (s *Server) writeGaps() {
	s.mu.Lock()
	gaps := []struct {
		g      gapCount
		reason string
	}{{s.dropped, record.ReasonQueueFull}, {s.stopped, record.ReasonStopped}}
	s.dropped, s.stopped = gapCount{}, gapCount{}
	s.mu.Unlock()
	for _, gap := range gaps {
		if gap.g.n == 0 {
			continue
		}
		if err := s.recorder.Gap(gap.g.from, gap.g.to, gap.g.n, gap.reason, record.GapIDS); err != nil {
			s.logError(err)
		}
	}
}

// logError logs an error, at most one message a minute; the next message
// says how many were left out.
func (s *Server) logError(err error) {
	s.mu.Lock()
	now := time.Now()
	if !s.lastError.IsZero() && now.Sub(s.lastError) < time.Minute {
		s.quiet++
		s.mu.Unlock()
		return
	}
	quiet := s.quiet
	s.lastError, s.quiet = now, 0
	s.mu.Unlock()
	if quiet > 0 {
		s.log.Printf("error: %s (and %d more errors in the last minute)", printable(err), quiet)
		return
	}
	s.log.Printf("error: %s", printable(err))
}

// Shutdown stops ids-live's input (SIGTERM). It stops accepting copiers
// and stops them from sending: from then on a copier's writes fail, and it
// counts its copies as missed (T8). The frames a copier had already sent
// are still read, and the queue is analysed until ctx's deadline. Copies
// left after the deadline are not analysed but counted in a gap record.
// Shutdown writes the last gaps, but does not close the recorder.
func (s *Server) Shutdown(ctx context.Context) Stats {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return s.Stats()
	}
	s.closing = true
	var conns []*net.UnixConn
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	// The listener created the socket file, and removes it.
	s.ln.Close()

	deadline, hasDeadline := ctx.Deadline()
	for _, c := range conns {
		// On Linux a copier's writes fail once the IDS has shut its side
		// for reading, while what it wrote before can still be read.
		c.CloseRead()
		if hasDeadline {
			c.SetReadDeadline(deadline)
		}
	}
	if !waitFor(&s.readers, ctx) {
		for _, c := range conns {
			c.Close()
		}
		s.readers.Wait()
	}

	s.qmu.Lock()
	s.qclosed = true
	close(s.queue)
	s.qmu.Unlock()
	if !waitFor(&s.workers, ctx) {
		s.halt.Store(true)
		s.workers.Wait()
	}

	close(s.done)
	s.flusher.Wait()
	s.writeGaps()
	return s.Stats()
}

// waitFor waits until wg is done or ctx ends, and reports whether wg is
// done.
func waitFor(wg *sync.WaitGroup, ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// Stats returns the counts so far.
func (s *Server) Stats() Stats {
	return Stats{
		Received: s.stats.received.Load(),
		Analysed: s.stats.analysed.Load(),
		Failed:   s.stats.failed.Load(),
		Dropped:  s.stats.dropped.Load(),
		Stopped:  s.stats.stopped.Load(),
		Missed:   s.stats.missed.Load(),
	}
}
