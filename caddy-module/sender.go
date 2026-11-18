package idscopy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/EfeSipahi/ids-system/internal/copyframe"
)

// senders holds one sender per socket path. Caddy runs the old and the new
// configuration side by side during a reload, so a sender lives as long as
// any configuration uses it, and its connection survives reloads.
var senders = caddy.NewUsagePool()

// Timings of the connection. retryInterval is T8's "every second".
const (
	retryInterval = time.Second
	dialTimeout   = time.Second
	helloTimeout  = 5 * time.Second
	writeTimeout  = 10 * time.Second
	// stopTimeout is how long a stopping sender may take to send what is
	// queued and the last counts.
	stopTimeout = 3 * time.Second
)

// defaultMaxFrame is the IDS's frame limit when its hello gives none.
const defaultMaxFrame = 16 << 20

// Program is the copier's name in its hello frames.
const Program = "caddy ids_copy"

// Version is the copier's version.
const Version = "0.1.0-dev"

// sender sends the copies of one socket's queue to ids-live, and counts
// those it can't send (T7, T8).
type sender struct {
	socket string
	logger *zap.Logger

	mu        sync.Mutex
	maxCopies int
	maxBytes  int64
	queue     []queued
	bytes     int64
	connected bool
	stopped   bool
	// missed counts the copies not sent, by reason, until a missed frame
	// reports them.
	missed map[string]*copyframe.Missed

	wake     chan struct{}
	done     chan struct{}
	finished chan struct{}
}

type queued struct {
	cp   *copyframe.Copy
	size int64
}

// joinSender returns the sender of socket, starting it when there is
// none. The queue's limits are the newest configuration's.
func joinSender(socket string, maxCopies int, maxBytes int64, logger *zap.Logger) (*sender, error) {
	v, _, err := senders.LoadOrNew(socket, func() (caddy.Destructor, error) {
		s := &sender{
			socket:   socket,
			logger:   logger,
			missed:   map[string]*copyframe.Missed{},
			wake:     make(chan struct{}, 1),
			done:     make(chan struct{}),
			finished: make(chan struct{}),
		}
		go s.run()
		return s, nil
	})
	if err != nil {
		return nil, err
	}
	s := v.(*sender)
	s.mu.Lock()
	s.maxCopies, s.maxBytes = maxCopies, maxBytes
	s.mu.Unlock()
	return s, nil
}

// add puts a copy in the queue without waiting. When the queue is full or
// ids-live is not connected, the copy is counted instead (T7, T8).
func (s *sender) add(cp *copyframe.Copy) {
	size := approximateSize(cp)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.stopped || !s.connected:
		s.missLocked(cp.Meta.Time, copyframe.ReasonNotConnected)
	case len(s.queue) >= s.maxCopies || s.bytes+size > s.maxBytes:
		s.missLocked(cp.Meta.Time, copyframe.ReasonQueueFull)
	default:
		s.queue = append(s.queue, queued{cp, size})
		s.bytes += size
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// approximateSize is about the memory a copy holds.
func approximateSize(cp *copyframe.Copy) int64 {
	n := 512 + len(cp.Target) + len(cp.Body) + len(cp.ResponseBody)
	for _, h := range cp.Headers {
		n += len(h.Name) + len(h.Value) + 8
	}
	for _, h := range cp.ResponseHeaders {
		n += len(h.Name) + len(h.Value) + 8
	}
	return int64(n)
}

func (s *sender) missLocked(t time.Time, reason string) {
	m := s.missed[reason]
	if m == nil {
		m = &copyframe.Missed{From: t, To: t, Reason: reason}
		s.missed[reason] = m
	}
	if t.Before(m.From) {
		m.From = t
	}
	if t.After(m.To) {
		m.To = t
	}
	m.Count++
}

func (s *sender) pop() (queued, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return queued{}, false
	}
	q := s.queue[0]
	s.queue[0] = queued{}
	s.queue = s.queue[1:]
	s.bytes -= q.size
	return q, true
}

// setConnected changes the state. When the connection is lost, the copies
// still queued are counted as not sent.
func (s *sender) setConnected(up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = up
	if up {
		return
	}
	for _, q := range s.queue {
		s.missLocked(q.cp.Meta.Time, copyframe.ReasonNotConnected)
	}
	s.queue, s.bytes = nil, 0
}

// run connects, sends, and reconnects every second when the connection is
// lost, until Destruct.
func (s *sender) run() {
	defer close(s.finished)
	reported := false // that ids-live can't be reached
	for {
		conn, r, maxFrame, err := s.dial()
		if err == nil {
			reported = false
			s.logger.Info("ids_copy: connected to ids-live", zap.String("socket", s.socket), zap.Int64("max_frame", maxFrame))
			s.setConnected(true)
			err = s.serve(conn, r, maxFrame)
			s.setConnected(false)
			conn.Close()
			if err == nil {
				return
			}
			s.logger.Warn("ids_copy: the connection to ids-live ended; copies are counted as missed until it is back", zap.String("socket", s.socket), zap.Error(err))
		} else if !reported {
			reported = true
			s.logger.Warn("ids_copy: ids-live can't be reached; copies are counted as missed until it can", zap.String("socket", s.socket), zap.Error(err))
		}
		select {
		case <-s.done:
			return
		case <-time.After(retryInterval):
		}
	}
}

// dial connects and exchanges hello frames. It returns the IDS's frame
// limit.
func (s *sender) dial() (net.Conn, *copyframe.Reader, int64, error) {
	conn, err := net.DialTimeout("unix", s.socket, dialTimeout)
	if err != nil {
		return nil, nil, 0, err
	}
	fail := func(err error) (net.Conn, *copyframe.Reader, int64, error) {
		conn.Close()
		return nil, nil, 0, err
	}
	hello, err := copyframe.AppendHello(nil, copyframe.Hello{Format: copyframe.Version, Program: Program, Version: Version})
	if err != nil {
		return fail(err)
	}
	conn.SetDeadline(time.Now().Add(helloTimeout))
	if _, err := conn.Write(hello); err != nil {
		return fail(err)
	}
	r := copyframe.NewReader(conn, 1<<20)
	f, err := r.Next()
	switch {
	case err != nil:
		return fail(fmt.Errorf("no hello frame from ids-live: %w", err))
	case f.Type != copyframe.TypeHello:
		return fail(fmt.Errorf("ids-live sent a %s frame first, not a hello frame", f.Type))
	case f.Hello.Error != "":
		return fail(fmt.Errorf("ids-live refused the connection: %s", f.Hello.Error))
	case f.Hello.Format != copyframe.Version:
		return fail(fmt.Errorf("ids-live speaks copy format %d; this copier speaks %d", f.Hello.Format, copyframe.Version))
	}
	conn.SetDeadline(time.Time{})
	maxFrame := f.Hello.MaxFrame
	if maxFrame == 0 {
		maxFrame = defaultMaxFrame
	}
	return conn, r, maxFrame, nil
}

// serve sends the counts of missed copies first, then the copies, until
// the connection fails (its error) or the sender stops (nil).
func (s *sender) serve(conn net.Conn, r *copyframe.Reader, maxFrame int64) error {
	// ids-live sends nothing after its hello in format version 1; reading
	// tells when it closes the connection.
	gone := make(chan error, 1)
	go func() {
		for {
			if _, err := r.Next(); err != nil {
				gone <- err
				return
			}
		}
	}()
	tick := time.NewTicker(retryInterval)
	defer tick.Stop()
	for {
		if err := s.sendMissed(conn); err != nil {
			return err
		}
		select {
		case <-s.wake:
			if err := s.sendQueued(conn, maxFrame); err != nil {
				return err
			}
		case <-tick.C:
		case err := <-gone:
			return fmt.Errorf("ids-live closed the connection: %w", err)
		case <-s.done:
			// Send what is queued and the last counts, then stop. What
			// fails stays counted, and Destruct logs it.
			if s.sendQueued(conn, maxFrame) == nil {
				s.sendMissed(conn)
			}
			return nil
		}
	}
}

// sendQueued sends the queued copies.
func (s *sender) sendQueued(conn net.Conn, maxFrame int64) error {
	for {
		q, ok := s.pop()
		if !ok {
			return nil
		}
		if err := s.sendCopy(conn, q.cp, maxFrame); err != nil {
			return err
		}
	}
}

// sendCopy fits a copy into the IDS's frame limit (docs/copy-format.md,
// section 4.4) and sends it. A copy that can't be sent is counted.
func (s *sender) sendCopy(conn net.Conn, cp *copyframe.Copy, maxFrame int64) error {
	fits, err := cp.Fit(maxFrame)
	if err == nil && fits {
		var frame []byte
		if frame, err = copyframe.AppendCopy(nil, cp); err == nil {
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, err := conn.Write(frame); err != nil {
				s.miss(cp.Meta.Time, copyframe.ReasonNotConnected)
				return err
			}
			return nil
		}
	}
	if err != nil {
		// A copy the format does not allow. The message names the part,
		// never a value of the request.
		s.logger.Warn("ids_copy: a copy can't be sent", zap.Error(err))
	}
	s.miss(cp.Meta.Time, copyframe.ReasonRefused)
	return nil
}

func (s *sender) miss(t time.Time, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missLocked(t, reason)
}

// sendMissed sends a missed frame for each reason with a count. Counts
// that can't be sent are kept for the next connection.
func (s *sender) sendMissed(conn net.Conn) error {
	s.mu.Lock()
	pending := s.missed
	s.missed = map[string]*copyframe.Missed{}
	s.mu.Unlock()
	var err error
	for reason, m := range pending {
		frame, ferr := copyframe.AppendMissed(nil, *m)
		if ferr != nil {
			return ferr // can't happen: the counts are made here
		}
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err = conn.Write(frame); err != nil {
			break
		}
		delete(pending, reason)
	}
	if len(pending) > 0 {
		s.mu.Lock()
		for _, m := range pending {
			s.mergeLocked(m)
		}
		s.mu.Unlock()
	}
	return err
}

// mergeLocked adds the counts of m to those not yet sent.
func (s *sender) mergeLocked(m *copyframe.Missed) {
	got := s.missed[m.Reason]
	if got == nil {
		s.missed[m.Reason] = m
		return
	}
	if m.From.Before(got.From) {
		got.From = m.From
	}
	if m.To.After(got.To) {
		got.To = m.To
	}
	got.Count += m.Count
}

// Destruct stops the sender when no configuration uses it any more. It
// sends what is queued, if it can, within stopTimeout.
func (s *sender) Destruct() error {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	close(s.done)
	select {
	case <-s.finished:
	case <-time.After(stopTimeout):
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var lost int64
	for _, m := range s.missed {
		lost += m.Count
	}
	lost += int64(len(s.queue))
	if lost > 0 {
		s.logger.Warn("ids_copy: copies were not sent and could not be reported to ids-live", zap.String("socket", s.socket), zap.Int64("copies", lost))
	}
	return nil
}
