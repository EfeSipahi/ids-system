// Command replay sends example requests to a web server, for the lab (T9).
// Each request goes over TLS as raw HTTP/1.1 bytes, exactly as the example
// file writes it: the request line, the headers in their order and case,
// and the body. Only -keepalive and -xff change what is sent.
//
//	go run ./lab/replay -addr localhost:8080 -ca root.crt -parallel 8 FILE...
//
// It checks the server's certificate against -ca, Caddy's local root, and
// prints how many requests got which status, and how long they took: the
// median and the slowest 1 in 100, from writing the request to reading the
// whole response. With -h2, the requests go through Go's HTTP client over
// HTTP/2 instead; the header names are then Go's.
//
// Exit status: 0 when every request got a response, 1 otherwise.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EfeSipahi/ids-system/internal/httpmodel"
	"github.com/EfeSipahi/ids-system/internal/offline"
)

func main() {
	os.Exit(run())
}

type options struct {
	addr      string
	keepalive bool
	xff       string
	h2        bool
	tls       *tls.Config
}

// result is what one request did.
type result struct {
	status int
	took   time.Duration
	err    error
}

// summary is the JSON report.
type summary struct {
	Sent     int            `json:"sent"`
	Answered int            `json:"answered"`
	Failed   int            `json:"failed"`
	Statuses map[string]int `json:"statuses"`
	Errors   []string       `json:"errors,omitempty"`
	Parallel int            `json:"parallel"`
	Seconds  float64        `json:"seconds"`
	PerSec   float64        `json:"per_second"`
	MedianMS float64        `json:"median_ms"`
	P90MS    float64        `json:"p90_ms"`
	P99MS    float64        `json:"p99_ms"`
	MaxMS    float64        `json:"max_ms"`
}

func run() int {
	addr := flag.String("addr", "localhost:8080", "server `host:port`; the host is also the TLS server name")
	caFile := flag.String("ca", "", "PEM `file` of the root that signed the server's certificate (Caddy's local root)")
	parallel := flag.Int("parallel", 1, "requests sent at the same time")
	repeat := flag.Int("repeat", 1, "send the whole list this many times")
	skip := flag.Int("skip", 0, "leave out the first `n` requests of the list")
	limit := flag.Int("limit", 0, "send at most `n` requests of the list (0: all)")
	keepalive := flag.Bool("keepalive", false, "leave out Connection headers, so that connections are reused")
	xff := flag.String("xff", "", "add an X-Forwarded-For header with this `value`")
	h2 := flag.Bool("h2", false, "send through Go's HTTP client over HTTP/2")
	asJSON := flag.Bool("json", false, "print the report as JSON")
	flag.Parse()
	if *caFile == "" || flag.NArg() == 0 || *parallel < 1 || *repeat < 1 {
		fmt.Fprintln(os.Stderr, "replay: give -ca, at least one example file, and -parallel and -repeat of 1 or more")
		return 2
	}
	pem, err := os.ReadFile(*caFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 2
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fmt.Fprintf(os.Stderr, "replay: %s holds no certificate\n", *caFile)
		return 2
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: -addr: %v\n", err)
		return 2
	}

	var requests []*httpmodel.Request
	for _, file := range flag.Args() {
		examples, err := offline.LoadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "replay: %v\n", err)
			return 2
		}
		for _, ex := range examples {
			requests = append(requests, ex.Request)
		}
	}
	requests = requests[min(*skip, len(requests)):]
	if *limit > 0 && *limit < len(requests) {
		requests = requests[:*limit]
	}
	var list []*httpmodel.Request
	for range *repeat {
		list = append(list, requests...)
	}

	opt := options{addr: *addr, keepalive: *keepalive, xff: *xff, h2: *h2,
		tls: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12}}
	results := make([]result, len(list))
	next := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	for range *parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := newWorker(opt)
			defer w.close()
			for i := range next {
				results[i] = w.send(list[i])
			}
		}()
	}
	for i := range list {
		next <- i
	}
	close(next)
	wg.Wait()
	s := summarize(results, *parallel, time.Since(start))
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(s)
	} else {
		fmt.Printf("sent %d, answered %d, failed %d, statuses %v, %d at a time, %.1f s (%.0f/s); median %.2f ms, p90 %.2f ms, p99 %.2f ms, max %.2f ms\n",
			s.Sent, s.Answered, s.Failed, s.Statuses, s.Parallel, s.Seconds, s.PerSec, s.MedianMS, s.P90MS, s.P99MS, s.MaxMS)
		for _, e := range s.Errors {
			fmt.Println("error:", e)
		}
	}
	if s.Failed > 0 {
		return 1
	}
	return 0
}

func summarize(results []result, parallel int, total time.Duration) summary {
	s := summary{Sent: len(results), Statuses: map[string]int{}, Parallel: parallel, Seconds: total.Seconds()}
	var took []time.Duration
	errs := map[string]int{}
	for _, r := range results {
		if r.err != nil {
			s.Failed++
			errs[r.err.Error()]++
			continue
		}
		s.Answered++
		s.Statuses[fmt.Sprint(r.status)]++
		took = append(took, r.took)
	}
	for e, n := range errs {
		s.Errors = append(s.Errors, fmt.Sprintf("%d× %s", n, e))
	}
	slices.Sort(s.Errors)
	if total > 0 {
		s.PerSec = float64(len(results)) / total.Seconds()
	}
	if len(took) > 0 {
		slices.Sort(took)
		at := func(q float64) float64 {
			i := int(q * float64(len(took)-1))
			return float64(took[i].Microseconds()) / 1000
		}
		s.MedianMS, s.P90MS, s.P99MS, s.MaxMS = at(0.5), at(0.9), at(0.99), at(1)
	}
	return s
}

// worker sends requests one after another, reusing its connection while
// the server keeps it open.
type worker struct {
	opt    options
	conn   *tls.Conn
	r      *bufio.Reader
	client *http.Client
}

func newWorker(opt options) *worker {
	w := &worker{opt: opt}
	if opt.h2 {
		w.client = &http.Client{Transport: &http.Transport{TLSClientConfig: opt.tls, ForceAttemptHTTP2: true}, Timeout: time.Minute}
	}
	return w
}

func (w *worker) close() {
	if w.conn != nil {
		w.conn.Close()
	}
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
}

// raw writes the request as the example has it.
func raw(req *httpmodel.Request, opt options) []byte {
	rec := req.Received
	var b bytes.Buffer
	b.WriteString(rec.Method + " " + rec.Target)
	if rec.Version != "" {
		b.WriteString(" " + rec.Version)
	}
	b.WriteString("\r\n")
	length := false
	for _, h := range rec.Headers {
		if opt.keepalive && strings.EqualFold(h.Name, "Connection") {
			continue
		}
		length = length || strings.EqualFold(h.Name, "Content-Length") || strings.EqualFold(h.Name, "Transfer-Encoding")
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	if len(rec.Body) > 0 && !length {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(rec.Body))
	}
	if opt.xff != "" {
		b.WriteString("X-Forwarded-For: " + opt.xff + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(rec.Body)
	return b.Bytes()
}

func (w *worker) send(req *httpmodel.Request) result {
	if w.opt.h2 {
		return w.sendH2(req)
	}
	data := raw(req, w.opt)
	for attempt := 0; ; attempt++ {
		reused := w.conn != nil
		if w.conn == nil {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", w.opt.addr, w.opt.tls)
			if err != nil {
				return result{err: err}
			}
			w.conn, w.r = conn, bufio.NewReader(conn)
		}
		w.conn.SetDeadline(time.Now().Add(time.Minute))
		start := time.Now()
		_, err := w.conn.Write(data)
		var resp *http.Response
		if err == nil {
			resp, err = http.ReadResponse(w.r, nil)
		}
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		took := time.Since(start)
		if err != nil {
			w.conn.Close()
			w.conn = nil
			// A kept connection the server closed in the meantime: once
			// more on a new one.
			if reused && attempt == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
				continue
			}
			return result{err: err}
		}
		if resp.Close {
			w.conn.Close()
			w.conn = nil
		}
		return result{status: resp.StatusCode, took: took}
	}
}

func (w *worker) sendH2(req *httpmodel.Request) result {
	rec := req.Received
	httpReq, err := http.NewRequest(rec.Method, "https://"+w.opt.addr+rec.Target, bytes.NewReader(rec.Body))
	if err != nil {
		return result{err: err}
	}
	for _, h := range rec.Headers {
		switch strings.ToLower(h.Name) {
		case "host", "connection", "content-length":
			continue // HTTP/2 has its own
		}
		httpReq.Header.Add(h.Name, h.Value)
	}
	if w.opt.xff != "" {
		httpReq.Header.Set("X-Forwarded-For", w.opt.xff)
	}
	start := time.Now()
	resp, err := w.client.Do(httpReq)
	if err != nil {
		return result{err: err}
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		return result{err: fmt.Errorf("the answer came over %s, not HTTP/2", resp.Proto)}
	}
	return result{status: resp.StatusCode, took: time.Since(start)}
}
