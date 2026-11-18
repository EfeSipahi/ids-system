// Command testapp is the application behind Caddy in the lab (T9). It
// answers the kinds of response the copier treats differently (T4, C7): a
// text, an HTML page, an image, a gzip response, a large text, a slow
// response and a WebSocket upgrade. Every other path, such as the CSIC
// shop's, gets a short text. It reads every request body to its end, as an
// application behind a proxy does, and never echoes a request value.
//
//	go run ./lab/testapp -listen 127.0.0.1:9000
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9000", "address to listen on")
	flag.Parse()
	log.Printf("testapp listening on http://%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, handler()))
}

// png is a 1×1 PNG image.
var png = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/lab/text", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "a plain text answer\n")
	})
	mux.HandleFunc("/lab/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><title>lab</title><p>an HTML answer</p>\n")
	})
	mux.HandleFunc("/lab/image.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	})
	mux.HandleFunc("/lab/gzip", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		z := gzip.NewWriter(&buf)
		io.WriteString(z, strings.Repeat("<p>compressed</p>\n", 100))
		z.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	})
	// /lab/big?kb=600 answers that many kilobytes of text.
	mux.HandleFunc("/lab/big", func(w http.ResponseWriter, r *http.Request) {
		kb, _ := strconv.Atoi(r.URL.Query().Get("kb"))
		w.Header().Set("Content-Type", "text/plain")
		line := strings.Repeat("x", 1023) + "\n"
		for range min(max(kb, 1), 100_000) {
			io.WriteString(w, line)
		}
	})
	// /lab/slow?ms=12000 sends its headers and a first part at once and the
	// rest after that many milliseconds.
	mux.HandleFunc("/lab/slow", func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "first part\n")
		http.NewResponseController(w).Flush()
		select {
		case <-time.After(time.Duration(min(max(ms, 0), 120_000)) * time.Millisecond):
			io.WriteString(w, "second part\n")
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/lab/ws", webSocket)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	return mux
}

// webSocket accepts a WebSocket upgrade (RFC 6455) and closes the
// connection after its first message, or after a second.
func webSocket(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "a WebSocket upgrade is expected", http.StatusBadRequest)
		return
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
	rw.Flush()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	bufio.NewReader(rw).ReadByte()
}
