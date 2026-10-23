package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServesOnlyHTTPS starts the real server with its own certificate. A
// browser that trusts the certificate gets the pages; plain HTTP and old
// TLS get nothing.
func TestServesOnlyHTTPS(t *testing.T) {
	d := newDashboard(t, "")
	cert, made, err := d.srv.Certificate()
	if err != nil || !made {
		t.Fatalf("certificate: made %v, %v", made, err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.srv.Serve(ctx, ln, cert) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	addr := ln.Addr().String()

	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
		// Keep redirects visible.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       5 * time.Second,
	}
	for _, host := range []string{addr, strings.Replace(addr, "127.0.0.1", "localhost", 1)} {
		resp, err := client.Get("https://" + host + "/login")
		if err != nil {
			t.Fatalf("HTTPS to %s: %v", host, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "IDS dashboard") {
			t.Errorf("HTTPS to %s: %d", host, resp.StatusCode)
		}
		if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
			t.Errorf("TLS state %+v", resp.TLS)
		}
	}

	// Plain HTTP to the same port: Go's TLS server answers 400 and
	// serves nothing.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/login")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || strings.Contains(string(body), "IDS dashboard") {
			t.Errorf("plain HTTP got %d: %s", resp.StatusCode, body)
		}
	}

	// TLS 1.1 is refused by the server. (MinVersion is set, as Go's
	// client would not offer TLS 1.1 at all otherwise.)
	old := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	if conn, err := tls.Dial("tcp", addr, old); err == nil {
		conn.Close()
		t.Error("a TLS 1.1 connection was accepted")
	} else if !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("TLS 1.1: %v", err)
	}

	// A client that does not trust the certificate stops.
	if _, err := (&http.Client{Timeout: 5 * time.Second}).Get("https://" + addr + "/login"); err == nil {
		t.Error("an untrusted self-made certificate was accepted")
	}
}

func TestOwnCertificate(t *testing.T) {
	cfg := Config{Listen: "127.0.0.1:8443", StateDir: t.TempDir()}
	cert, made, err := certificate(cfg, t0)
	if err != nil || !made {
		t.Fatalf("first: made %v, %v", made, err)
	}
	leaf := cert.Leaf
	if !strings.Contains(strings.Join(leaf.DNSNames, " "), "localhost") || len(leaf.IPAddresses) != 2 ||
		!leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || !leaf.IPAddresses[1].Equal(net.IPv6loopback) {
		t.Errorf("names %v, addresses %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if !leaf.NotAfter.Equal(t0.Add(certLifetime)) {
		t.Errorf("valid until %v", leaf.NotAfter)
	}
	for _, name := range []string{CertFile, KeyFile} {
		info, err := os.Stat(filepath.Join(cfg.StateDir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, info.Mode().Perm(), err)
		}
	}

	// The next start uses the same certificate.
	again, made, err := certificate(cfg, t0.Add(24*time.Hour))
	if err != nil || made || Fingerprint(again) != Fingerprint(cert) {
		t.Errorf("second start: made %v, %v", made, err)
	}
	// Seven days before its end it is replaced.
	renewed, made, err := certificate(cfg, t0.Add(certLifetime-certRenewBefore+time.Second))
	if err != nil || !made || Fingerprint(renewed) == Fingerprint(cert) {
		t.Errorf("near its end: made %v, %v", made, err)
	}
	// A new listen address gets a certificate that names it.
	cfg.Listen = "10.1.2.3:8443"
	moved, made, err := certificate(cfg, t0.Add(48*time.Hour))
	if err != nil || !made || !moved.Leaf.IPAddresses[2].Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("new address: made %v, %v", made, err)
	}

	// A configured certificate is used as it is.
	other := t.TempDir()
	os.Rename(filepath.Join(cfg.StateDir, CertFile), filepath.Join(other, "c.pem"))
	os.Rename(filepath.Join(cfg.StateDir, KeyFile), filepath.Join(other, "k.pem"))
	given := Config{Listen: "127.0.0.1:8443", StateDir: t.TempDir(), TLSCert: filepath.Join(other, "c.pem"), TLSKey: filepath.Join(other, "k.pem")}
	used, made, err := certificate(given, t0)
	if err != nil || made || Fingerprint(used) != Fingerprint(moved) {
		t.Errorf("configured: made %v, %v", made, err)
	}
	if _, err := os.Stat(filepath.Join(given.StateDir, CertFile)); err == nil {
		t.Error("a certificate was made although one is configured")
	}

	// A broken file is an error, not silently replaced.
	os.WriteFile(filepath.Join(cfg.StateDir, CertFile), []byte("broken"), 0o600)
	os.WriteFile(filepath.Join(cfg.StateDir, KeyFile), []byte("broken"), 0o600)
	if _, _, err := certificate(cfg, t0); err == nil {
		t.Error("a broken certificate file was accepted")
	}
}

func TestFingerprint(t *testing.T) {
	cert, _, err := certificate(Config{Listen: "127.0.0.1:8443", StateDir: t.TempDir()}, t0)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	got := Fingerprint(cert)
	if strings.ReplaceAll(got, ":", "") != want || len(got) != 95 {
		t.Errorf("Fingerprint = %s, want %s with colons", got, want)
	}
	if Fingerprint(tls.Certificate{}) != "" {
		t.Error("an empty certificate has a fingerprint")
	}
}

func TestURL(t *testing.T) {
	for listen, want := range map[string]string{
		"127.0.0.1:8443": "https://127.0.0.1:8443",
		"0.0.0.0:9000":   "https://localhost:9000",
		"[::1]:8443":     "https://[::1]:8443",
		":8443":          "https://localhost:8443",
	} {
		s := &Server{cfg: Config{Listen: listen}}
		if got := s.URL(); got != want {
			t.Errorf("URL(%q) = %q, want %q", listen, got, want)
		}
	}
}
