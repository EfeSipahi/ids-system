package dashboard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The files of the certificate the dashboard makes for itself.
const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
)

const (
	certLifetime = 365 * 24 * time.Hour
	// certRenewBefore: a certificate this close to its end is replaced.
	certRenewBefore = 7 * 24 * time.Hour
)

// certificate returns the certificate to serve: the configured one, or
// the dashboard's own, which is made when there is none yet, when it is
// about to expire, or when it does not name the listen address. made
// reports whether a new one was made.
func certificate(cfg Config, now time.Time) (cert tls.Certificate, made bool, err error) {
	if cfg.TLSCert != "" {
		cert, err = tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		return cert, false, err
	}
	certPath := filepath.Join(cfg.StateDir, CertFile)
	keyPath := filepath.Join(cfg.StateDir, KeyFile)
	names, ips := certHosts(cfg.Listen)

	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil && usable(cert.Leaf, names, ips, now) {
		return cert, false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, false, fmt.Errorf("%s: %w", certPath, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, false, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "IDS dashboard"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return tls.Certificate{}, false, err
	}
	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	return cert, true, err
}

// certHosts are the names and addresses the dashboard's own certificate is
// for: this machine, and the listen address when it is another one.
func certHosts(listen string) ([]string, []net.IP) {
	names := []string{"localhost"}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	host, _, _ := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() && !slices.ContainsFunc(ips, ip.Equal) {
		ips = append(ips, ip)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		// Listening on every address: name the machine too.
		if name, err := os.Hostname(); err == nil && name != "" && name != "localhost" {
			names = append(names, name)
		}
	}
	return names, ips
}

func usable(leaf *x509.Certificate, names []string, ips []net.IP, now time.Time) bool {
	if leaf == nil || now.Add(certRenewBefore).After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return false
	}
	for _, name := range names {
		if !slices.Contains(leaf.DNSNames, name) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
			return false
		}
	}
	return true
}

func writePEM(path, kind string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: kind, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Fingerprint returns the SHA-256 fingerprint of a certificate, as
// browsers show it: pairs of hex digits joined by colons. A user can
// compare it with what the browser shows before trusting the certificate.
func Fingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
