package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair mints a self-signed certificate and writes it, its key, and a
// single-certificate bundle into dir. serial distinguishes generations so a
// test can tell which one is being served.
func writeKeyPair(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "tlsconf test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	write(t, filepath.Join(dir, "cert.pem"), certPEM)
	write(t, filepath.Join(dir, "key.pem"), keyPEM)
	write(t, filepath.Join(dir, "bundle.pem"), certPEM)
}

// write puts content at path and stamps a distinct mtime, so the change
// detector sees a change without the test depending on filesystem timestamp
// granularity.
func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	stamp := time.Now().Add(time.Duration(len(content)) * time.Millisecond)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func paths(dir string) (cert, key, bundle string) {
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "bundle.pem")
}

func newSource(t *testing.T, dir string) *Source {
	t.Helper()
	cert, key, bundle := paths(dir)
	s, err := NewSource(cert, key, bundle, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	return s
}

// servedSerial is the serial of the certificate the source would present right
// now, obtained through the same callback a real handshake uses.
func servedSerial(t *testing.T, s *Source) int64 {
	t.Helper()
	cfg, err := s.ServerConfig().GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("config carries %d certificates, want 1", len(cfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse served certificate: %v", err)
	}
	return leaf.SerialNumber.Int64()
}

// The startup path fails closed: with no last-known-good to fall back to, a
// broker that cannot prove its identity or verify a caller's must not run.
func TestNewSourceRefusesUnreadableMaterial(t *testing.T) {
	dir := t.TempDir()
	cert, key, bundle := paths(dir)
	if _, err := NewSource(cert, key, bundle, nil); err == nil {
		t.Fatal("accepted paths that do not exist")
	}
	if _, err := NewSource("", "", "", nil); err == nil {
		t.Fatal("accepted empty paths")
	}
}

func TestNewSourceRefusesBundleWithNoCertificates(t *testing.T) {
	dir := t.TempDir()
	writeKeyPair(t, dir, 1)
	_, _, bundle := paths(dir)
	write(t, bundle, []byte("not a certificate\n"))

	cert, key, _ := paths(dir)
	if _, err := NewSource(cert, key, bundle, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("accepted a trust bundle containing no certificates")
	}
}

// The reason the package exists: an SVID with an hours-long life is rewritten
// underneath a long-running process, and the next handshake has to use it.
func TestRotatedMaterialIsPickedUp(t *testing.T) {
	dir := t.TempDir()
	writeKeyPair(t, dir, 1)
	s := newSource(t, dir)

	if got := servedSerial(t, s); got != 1 {
		t.Fatalf("serving serial %d, want 1", got)
	}

	writeKeyPair(t, dir, 2)
	if got := servedSerial(t, s); got != 2 {
		t.Fatalf("serving serial %d after rotation, want 2", got)
	}
}

// A half-written or truncated file from a rotation tool must not take the
// service down — same call as the mapping snapshot's staleness policy, for the
// same reason.
func TestFailedReloadKeepsServingLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	writeKeyPair(t, dir, 1)
	s := newSource(t, dir)

	certPath, _, _ := paths(dir)
	write(t, certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"))

	if got := servedSerial(t, s); got != 1 {
		t.Fatalf("serving serial %d after a broken rotation, want the last known good (1)", got)
	}

	// And a subsequent good write still takes effect.
	writeKeyPair(t, dir, 3)
	if got := servedSerial(t, s); got != 3 {
		t.Fatalf("serving serial %d after recovery, want 3", got)
	}
}

// A missing file is not an excuse to stop requiring client certificates.
func TestPolicyHoldsOnEveryConfig(t *testing.T) {
	dir := t.TempDir()
	writeKeyPair(t, dir, 1)
	s := newSource(t, dir)

	outer := s.ServerConfig()
	inner, err := outer.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	// Go uses the returned config for the rest of the handshake, so the client
	// authentication requirement has to be set on it too or it silently does
	// not apply.
	for name, cfg := range map[string]*tls.Config{"outer": outer, "per-connection": inner} {
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("%s config ClientAuth = %v, want RequireAndVerifyClientCert", name, cfg.ClientAuth)
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s config MinVersion = %x, want TLS 1.3", name, cfg.MinVersion)
		}
	}
	if inner.ClientCAs == nil {
		t.Error("per-connection config has no ClientCAs, so no chain could be verified")
	}
}
