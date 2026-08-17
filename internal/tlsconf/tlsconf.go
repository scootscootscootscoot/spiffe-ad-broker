// Package tlsconf builds the broker's mutual-TLS configuration from files on
// disk, and picks up changes to them without a restart.
//
// Reloading is not a convenience here. Both halves of this material rotate on
// their own schedule and neither rotation is under the broker's control: the
// broker's own server certificate is an SVID with a lifetime measured in
// hours, and the trust bundle changes whenever the trust domain's CA rotates.
// A process that read them once at startup would stop accepting connections
// some time later for reasons that look nothing like a certificate problem.
//
// The package is transport-independent on purpose — a gRPC server would want
// exactly this — so the transport decision stays reversible.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Source holds the broker's TLS material and reloads it when the files behind
// it change.
type Source struct {
	certPath   string
	keyPath    string
	bundlePath string
	log        *slog.Logger

	mu      sync.Mutex
	current material
	stamps  map[string]stamp
}

// material is one consistent set of TLS inputs.
type material struct {
	cert   tls.Certificate
	bundle *x509.CertPool
}

// stamp is the cheap change detector: modification time plus size. It is not a
// content hash, so it can miss a same-size same-mtime rewrite — acceptable,
// because the writers here (SPIRE's SVID dumper, a config-management run) all
// touch mtime.
type stamp struct {
	modTime int64
	size    int64
}

// NewSource loads the TLS material and returns a Source.
//
// A failure here refuses: at startup there is no last-known-good to fall back
// to, and a broker that cannot prove its own identity or verify a caller's has
// nothing safe to do with a connection.
func NewSource(certPath, keyPath, bundlePath string, log *slog.Logger) (*Source, error) {
	if certPath == "" || keyPath == "" || bundlePath == "" {
		return nil, errors.New("tlsconf: certificate, key, and trust bundle paths are all required")
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Source{
		certPath:   certPath,
		keyPath:    keyPath,
		bundlePath: bundlePath,
		log:        log,
		stamps:     map[string]stamp{},
	}
	m, stamps, err := s.load()
	if err != nil {
		return nil, err
	}
	s.current, s.stamps = m, stamps
	return s, nil
}

// ServerConfig returns a *tls.Config that requires and verifies a client
// certificate, and that resolves its key material per connection so a rotated
// SVID or trust bundle takes effect without a restart.
func (s *Source) ServerConfig() *tls.Config {
	cfg := s.baseConfig()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		m := s.materialForHandshake()
		out := s.baseConfig()
		out.Certificates = []tls.Certificate{m.cert}
		out.ClientCAs = m.bundle
		return out, nil
	}
	return cfg
}

// baseConfig is the policy half, applied identically to the outer config and
// to the one returned per connection — Go uses the returned config for the
// rest of the handshake, so the client-authentication requirement has to be
// set on both or it silently does not apply.
func (s *Source) baseConfig() *tls.Config {
	return &tls.Config{
		// TLS 1.3 only. This is a greenfield service talking to workloads that
		// already speak modern TLS to get their SVID, so there is no legacy
		// client to accommodate — and it removes cipher-suite selection as a
		// thing anyone has to get right.
		MinVersion: tls.VersionTLS13,

		// The authentication. Not a bearer token layered on top: the caller's
		// identity is the verified peer certificate and nothing else.
		ClientAuth: tls.RequireAndVerifyClientCert,

		// Set explicitly so the per-connection config carries it too;
		// http.Server would otherwise only add it to the outer one.
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// materialForHandshake returns the material to use now, reloading first if the
// files changed.
//
// A failed reload keeps the last known good material and logs loudly, matching
// the mapping snapshot's staleness policy and for the same reason: a producer
// writing a truncated or half-written file must not take the service down. A
// reload that *succeeds* always takes effect, so removing a CA from the bundle
// does de-trust it.
func (s *Source) materialForHandshake() material {
	s.mu.Lock()
	defer s.mu.Unlock()

	stamps, err := s.stampAll()
	if err != nil {
		s.log.Error("cannot stat TLS material; serving last known good",
			slog.String("detail", err.Error()))
		return s.current
	}
	if sameStamps(stamps, s.stamps) {
		return s.current
	}

	m, loadedStamps, err := s.load()
	if err != nil {
		s.log.Error("TLS material changed but failed to load; serving last known good",
			slog.String("detail", err.Error()))
		// Record the stamps anyway so a persistently broken file is reported
		// once per change rather than on every single handshake.
		s.stamps = stamps
		return s.current
	}
	s.current, s.stamps = m, loadedStamps
	s.log.Info("reloaded TLS material",
		slog.String("cert", s.certPath),
		slog.String("bundle", s.bundlePath))
	return s.current
}

// load reads all three files and returns them only if every one succeeded.
// There is no partially reloaded state: a new certificate paired with an old
// bundle is a combination nobody chose.
func (s *Source) load() (material, map[string]stamp, error) {
	stamps, err := s.stampAll()
	if err != nil {
		return material{}, nil, err
	}
	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return material{}, nil, fmt.Errorf("tlsconf: load key pair: %w", err)
	}
	pemBundle, err := os.ReadFile(s.bundlePath)
	if err != nil {
		return material{}, nil, fmt.Errorf("tlsconf: read trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBundle) {
		return material{}, nil, fmt.Errorf("tlsconf: trust bundle %s contains no usable certificates", s.bundlePath)
	}
	return material{cert: cert, bundle: pool}, stamps, nil
}

func (s *Source) stampAll() (map[string]stamp, error) {
	out := make(map[string]stamp, 3)
	for _, path := range []string{s.certPath, s.keyPath, s.bundlePath} {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("tlsconf: stat: %w", err)
		}
		out[path] = stamp{modTime: info.ModTime().UnixNano(), size: info.Size()}
	}
	return out, nil
}

func sameStamps(a, b map[string]stamp) bool {
	if len(a) != len(b) {
		return false
	}
	for path, sa := range a {
		if sb, ok := b[path]; !ok || sa != sb {
			return false
		}
	}
	return true
}
