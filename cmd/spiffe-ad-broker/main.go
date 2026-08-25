// Command spiffe-ad-broker exchanges a workload's SPIFFE SVID for a
// certificate that Active Directory will accept for PKINIT.
//
// It authenticates the caller by its SVID over mutual TLS, resolves the target
// AD account from a local mapping snapshot, validates the caller's PKCS#10
// request, and asks the configured backend to issue.
//
// The adcs backend issues: it wraps the workload's request in a CMC signed by
// an enrollment agent credential, asks ADCS to issue for the mapped account,
// and refuses anything that comes back naming a different one. The
// subordinate backend is still a stub and refuses with 501.
//
// Two bounds apply to every request. A per-caller rate limit caps the work one
// workload can cause, and a global one caps this broker's aggregate draw on
// the CA. Both are token buckets, so a rotation wave still gets through.
// Separately, every issued credential is appended to -issuance-record before
// it is returned; a credential that cannot be recorded is not handed over,
// because nobody could revoke it.
//
// Usage:
//
//	spiffe-ad-broker \
//	  -listen :8443 \
//	  -tls-cert /run/spire/svid.pem -tls-key /run/spire/svid.key \
//	  -trust-bundle /run/spire/bundle.pem \
//	  -mapping /etc/spiffe-ad-broker/mapping.json \
//	  -issuance-record /var/lib/spiffe-ad-broker/issued.jsonl \
//	  -backend adcs \
//	  -adcs-ces-url https://ca.example.com/Example%%20CA_CES_Certificate/service.svc/CES \
//	  -adcs-template WorkloadPKINIT \
//	  -adcs-agent-cert agent.pem -adcs-agent-key agent.key \
//	  -adcs-client-cert ces-client.pem -adcs-client-key ces-client.key \
//	  -adcs-ca-bundle ad-ca.pem
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/broker"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/adcs"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/subordinate"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/ratelimit"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/record"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/tlsconf"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/transport/httpapi"
)

// shutdownGrace bounds how long in-flight requests get after a signal.
const shutdownGrace = 15 * time.Second

type options struct {
	listen      string
	certPath    string
	keyPath     string
	bundlePath  string
	mappingPath string
	backend     string
	maxAge      time.Duration
	logFormat   string

	// Bounds on how much work a caller, and the service as a whole, may
	// cause. recordPath is where issued credentials are accounted for.
	recordPath  string
	callerRate  float64
	callerBurst int
	globalRate  float64
	globalBurst int
	limiterIdle time.Duration

	// adcs backend. Two separate credentials, and they are not
	// interchangeable: the agent signs the enrolment request, the client
	// certificate authenticates the TLS connection to CES.
	adcsCESURL     string
	adcsTemplate   string
	adcsAgentCert  string
	adcsAgentKey   string
	adcsClientCert string
	adcsClientKey  string
	adcsCABundle   string
	adcsTimeout    time.Duration
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "spiffe-ad-broker: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}
	log, err := newLogger(opts.logFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(log)

	registry, err := mapping.Load(opts.mappingPath)
	if err != nil {
		return err
	}
	backend, err := newBackend(opts)
	if err != nil {
		return err
	}

	recorder, err := newRecorder(opts, log)
	if err != nil {
		return err
	}
	defer recorder.Close()

	b, err := broker.New(broker.Config{
		Registry:       registry,
		Backend:        backend,
		Logger:         log,
		MaxSnapshotAge: opts.maxAge,
		CallerLimit:    ratelimit.NewKeyed(opts.callerRate, opts.callerBurst, opts.limiterIdle),
		GlobalLimit:    ratelimit.New(opts.globalRate, opts.globalBurst),
		Record:         recorder,
	})
	if err != nil {
		return err
	}

	api, err := httpapi.NewServer(b, log)
	if err != nil {
		return err
	}

	tlsSource, err := tlsconf.NewSource(opts.certPath, opts.keyPath, opts.bundlePath, log)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:   api.Handler(),
		TLSConfig: tlsSource.ServerConfig(),

		// Bounded on every axis. This listener is reachable by every workload
		// in the trust domain, and an unbounded read or an idle connection
		// that never closes is the cheapest denial of service there is.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,

		// Route Go's own TLS and connection errors through the structured
		// logger rather than the standard logger's stderr.
		ErrorLog: slog.NewLogLogger(log.With(slog.String("source", "http")).Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.listen, err)
	}

	log.Info("serving",
		slog.String("addr", ln.Addr().String()),
		slog.String("path", httpapi.IssuePath),
		slog.String("backend", b.BackendName()),
		slog.String("snapshot_version", b.SnapshotVersion()),
		slog.Int("mappings", b.MappingCount()),
		slog.String("issuance_record", opts.recordPath),
	)
	// A disabled limit is a deployment decision, not a default, so it is said
	// out loud rather than inferred from the absence of a line.
	if opts.callerRate <= 0 || opts.callerBurst <= 0 {
		log.Warn("the per-caller rate limit is disabled; one caller can spend all of this process's CPU on proof-of-possession checks")
	}
	if opts.globalRate <= 0 || opts.globalBurst <= 0 {
		log.Warn("the global rate limit is disabled; this broker will place no bound on its own load against the CA")
	}
	// Said plainly rather than left for someone to discover from a 501.
	if opts.backend == "subordinate" {
		log.Warn("the subordinate backend is not implemented; every well-formed request will be refused with not_implemented",
			slog.String("backend", b.BackendName()))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		// Certificate and key are already resolved per connection by the TLS
		// source, so no paths are passed here.
		errCh <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Info("shutting down", slog.Duration("grace", shutdownGrace))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}

func parseFlags(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("spiffe-ad-broker", flag.ContinueOnError)
	fs.StringVar(&opts.listen, "listen", ":8443", "address to listen on")
	fs.StringVar(&opts.certPath, "tls-cert", "", "PEM file holding the broker's own certificate (its SVID)")
	fs.StringVar(&opts.keyPath, "tls-key", "", "PEM file holding the private key for -tls-cert")
	fs.StringVar(&opts.bundlePath, "trust-bundle", "", "PEM bundle of CAs that issue callers' SVIDs")
	fs.StringVar(&opts.mappingPath, "mapping", "", "path to the SPIFFE ID to AD SID snapshot")
	fs.StringVar(&opts.backend, "backend", "", `issuance backend: "adcs" or "subordinate"`)
	fs.DurationVar(&opts.maxAge, "mapping-max-age", 24*time.Hour,
		"report the mapping snapshot as stale beyond this age; 0 disables. Staleness never refuses issuance")
	fs.StringVar(&opts.logFormat, "log-format", "text", `log format: "text" or "json"`)

	fs.StringVar(&opts.recordPath, "issuance-record", "",
		"append-only file recording every credential issued; required with a backend that can issue")

	// Deliberately low. Issuance is a rare event in the life of a workload —
	// one credential per SVID rotation at most — so a caller asking more often
	// than this is retrying, not working, and the burst is what absorbs a
	// fleet coming back at the same time.
	fs.Float64Var(&opts.callerRate, "rate-per-caller", 0.1,
		"sustained requests per second allowed from one caller; 0 disables the per-caller limit")
	fs.IntVar(&opts.callerBurst, "burst-per-caller", 5,
		"requests one caller may make at once before the sustained rate applies")
	fs.Float64Var(&opts.globalRate, "rate-global", 2,
		"sustained requests per second this broker will ask the backend for, in total; 0 disables the global limit")
	fs.IntVar(&opts.globalBurst, "burst-global", 20,
		"requests the broker will pass to the backend at once before the sustained rate applies")
	fs.DurationVar(&opts.limiterIdle, "rate-limit-idle", ratelimit.DefaultIdle,
		"how long an unused per-caller bucket is retained before it is evicted")

	fs.StringVar(&opts.adcsCESURL, "adcs-ces-url", "", "adcs: Certificate Enrollment Web Service endpoint (https)")
	fs.StringVar(&opts.adcsTemplate, "adcs-template", "", "adcs: certificate template to enrol the target account from")
	fs.StringVar(&opts.adcsAgentCert, "adcs-agent-cert", "",
		"adcs: PEM file holding the enrollment agent certificate, which must carry the Certificate Request Agent policy")
	fs.StringVar(&opts.adcsAgentKey, "adcs-agent-key", "", "adcs: PEM file holding the private key for -adcs-agent-cert")
	fs.StringVar(&opts.adcsClientCert, "adcs-client-cert", "",
		"adcs: PEM file holding the client certificate that authenticates to CES (not the enrollment agent certificate)")
	fs.StringVar(&opts.adcsClientKey, "adcs-client-key", "", "adcs: PEM file holding the private key for -adcs-client-cert")
	fs.StringVar(&opts.adcsCABundle, "adcs-ca-bundle", "", "adcs: PEM bundle of CAs that issue the CES server certificate")
	fs.DurationVar(&opts.adcsTimeout, "adcs-timeout", 30*time.Second, "adcs: bound on one CES round trip")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	// Every one of these is required. There is no default trust bundle, no
	// default mapping, and no default backend, because each of those defaults
	// would be a guess about who may authenticate as which AD account.
	for _, required := range []struct{ flag, value string }{
		{"tls-cert", opts.certPath},
		{"tls-key", opts.keyPath},
		{"trust-bundle", opts.bundlePath},
		{"mapping", opts.mappingPath},
		{"backend", opts.backend},
	} {
		if required.value == "" {
			fs.Usage()
			return options{}, fmt.Errorf("-%s is required", required.flag)
		}
	}

	if opts.backend == "adcs" {
		for _, required := range []struct{ flag, value string }{
			{"adcs-ces-url", opts.adcsCESURL},
			{"adcs-template", opts.adcsTemplate},
			{"adcs-agent-cert", opts.adcsAgentCert},
			{"adcs-agent-key", opts.adcsAgentKey},
			{"adcs-client-cert", opts.adcsClientCert},
			{"adcs-client-key", opts.adcsClientKey},
			{"adcs-ca-bundle", opts.adcsCABundle},

			// Grouped with the adcs flags because adcs is the only backend
			// that can issue today. The rule is about capability, not about
			// this particular backend: a broker that can mint AD credentials
			// must keep an account of the ones it minted, or nobody can
			// revoke them.
			{"issuance-record", opts.recordPath},
		} {
			if required.value == "" {
				fs.Usage()
				return options{}, fmt.Errorf("-%s is required with -backend adcs", required.flag)
			}
		}
	}
	return opts, nil
}

// newRecorder opens the issuance record, or returns the discarding one when
// the configured backend cannot issue.
//
// Opening happens at startup on purpose. A broker that cannot write its record
// should fail to start, rather than discover it while refusing a caller that
// did nothing wrong.
func newRecorder(opts options, log *slog.Logger) (record.Recorder, error) {
	if opts.recordPath == "" {
		// Only reachable for a backend that cannot issue: parseFlags requires
		// the flag otherwise.
		log.Warn("no -issuance-record configured; nothing this process does will be accounted for after it exits",
			slog.String("backend", opts.backend))
		return record.Discard{}, nil
	}
	return record.Open(opts.recordPath)
}

func newBackend(opts options) (issuer.Issuer, error) {
	switch opts.backend {
	case "adcs":
		return newADCSBackend(opts)
	case "subordinate":
		return subordinate.New(), nil
	default:
		return nil, fmt.Errorf("unknown backend %q (want %q or %q)", opts.backend, "adcs", "subordinate")
	}
}

// newADCSBackend assembles the two credentials the adcs backend needs.
//
// They are separate on purpose and cannot be collapsed. The agent credential
// signs the enrolment request and must carry the Certificate Request Agent
// application policy; the client credential authenticates the TLS connection
// to CES and must carry Client Authentication and map to an AD account. An
// enrollment agent certificate carries the first and not the second.
func newADCSBackend(opts options) (issuer.Issuer, error) {
	agentPair, err := tls.LoadX509KeyPair(opts.adcsAgentCert, opts.adcsAgentKey)
	if err != nil {
		return nil, fmt.Errorf("adcs enrollment agent credential: %w", err)
	}
	agentCert, err := x509.ParseCertificate(agentPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("adcs enrollment agent certificate: %w", err)
	}
	agentKey, ok := agentPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("adcs enrollment agent key of type %T cannot sign", agentPair.PrivateKey)
	}
	agent := &adcs.Agent{Certificate: agentCert, Key: agentKey}
	for _, der := range agentPair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("adcs enrollment agent chain: %w", err)
		}
		agent.Chain = append(agent.Chain, c)
	}

	clientPair, err := tls.LoadX509KeyPair(opts.adcsClientCert, opts.adcsClientKey)
	if err != nil {
		return nil, fmt.Errorf("adcs CES client credential: %w", err)
	}
	bundlePEM, err := os.ReadFile(opts.adcsCABundle)
	if err != nil {
		return nil, fmt.Errorf("adcs CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundlePEM) {
		return nil, fmt.Errorf("adcs CA bundle %s holds no certificates", opts.adcsCABundle)
	}

	return adcs.New(adcs.Config{
		CESURL:   opts.adcsCESURL,
		Template: opts.adcsTemplate,
		Agent:    agent,
		Client: &http.Client{
			Timeout: opts.adcsTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:   tls.VersionTLS12,
					Certificates: []tls.Certificate{clientPair},
					RootCAs:      roots,
				},
			},
		},
	})
}

func newLogger(format string) (*slog.Logger, error) {
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, nil)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q (want %q or %q)", format, "text", "json")
	}
}
