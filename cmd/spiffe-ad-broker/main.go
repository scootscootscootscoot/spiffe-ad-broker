// Command spiffe-ad-broker exchanges a workload's SPIFFE SVID for a
// certificate that Active Directory will accept for PKINIT.
//
// It authenticates the caller by its SVID over mutual TLS, resolves the target
// AD account from a local mapping snapshot, validates the caller's PKCS#10
// request, and asks the configured backend to issue. Neither backend can issue
// yet, so every well-formed request currently ends in a 501 — that refusal is
// the point of the path being real: authentication, mapping, and validation
// all run before it.
//
// Usage:
//
//	spiffe-ad-broker \
//	  -listen :8443 \
//	  -tls-cert /run/spire/svid.pem -tls-key /run/spire/svid.key \
//	  -trust-bundle /run/spire/bundle.pem \
//	  -mapping /etc/spiffe-ad-broker/mapping.json \
//	  -backend adcs
package main

import (
	"context"
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
	backend, err := newBackend(opts.backend)
	if err != nil {
		return err
	}

	b, err := broker.New(broker.Config{
		Registry:       registry,
		Backend:        backend,
		Logger:         log,
		MaxSnapshotAge: opts.maxAge,
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
	)
	// Said plainly rather than left for someone to discover from a 501: the
	// path in front of the backends is real, the backends are not.
	log.Warn("no issuance backend is implemented; every well-formed request will be refused with not_implemented",
		slog.String("backend", b.BackendName()))

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
	return opts, nil
}

func newBackend(name string) (issuer.Issuer, error) {
	switch name {
	case "adcs":
		return adcs.New(), nil
	case "subordinate":
		return subordinate.New(), nil
	default:
		return nil, fmt.Errorf("unknown backend %q (want %q or %q)", name, "adcs", "subordinate")
	}
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
