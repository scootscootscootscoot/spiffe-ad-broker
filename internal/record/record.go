// Package record keeps a durable account of the credentials this broker
// caused to exist.
//
// Everything the broker does is logged, but a log is not an account. Logs get
// rotated, sampled, shipped to somewhere with its own retention, and — in the
// shape this service will actually be deployed in — are gone with the
// container. What has to survive is narrower and harder: the list of
// certificates that exist in Active Directory because a workload asked this
// broker for one.
//
// Two things need it.
//
//   - Revocation. Removing a mapping entry stops future issuance and does
//     nothing whatever to a credential already issued. To revoke one, the
//     issuer and serial have to be known, and the CA is not a searchable
//     index of "things this broker asked for".
//
//   - Audit. A certificate carrying an AD SID authenticates as that account.
//     "Which workload obtained the credential that logged in as this account
//     on Tuesday" has to be answerable from something that outlived Tuesday.
//
// # Only issuances, deliberately
//
// Refusals are not recorded here. They are logged, once, where they are
// raised, which is the right place for them — and writing them to a durable
// file would turn a refused flood into disk exhaustion, converting a bounded
// failure into an outage. The record answers "what exists", and a refusal
// created nothing.
//
// # Format
//
// One JSON object per line, appended, fsynced before Record returns. JSON
// lines rather than a database because the file has one writer, is only ever
// appended to, and is read by whatever an operator has to hand at three in
// the morning.
//
// A reader should skip a malformed final line rather than fail: the process
// can be killed between the write and the next one, and a truncated tail is
// the expected worst case.
package record

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// An Issuance is one credential that now exists because of this broker.
//
// The fields are chosen to answer the two questions above without needing
// anything else: Issuer and Serial identify the certificate to the CA that
// would revoke it, ADSID and ADAccount say what it authenticates as, and
// Caller says who obtained it.
type Issuance struct {
	Time            time.Time `json:"time"`
	Caller          string    `json:"caller"`
	Backend         string    `json:"backend"`
	SnapshotVersion string    `json:"snapshot_version"`
	ADSID           string    `json:"ad_sid"`
	ADAccount       string    `json:"ad_account,omitempty"`

	// Serial is the decimal serial number, matching how the certificate is
	// logged. Issuer is the leaf's issuer DN. Together they are the CA's own
	// identifier for the certificate and what a revocation call needs.
	Serial string `json:"serial"`
	Issuer string `json:"issuer"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	// Fingerprint is the SHA-256 of the leaf's DER, lowercase hex. It is what
	// matches this row against a certificate someone is holding, without
	// trusting that two CAs never reuse a serial.
	Fingerprint string `json:"fingerprint"`
}

// FromCertificate fills in the certificate-derived fields of an Issuance.
func FromCertificate(cert *x509.Certificate) Issuance {
	sum := sha256.Sum256(cert.Raw)
	return Issuance{
		Serial:      cert.SerialNumber.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

// A Recorder durably records an issuance.
//
// Record returning an error is not advisory. The broker refuses to hand over
// a credential it could not record, because an unrecorded credential is one
// nobody can revoke.
type Recorder interface {
	Record(ctx context.Context, iss Issuance) error
	Close() error
}

// File is a Recorder appending to a file on disk.
type File struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// Open opens or creates the record file for appending.
//
// The file is opened, and a zero-length write is not attempted, at startup
// rather than at first issuance: a broker that cannot write its record must
// fail to start, not discover it while refusing a caller that did nothing
// wrong.
//
// Mode is 0600. The file names AD accounts and the workloads mapped to them,
// which is a map of what to attack.
func Open(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("record: no path")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record: open %s: %w", path, err)
	}
	return &File{f: f, path: path}, nil
}

// Path is the file being written, for startup logging.
func (r *File) Path() string { return r.path }

// Record appends iss and does not return until it is on disk.
//
// The fsync is the point of the type. Without it the record is in the page
// cache and a power loss takes exactly the credentials issued closest to the
// event — the ones most likely to still be valid.
func (r *File) Record(_ context.Context, iss Issuance) error {
	if iss.Time.IsZero() {
		iss.Time = time.Now()
	}
	line, err := json.Marshal(iss)
	if err != nil {
		return fmt.Errorf("record: encode: %w", err)
	}
	line = append(line, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()

	// One Write of the whole line, so an interrupted process can only ever
	// truncate the tail rather than interleave two rows.
	if _, err := r.f.Write(line); err != nil {
		return fmt.Errorf("record: append to %s: %w", r.path, err)
	}
	if err := r.f.Sync(); err != nil {
		return fmt.Errorf("record: sync %s: %w", r.path, err)
	}
	return nil
}

// Close closes the underlying file.
func (r *File) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Discard is a Recorder that keeps nothing.
//
// It exists for tests and for backends that cannot issue, so that the broker
// never has to hold a nil Recorder and branch on it. It is not a deployment
// option: a configuration that can issue is required to configure a File.
type Discard struct{}

func (Discard) Record(context.Context, Issuance) error { return nil }
func (Discard) Close() error                           { return nil }
