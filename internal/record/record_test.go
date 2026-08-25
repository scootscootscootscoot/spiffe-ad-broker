package record

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "pkinittest"},
		Issuer:       pkix.Name{CommonName: "Lab Issuing CA"},
		NotBefore:    time.Now().Add(-time.Minute).Truncate(time.Second),
		NotAfter:     time.Now().Add(time.Hour).Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func readRows(t *testing.T, path string) []Issuance {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var rows []Issuance
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var iss Issuance
		if err := json.Unmarshal([]byte(line), &iss); err != nil {
			t.Fatalf("record line is not JSON: %q: %v", line, err)
		}
		rows = append(rows, iss)
	}
	return rows
}

// The fields have to come off the certificate itself, because they are what a
// revocation call needs and the CA is not a searchable index of what this
// broker asked for.
func TestFromCertificateCarriesWhatRevocationNeeds(t *testing.T) {
	cert := testCert(t, 0x5eadbeef)
	iss := FromCertificate(cert)

	if iss.Serial != cert.SerialNumber.String() {
		t.Errorf("Serial = %q, want %q", iss.Serial, cert.SerialNumber.String())
	}
	if iss.Issuer != cert.Issuer.String() {
		t.Errorf("Issuer = %q, want %q", iss.Issuer, cert.Issuer.String())
	}
	sum := sha256.Sum256(cert.Raw)
	if want := hex.EncodeToString(sum[:]); iss.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", iss.Fingerprint, want)
	}
	if !iss.NotBefore.Equal(cert.NotBefore) || !iss.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("validity window = %v..%v, want %v..%v",
			iss.NotBefore, iss.NotAfter, cert.NotBefore, cert.NotAfter)
	}
}

func TestRecordAppendsOneLinePerIssuance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	for i := range 3 {
		iss := FromCertificate(testCert(t, int64(i+1)))
		iss.Caller = fmt.Sprintf("spiffe://example.org/workload/%d", i)
		iss.ADSID = "S-1-5-21-3734714977-4168152908-3762407930-1103"
		iss.ADAccount = `PKINITLAB\pkinittest`
		iss.Backend = "adcs"
		if err := r.Record(context.Background(), iss); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	rows := readRows(t, path)
	if len(rows) != 3 {
		t.Fatalf("recorded %d rows, want 3", len(rows))
	}
	for i, row := range rows {
		if row.Serial != big.NewInt(int64(i+1)).String() {
			t.Errorf("row %d serial = %q, want %d", i, row.Serial, i+1)
		}
		if row.ADAccount != `PKINITLAB\pkinittest` {
			t.Errorf("row %d lost the account name: %q", i, row.ADAccount)
		}
		if row.Time.IsZero() {
			t.Errorf("row %d has no timestamp", i)
		}
	}
}

// The record's whole value is that it outlives the process, so re-opening must
// continue the file rather than start it again.
func TestReopenAppendsRatherThanTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")

	for i := range 2 {
		r, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := r.Record(context.Background(), FromCertificate(testCert(t, int64(i+1)))); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	if rows := readRows(t, path); len(rows) != 2 {
		t.Fatalf("recorded %d rows across two processes, want 2", len(rows))
	}
}

// The file names AD accounts and the workloads mapped to them, which is a map
// of what to attack.
func TestRecordFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}
}

// Opening happens at startup precisely so this is a startup failure and not a
// refusal handed to a caller that did nothing wrong.
func TestOpenFailsOnAnUnwritablePath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "issued.jsonl")); err == nil {
		t.Fatal("Open accepted a path it cannot write")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("Open accepted an empty path")
	}
}

// A failed write has to be reported, not swallowed: the broker refuses to hand
// over a credential it could not record, and that decision depends on this
// error arriving.
func TestRecordReportsAWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Record(context.Background(), FromCertificate(testCert(t, 1))); err == nil {
		t.Fatal("Record reported success after the file was closed")
	}
}

func TestRecordFillsTheTimestampWhenUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	before := time.Now().Add(-time.Second)
	if err := r.Record(context.Background(), Issuance{Caller: "spiffe://example.org/w"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rows := readRows(t, path)
	if len(rows) != 1 || rows[0].Time.Before(before) {
		t.Fatalf("Record did not stamp the row: %+v", rows)
	}
}

// One Write per row, under a mutex: concurrent issuances must not interleave
// into a line nothing can parse. Run with -race, which is what CI does.
func TestConcurrentRecordsDoNotInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issued.jsonl")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { r.Close() })

	const n = 40
	cert := testCert(t, 7)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			iss := FromCertificate(cert)
			iss.Caller = fmt.Sprintf("spiffe://example.org/workload/%02d", i)
			if err := r.Record(context.Background(), iss); err != nil {
				t.Errorf("Record: %v", err)
			}
		}()
	}
	wg.Wait()

	rows := readRows(t, path)
	if len(rows) != n {
		t.Fatalf("recorded %d rows, want %d", len(rows), n)
	}
	seen := make(map[string]bool, n)
	for _, row := range rows {
		seen[row.Caller] = true
	}
	if len(seen) != n {
		t.Fatalf("%d distinct callers survived, want %d — rows were lost or merged", len(seen), n)
	}
}

func TestDiscardKeepsNothingAndSucceeds(t *testing.T) {
	var d Discard
	if err := d.Record(context.Background(), Issuance{}); err != nil {
		t.Fatalf("Discard.Record: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Discard.Close: %v", err)
	}
}
