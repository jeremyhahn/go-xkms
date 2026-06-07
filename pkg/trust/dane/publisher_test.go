// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package dane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	truststrap "github.com/jeremyhahn/go-truststrap/pkg/dane"
)

// newTestCert builds a minimal self-signed certificate for record
// derivation tests.
func newTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kms.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
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

// TestBuildRecords_MapsTruststrapOutput verifies BuildRecords returns one
// Record per truststrap-generated TLSA record, field-for-field, with the
// default TTL applied — proving the mapping (not a reimplementation) is
// correct.
func TestBuildRecords_MapsTruststrapOutput(t *testing.T) {
	cert := newTestCert(t)
	const host = "kms.example.com"
	const port uint16 = 443

	want, err := truststrap.GenerateCommonTLSARecords(cert, host, port)
	if err != nil {
		t.Fatalf("truststrap generate: %v", err)
	}

	got, err := BuildRecords(cert, host, port)
	if err != nil {
		t.Fatalf("BuildRecords: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("record count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			t.Errorf("record %d Name = %q, want %q", i, got[i].Name, want[i].Name)
		}
		if got[i].Usage != want[i].Usage {
			t.Errorf("record %d Usage = %d, want %d", i, got[i].Usage, want[i].Usage)
		}
		if got[i].Selector != want[i].Selector {
			t.Errorf("record %d Selector = %d, want %d", i, got[i].Selector, want[i].Selector)
		}
		if got[i].MatchingType != want[i].MatchingType {
			t.Errorf("record %d MatchingType = %d, want %d", i, got[i].MatchingType, want[i].MatchingType)
		}
		if got[i].Data != want[i].HexData {
			t.Errorf("record %d Data = %q, want %q", i, got[i].Data, want[i].HexData)
		}
		if got[i].TTL != DefaultTTL {
			t.Errorf("record %d TTL = %d, want %d", i, got[i].TTL, DefaultTTL)
		}
	}
}

// TestBuildRecords_InvalidInput verifies BuildRecords surfaces the
// truststrap validation errors rather than panicking or silently
// returning empty output.
func TestBuildRecords_InvalidInput(t *testing.T) {
	cert := newTestCert(t)
	tests := []struct {
		name string
		cert *x509.Certificate
		host string
		port uint16
	}{
		{"nil cert", nil, "kms.example.com", 443},
		{"empty host", cert, "", 443},
		{"zero port", cert, "kms.example.com", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildRecords(tc.cert, tc.host, tc.port); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// fakePublisher records the last PublishDANE call for assertion.
type fakePublisher struct {
	records []Record
	err     error
}

func (f *fakePublisher) PublishDANE(_ context.Context, records []Record) error {
	f.records = records
	return f.err
}

// TestDANEPublisher_ReceivesRecords verifies a registered publisher is
// invoked with the records produced by BuildRecords — the contract the
// service layer relies on.
func TestDANEPublisher_ReceivesRecords(t *testing.T) {
	cert := newTestCert(t)
	records, err := BuildRecords(cert, "kms.example.com", 443)
	if err != nil {
		t.Fatalf("BuildRecords: %v", err)
	}

	pub := &fakePublisher{}
	var p DANEPublisher = pub
	if err := p.PublishDANE(context.Background(), records); err != nil {
		t.Fatalf("PublishDANE: %v", err)
	}
	if len(pub.records) != len(records) {
		t.Fatalf("publisher received %d records, want %d", len(pub.records), len(records))
	}
}

// TestErrNoDANEPublisher_Identity verifies the sentinel error is
// matchable through errors.Is after wrapping, which is how the service
// layer reports "not configured".
func TestErrNoDANEPublisher_Identity(t *testing.T) {
	wrapped := errors.Join(errors.New("trust.PublishDANE"), ErrNoDANEPublisher)
	if !errors.Is(wrapped, ErrNoDANEPublisher) {
		t.Fatal("expected wrapped error to match ErrNoDANEPublisher")
	}
}
