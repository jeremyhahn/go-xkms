// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// The TOFU TLS verifier (#139): first use captures and persists the leaf's
// SPKI pin, every later connection must present it. These tests drive
// VerifyConnection directly, as the SPKI tests do, so the decision table is
// exercised without a network.

func tofuState(cert *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

func TestNewTOFUTLSConfig_Shape(t *testing.T) {
	cfg, err := NewTOFUTLSConfig(context.Background(), truststrap.NewMemoryPinStore(), "bmc.example.com:443", nil)
	if err != nil {
		t.Fatalf("NewTOFUTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil || !cfg.SessionTicketsDisabled {
		t.Fatal("expected the custom-verifier shape: InsecureSkipVerify, VerifyConnection set, session tickets disabled")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
}

func TestNewTOFUTLSConfig_FirstUseCapturesThenPins(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	cert := newTestCert(t, "bmc.example.com")
	cfg, err := NewTOFUTLSConfig(context.Background(), store, "bmc.example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := cfg.VerifyConnection(tofuState(cert)); err != nil {
		t.Fatalf("first use must capture, got %v", err)
	}
	pin, err := store.Get(context.Background(), "bmc.example.com", 443)
	if err != nil {
		t.Fatalf("the captured pin must be persisted: %v", err)
	}
	if pin.SPKISHA256 != spkiSHA256Hex(cert) {
		t.Fatalf("persisted pin %s != leaf SPKI pin %s", pin.SPKISHA256, spkiSHA256Hex(cert))
	}
	if pin.Source != "tofu" || pin.CertFingerprint == "" || pin.FirstSeen.IsZero() {
		t.Fatalf("pin record must carry source, fingerprint and first-seen: %+v", pin)
	}

	if err := cfg.VerifyConnection(tofuState(cert)); err != nil {
		t.Fatalf("the same leaf must verify on the second connection, got %v", err)
	}

	other := newTestCert(t, "bmc.example.com")
	err = cfg.VerifyConnection(tofuState(other))
	var mismatch *TOFUPinMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("a different leaf must be refused with TOFUPinMismatchError, got %v", err)
	}
	if mismatch.Stored != spkiSHA256Hex(cert) || mismatch.Presented != spkiSHA256Hex(other) {
		t.Fatalf("mismatch must name both pins: %+v", mismatch)
	}
	if !errors.Is(err, spkipin.ErrSPKIPinMismatch) {
		t.Fatalf("the mismatch must unwrap to spkipin's error, got %v", err)
	}
	if got, _ := store.Get(context.Background(), "bmc.example.com", 443); got.SPKISHA256 != pin.SPKISHA256 {
		t.Fatal("a mismatch must not overwrite the stored pin")
	}
}

func TestNewTOFUTLSConfig_ConfirmSeesThePinAndCanRefuse(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	cert := newTestCert(t, "bmc.example.com")
	var seen *truststrap.Pin
	refuse := errors.New("operator declined")
	cfg, err := NewTOFUTLSConfig(context.Background(), store, "bmc.example.com:8443",
		func(_ context.Context, pin *truststrap.Pin) error { seen = pin; return refuse })
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.VerifyConnection(tofuState(cert))
	var rejected truststrap.TOFURejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("a refused confirmation must surface as TOFURejectedError, got %v", err)
	}
	if !errors.Is(err, refuse) {
		t.Fatalf("the confirm hook's own error must be reachable, got %v", err)
	}
	if seen == nil || seen.Host != "bmc.example.com" || seen.Port != 8443 || seen.SPKISHA256 != spkiSHA256Hex(cert) {
		t.Fatalf("confirm must see the pin it is asked about: %+v", seen)
	}
	if _, getErr := store.Get(context.Background(), "bmc.example.com", 8443); getErr == nil {
		t.Fatal("a refused pin must not be persisted")
	}
}

func TestNewTOFUTLSConfig_ConfirmAcceptsOnceOnly(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	cert := newTestCert(t, "bmc.example.com")
	calls := 0
	cfg, err := NewTOFUTLSConfig(context.Background(), store, "bmc.example.com:443",
		func(context.Context, *truststrap.Pin) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := cfg.VerifyConnection(tofuState(cert)); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("confirm must run on first use only, ran %d times", calls)
	}
}

// A store that fails for a reason other than "no pin" must never be read as
// first use: that would let a broken store hand every endpoint a fresh pin.
type failingPinStore struct {
	truststrap.PinStore
	getErr error
	putErr error
}

func (f *failingPinStore) Get(ctx context.Context, host string, port int) (*truststrap.Pin, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.PinStore.Get(ctx, host, port)
}

func (f *failingPinStore) Put(ctx context.Context, pin *truststrap.Pin) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.PinStore.Put(ctx, pin)
}

func TestNewTOFUTLSConfig_StoreFailureIsNotFirstUse(t *testing.T) {
	cert := newTestCert(t, "bmc.example.com")
	boom := errors.New("qrdb unavailable")

	cfg, err := NewTOFUTLSConfig(context.Background(),
		&failingPinStore{PinStore: truststrap.NewMemoryPinStore(), getErr: boom}, "bmc.example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.VerifyConnection(tofuState(cert))
	var storeErr *TOFUPinStoreError
	if !errors.As(err, &storeErr) || storeErr.Op != "get" || !errors.Is(err, boom) {
		t.Fatalf("a failing Get must be a typed store error naming the op and cause, got %v", err)
	}

	cfg, err = NewTOFUTLSConfig(context.Background(),
		&failingPinStore{PinStore: truststrap.NewMemoryPinStore(), putErr: boom}, "bmc.example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.VerifyConnection(tofuState(cert))
	if !errors.As(err, &storeErr) || storeErr.Op != "put" {
		t.Fatalf("a failing Put must refuse the first connection, got %v", err)
	}
}

func TestNewTOFUTLSConfig_RefusesBadInputs(t *testing.T) {
	if _, err := NewTOFUTLSConfig(context.Background(), nil, "bmc.example.com:443", nil); !errors.Is(err, ErrTOFUPinStoreRequired) {
		t.Fatalf("nil store: got %v", err)
	}
	for _, endpoint := range []string{"", "bmc.example.com", ":443", "bmc.example.com:0", "bmc.example.com:70000", "bmc.example.com:https"} {
		_, err := NewTOFUTLSConfig(context.Background(), truststrap.NewMemoryPinStore(), endpoint, nil)
		var epErr *TOFUEndpointError
		if !errors.As(err, &epErr) {
			t.Fatalf("endpoint %q: expected TOFUEndpointError, got %v", endpoint, err)
		}
	}
	cfg, err := NewTOFUTLSConfig(context.Background(), truststrap.NewMemoryPinStore(), "bmc.example.com:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, spkipin.ErrNoCertificates) {
		t.Fatalf("no certificates: got %v", err)
	}
}

// Two endpoints on one store keep separate pins.
func TestNewTOFUTLSConfig_PinsAreKeyedByEndpoint(t *testing.T) {
	store := truststrap.NewMemoryPinStore()
	a, b := newTestCert(t, "a.example.com"), newTestCert(t, "b.example.com")
	cfgA, _ := NewTOFUTLSConfig(context.Background(), store, "a.example.com:443", nil)
	cfgB, _ := NewTOFUTLSConfig(context.Background(), store, "b.example.com:443", nil)
	if err := cfgA.VerifyConnection(tofuState(a)); err != nil {
		t.Fatal(err)
	}
	if err := cfgB.VerifyConnection(tofuState(b)); err != nil {
		t.Fatalf("b's first use must not be judged by a's pin: %v", err)
	}
	if err := cfgA.VerifyConnection(tofuState(b)); err == nil {
		t.Fatal("a must refuse b's leaf")
	}
}
