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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// =============================================================================
// Test fixtures
// =============================================================================

// newTestPEMBundle builds a minimal RSA root + ECDSA intermediate PEM bundle
// suitable for httptest-served fixtures. Both bundle structure (multi-cert
// PEM) and parseability are guaranteed.
func newTestPEMBundle(t *testing.T) []byte {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "xkms-test-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &ecKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})
	out := make([]byte, 0, len(rootPEM)+len(intPEM))
	out = append(out, rootPEM...)
	out = append(out, intPEM...)
	return out
}

// discardLogger returns an slog logger that throws away all output, keeping
// test output clean while still exercising logger-handling branches inside
// the bootstrappers.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// fetchDirect — success + invoke + toCABundle
// =============================================================================

func TestFetch_DirectSuccess(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != truststrap.DefaultDirectBundlePath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), Config{
		Mode:             ModeDirect,
		ServerURL:        srv.URL,
		Direct:           &DirectConfig{},
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
	})
	if err != nil {
		t.Fatalf("Fetch direct: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil CABundle")
	}
	if len(got.PEM) == 0 {
		t.Fatal("CABundle.PEM is empty")
	}
	if len(got.Certificates) != 2 {
		t.Fatalf("Certificates count = %d, want 2", len(got.Certificates))
	}
	if got.ContentType != "application/pem-certificate-chain" {
		t.Fatalf("ContentType = %q", got.ContentType)
	}
}

func TestFetch_DirectFetchFailureWrapsAsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDirect,
		ServerURL: srv.URL,
		Direct:    &DirectConfig{},
		Logger:    discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FetchError, got %T", err)
	}
	if fe.Mode != ModeDirect {
		t.Fatalf("FetchError.Mode = %q, want %q", fe.Mode, ModeDirect)
	}
	if fe.Cause == nil {
		t.Fatal("FetchError.Cause is nil")
	}
}

// =============================================================================
// fetchSPKI — constructor error + success
// =============================================================================

func TestFetch_SPKIConstructorErrorWrapsAsFetchError(t *testing.T) {
	// "abc" is not a 64-char hex string → spkipin.NewPinnedTLSConfig rejects
	// it → truststrap.NewSPKIBootstrapper returns an error → wrapper wraps as
	// FetchError{Mode: ModeSPKI}.
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeSPKI,
		ServerURL: "https://kms.example.com:8443",
		SPKI:      &SPKIConfig{Pin: "abc"},
		Logger:    discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Mode != ModeSPKI {
		t.Fatalf("expected FetchError{Mode:spki}, got %v", err)
	}
}

func TestFetch_SPKISuccess(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	serverCert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(serverCert)

	got, err := Fetch(context.Background(), Config{
		Mode:             ModeSPKI,
		ServerURL:        srv.URL,
		SPKI:             &SPKIConfig{Pin: pin},
		BundlePath:       "/", // httptest server accepts any path
		PerMethodTimeout: 5 * time.Second,
		Logger:           discardLogger(),
	})
	if err != nil {
		t.Fatalf("Fetch spki: %v", err)
	}
	if got == nil || len(got.Certificates) != 2 {
		t.Fatalf("unexpected bundle: %+v", got)
	}
}

func TestFetch_SPKIFetchFailureFromPinMismatch(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	wrongPin := strings.Repeat("00", 32) // valid hex, but mismatches the server cert
	_, err := Fetch(context.Background(), Config{
		Mode:             ModeSPKI,
		ServerURL:        srv.URL,
		SPKI:             &SPKIConfig{Pin: wrongPin},
		BundlePath:       "/",
		PerMethodTimeout: 2 * time.Second,
		Logger:           discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
}

// =============================================================================
// fetchDANE — constructor error path
// =============================================================================

func TestFetch_DANEConstructorErrorWrapsAsFetchError(t *testing.T) {
	// Port "not-a-number" inside the URL causes truststrap.NewDANEBootstrapper
	// to fail parsing.
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDANE,
		ServerURL: "https://kms.example.com:not-a-number",
		DANE:      &DANEConfig{Hostname: ""},
		Logger:    discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Mode != ModeDANE {
		t.Fatalf("expected FetchError{Mode:dane}, got %v", err)
	}
}

func TestFetch_DANEFetchFailureWithoutResolver(t *testing.T) {
	// With a valid URL but no DNSServer set, the constructed bootstrapper has
	// no resolver and FetchCABundle fails immediately with ErrDNSLookupFailed.
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDANE,
		ServerURL: "https://kms.example.com:8443",
		DANE:      &DANEConfig{Hostname: "kms.example.com"}, // no DNSServer
		Logger:    discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
}

// =============================================================================
// fetchNoise — constructor error path
// =============================================================================

func TestFetch_NoiseInvalidKeyConstructorError(t *testing.T) {
	// Non-hex key → NewNoiseBootstrapper rejects → wrapper wraps as FetchError.
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeNoise,
		ServerURL: "https://kms.example.com:8443",
		Noise:     &NoiseConfig{ServerStaticKey: "not-hex-key"},
		Logger:    discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Mode != ModeNoise {
		t.Fatalf("expected FetchError{Mode:noise}, got %v", err)
	}
}

func TestFetch_NoiseUsesExplicitServerAddr(t *testing.T) {
	// Valid 64-hex key but no listener at 127.0.0.1:1 → FetchCABundle dial
	// fails with ErrFetchFailed. This exercises the "addr != \"\"" branch in
	// fetchNoise that takes the explicit address instead of deriving from URL.
	validHexKey := strings.Repeat("ab", 32)
	_, err := Fetch(context.Background(), Config{
		Mode: ModeNoise,
		Noise: &NoiseConfig{
			ServerAddr:      "127.0.0.1:1",
			ServerStaticKey: validHexKey,
		},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
}

// =============================================================================
// fetchAuto — success path + sub-config branch coverage
// =============================================================================

func TestFetch_AutoFallsThroughToDirect(t *testing.T) {
	bundle := newTestPEMBundle(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bundle)
	}))
	defer srv.Close()

	// Configure every mode. Only Direct can actually succeed (HTTP-only
	// httptest, no TLS pin, no resolver, no Noise key). truststrap.AutoFetch
	// must walk the order and land on Direct. This drives every if-branch
	// inside fetchAuto.
	got, err := Fetch(context.Background(), Config{
		Mode:      ModeAuto,
		ServerURL: srv.URL,
		DANE:      &DANEConfig{Hostname: "kms.example.com"},
		Noise:     &NoiseConfig{ServerStaticKey: strings.Repeat("ab", 32), ServerAddr: "127.0.0.1:1"},
		SPKI:      &SPKIConfig{Pin: strings.Repeat("00", 32)},
		Direct:    &DirectConfig{},
		// Short per-method timeout so DANE/Noise/SPKI fail fast before
		// Direct succeeds.
		PerMethodTimeout: 500 * time.Millisecond,
		Logger:           discardLogger(),
	})
	if err != nil {
		t.Fatalf("Fetch auto: %v", err)
	}
	if got == nil || len(got.Certificates) != 2 {
		t.Fatalf("unexpected bundle: %+v", got)
	}
}

func TestFetch_AutoAllMethodsFailWrapsAsFetchError(t *testing.T) {
	// All sub-configs present, but pointed at an unreachable endpoint. Every
	// method fails → truststrap returns an AggregateError → wrapper wraps as
	// FetchError{Mode:auto}.
	_, err := Fetch(context.Background(), Config{
		Mode: ModeAuto,
		// Use a port nothing listens on; both DANE (HTTPS) and Direct
		// (HTTP) will fail to connect.
		ServerURL:        "http://127.0.0.1:1",
		Direct:           &DirectConfig{},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Mode != ModeAuto {
		t.Fatalf("expected FetchError{Mode:auto}, got %v", err)
	}
}

func TestFetch_AutoDeriveNoiseAddrFromServerURL(t *testing.T) {
	// Noise sub-config without explicit ServerAddr forces fetchAuto's
	// DeriveNoiseAddr branch. The test only needs to reach the truststrap
	// call; the connection itself will fail.
	_, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        "http://127.0.0.1:1",
		Noise:            &NoiseConfig{ServerStaticKey: strings.Repeat("ab", 32)}, // no ServerAddr
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("expected ErrFetch, got %v", err)
	}
}

// =============================================================================
// FetchError — unwrap chain hits underlying truststrap sentinel
// =============================================================================

func TestFetch_FetchErrorUnwrapsToTruststrapSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDirect,
		ServerURL: srv.URL,
		Direct:    &DirectConfig{},
		Logger:    discardLogger(),
	})
	if !errors.Is(err, truststrap.ErrDirectFetchFailed) {
		t.Fatalf("expected unwrap to truststrap.ErrDirectFetchFailed, got %v", err)
	}
}

// =============================================================================
// toCABundle — non-nil response coverage
// =============================================================================

func TestToCABundle_CopiesAllFields(t *testing.T) {
	resp := &truststrap.CABundleResponse{
		BundlePEM:    []byte("PEM"),
		Certificates: [][]byte{[]byte("DER1"), []byte("DER2")},
		ContentType:  "application/test",
	}
	got := toCABundle(resp)
	if got == nil {
		t.Fatal("toCABundle returned nil for non-nil response")
	}
	if string(got.PEM) != "PEM" {
		t.Fatalf("PEM = %q, want %q", got.PEM, "PEM")
	}
	if len(got.Certificates) != 2 {
		t.Fatalf("Certificates count = %d, want 2", len(got.Certificates))
	}
	if got.ContentType != "application/test" {
		t.Fatalf("ContentType = %q, want %q", got.ContentType, "application/test")
	}
}

// =============================================================================
// FetchError.Error formatting — both branches (with and without cause)
// =============================================================================

func TestFetchError_ErrorWithoutCause(t *testing.T) {
	e := &FetchError{Mode: ModeDirect}
	got := e.Error()
	if !strings.Contains(got, "direct") {
		t.Fatalf("expected mode in error string, got %q", got)
	}
	if strings.Contains(got, ":") && strings.Count(got, ":") > 1 {
		// "trust bootstrap: direct fetch failed" → exactly one colon.
		t.Fatalf("error message has unexpected cause suffix: %q", got)
	}
}

func TestFetchError_ErrorWithCause(t *testing.T) {
	e := &FetchError{Mode: ModeNoise, Cause: errors.New("dial failed")}
	got := e.Error()
	if !strings.Contains(got, "dial failed") {
		t.Fatalf("expected cause in error string, got %q", got)
	}
}
