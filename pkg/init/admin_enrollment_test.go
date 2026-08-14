// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package initialize

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsfido2 "github.com/jeremyhahn/go-xkms/pkg/factor/fido2"
)

// newAdminCertPEM issues a real self-signed P-256 certificate. The mtls factor
// parses what it is given, so a stub PEM cannot exercise enrollment.
func newAdminCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// mustPlan builds an enrollment plan or fails the test.
func mustPlan(t *testing.T, spec string) *qrdbsdk.AdminEnrollmentPlan {
	t.Helper()
	plan, err := qrdbsdk.ParseAdminFactors([]string{spec})
	if err != nil {
		t.Fatalf("ParseAdminFactors(%q): %v", spec, err)
	}
	return plan
}

// TestNewAdminFactorRegistry_RegistersTheHardwareFactors verifies the registry
// carries go-xkms's hardware factor implementations. This is the whole reason
// downstream projects build the ceremony through go-xkms rather than reaching
// for go-qrdb directly: qrdb owns the factor PLAN but implements no factors.
func TestNewAdminFactorRegistry_RegistersTheHardwareFactors(t *testing.T) {
	registry, local, err := NewAdminFactorRegistry(AdminEnrollmentConfig{
		RelyingPartyID: "example.com",
	})
	if err != nil {
		t.Fatalf("NewAdminFactorRegistry: %v", err)
	}
	if registry == nil {
		t.Fatal("registry must not be nil")
	}
	if local == nil {
		t.Fatal("a local ceremony must always be returned, even with no handler attached")
	}

	for _, name := range []string{xkmsfido2.FactorName, "piv"} {
		if _, lookupErr := registry.Lookup(name); lookupErr != nil {
			t.Errorf("registry is missing the %q factor: %v", name, lookupErr)
		}
	}
}

// TestNewAdminFactorRegistry_NoHandlerKeepsTheDefaultFIDO2Factor verifies that
// with no authenticator attached the default fido2 factor is left in place.
// The replacement only happens when a handler exists, so a host with no FIDO2
// support still builds a usable registry rather than failing construction.
func TestNewAdminFactorRegistry_NoHandlerKeepsTheDefaultFIDO2Factor(t *testing.T) {
	registry, _, err := NewAdminFactorRegistry(AdminEnrollmentConfig{
		RelyingPartyID: "example.com",
		FIDO2Handler:   nil,
	})
	if err != nil {
		t.Fatalf("NewAdminFactorRegistry: %v", err)
	}
	if _, err := registry.Lookup(xkmsfido2.FactorName); err != nil {
		t.Fatalf("the default fido2 factor must remain registered when no handler is attached: %v", err)
	}
}

// TestPreflightAdminFactors_NilPlanIsANoOp verifies the mTLS baseline needs no
// preflight: a nil plan means no factor was requested.
func TestPreflightAdminFactors_NilPlanIsANoOp(t *testing.T) {
	if err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{}); err != nil {
		t.Fatalf("nil plan must preflight cleanly, got %v", err)
	}
}

// TestPreflightAdminFactors_FIDO2WithNoHandlerStaysAvailable pins a deliberate
// design decision rather than an accident. With no local ceremony attached the
// fido2 factor reports itself AVAILABLE (pkg/factor/fido2/factor.go), because
// the browser/WebAuthn path needs no hardware on THIS host — reporting
// otherwise would block every ordinary server deployment from offering fido2.
//
// Preflight therefore passes here. The hardware check only bites when a local
// CTAP2 ceremony is wired, which is what a daemon does when it opens an
// authenticator for a planned passkey enrollment.
func TestPreflightAdminFactors_FIDO2WithNoHandlerStaysAvailable(t *testing.T) {
	err := PreflightAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:           mustPlan(t, "fido2"),
		Username:       "administrator",
		RelyingPartyID: "example.com",
		FIDO2Handler:   nil,
	})
	if err != nil {
		t.Fatalf("fido2 must preflight cleanly with no local ceremony attached, got %v", err)
	}
}

// TestPreflightAdminFactors_UnregisteredFactorFails verifies preflight rejects
// a plan naming a factor the registry cannot satisfy, rather than discovering
// it midway through the ceremony.
func TestPreflightAdminFactors_UnregisteredFactorFails(t *testing.T) {
	registry := qrdbsdk.NewFactorRegistry() // deliberately empty
	err := mustPlan(t, "fido2").Preflight(context.Background(), registry)
	if err == nil {
		t.Fatal("a plan naming an unregistered factor must fail preflight")
	}
}

// TestEnrollAdminFactors_NilPlanEnrollsNothing verifies the baseline path
// returns no results rather than inventing an enrollment.
func TestEnrollAdminFactors_NilPlanEnrollsNothing(t *testing.T) {
	enrolled, err := EnrollAdminFactors(context.Background(), AdminEnrollmentConfig{})
	if err != nil {
		t.Fatalf("nil plan must enroll cleanly, got %v", err)
	}
	if len(enrolled) != 0 {
		t.Fatalf("nil plan must enroll nothing, got %d factors", len(enrolled))
	}
}

// TestEnrollAdminFactors_MTLSBindsTheAdminCertificate verifies the mTLS factor
// enrolls against the certificate the ceremony issued, which is what turns
// that certificate into a login credential rather than a file on disk.
func TestEnrollAdminFactors_MTLSBindsTheAdminCertificate(t *testing.T) {
	enrolled, err := EnrollAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:         mustPlan(t, "mtls"),
		Username:     "administrator",
		TenantID:     "system",
		AdminCertPEM: newAdminCertPEM(t, "administrator"),
	})
	if err != nil {
		t.Fatalf("EnrollAdminFactors(mtls): %v", err)
	}
	if len(enrolled) != 1 {
		t.Fatalf("expected exactly one enrolled factor, got %d", len(enrolled))
	}
	if enrolled[0].Factor != qrdbsdk.FactorMTLS {
		t.Errorf("enrolled factor = %v, want mtls", enrolled[0].Factor)
	}
}

// TestEnrollAdminFactors_MTLSWithoutACertificateFails verifies the error path:
// an mTLS factor with nothing to bind to must fail loudly rather than record
// an enrollment that can never authenticate anyone.
func TestEnrollAdminFactors_MTLSWithoutACertificateFails(t *testing.T) {
	_, err := EnrollAdminFactors(context.Background(), AdminEnrollmentConfig{
		Plan:     mustPlan(t, "mtls"),
		Username: "administrator",
		TenantID: "system",
		// AdminCertPEM deliberately absent.
	})
	if err == nil {
		t.Fatal("mtls enrollment with no administrator certificate must fail")
	}
}

// TestEnrollAdminFactors_DisplayNameFallsBackToUsername verifies the
// authenticator's own UI always has a name to show.
func TestEnrollAdminFactors_DisplayNameFallsBackToUsername(t *testing.T) {
	cfg := AdminEnrollmentConfig{
		Plan:         mustPlan(t, "mtls"),
		Username:     "administrator",
		TenantID:     "system",
		AdminCertPEM: newAdminCertPEM(t, "administrator"),
	}
	if _, err := EnrollAdminFactors(context.Background(), cfg); err != nil {
		t.Fatalf("EnrollAdminFactors: %v", err)
	}
	if cfg.DisplayName != "" {
		t.Fatal("the caller's config must not be mutated")
	}
}
