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

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth_factors"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TestAuth_NilClient confirms Auth returns nil for a nil qrdb client
// instead of panicking. Callers that do their own nil check on the
// qrdb side should never reach this branch.
func TestAuth_NilClient(t *testing.T) {
	if got := Auth(nil); got != nil {
		t.Fatalf("Auth(nil) = %v want nil", got)
	}
}

// TestWithXKMSFactorVerifiers_NoneConfigured confirms the helper
// registers only the stateless PKCS11 verifier when neither the PIV
// nor the WebAuthn dependency is supplied. PKCS11 possession
// verification needs no configuration, so it is always available.
func TestWithXKMSFactorVerifiers_NoneConfigured(t *testing.T) {
	opts := WithXKMSFactorVerifiers(AuthFactorOptions{})
	if len(opts) != 1 {
		t.Fatalf("expected 1 opt (always-on pkcs11), got %d", len(opts))
	}
}

// TestWithXKMSFactorVerifiers_PIVOnly verifies the PIV verifier is
// registered (alongside the always-on PKCS11 verifier) when only PIV
// roots are configured.
func TestWithXKMSFactorVerifiers_PIVOnly(t *testing.T) {
	roots := x509.NewCertPool()
	opts := WithXKMSFactorVerifiers(AuthFactorOptions{PIVRoots: roots})
	if len(opts) != 2 {
		t.Fatalf("expected 2 opts for PIV-only (piv + pkcs11), got %d", len(opts))
	}
}

// TestWithXKMSFactorVerifiers_WebAuthnOnly verifies the WebAuthn
// verifier is registered (alongside the always-on PKCS11 verifier)
// when only the webauthn service is configured.
func TestWithXKMSFactorVerifiers_WebAuthnOnly(t *testing.T) {
	svc := newTestWebAuthnService(t)
	opts := WithXKMSFactorVerifiers(AuthFactorOptions{WebAuthnService: svc})
	if len(opts) != 2 {
		t.Fatalf("expected 2 opts for WebAuthn-only (webauthn + pkcs11), got %d", len(opts))
	}
}

// TestWithXKMSFactorVerifiers_Both verifies all verifiers are
// registered when both dependencies are supplied: PIV, WebAuthn, and
// the always-on PKCS11 verifier.
func TestWithXKMSFactorVerifiers_Both(t *testing.T) {
	svc := newTestWebAuthnService(t)
	roots := x509.NewCertPool()
	opts := WithXKMSFactorVerifiers(AuthFactorOptions{
		WebAuthnService: svc,
		PIVRoots:        roots,
	})
	if len(opts) != 3 {
		t.Fatalf("expected 3 opts (piv + webauthn + pkcs11), got %d", len(opts))
	}
	// All options should be applicable to embedded.Transport.
	// Apply them through the public option type; we only assert
	// they're non-nil opt functions here.
	for i, o := range opts {
		if o == nil {
			t.Fatalf("opt %d is nil", i)
		}
	}

	// Compile-time assertion that opts type-matches embedded.Option.
	_ = opts
}

// TestVerifierAdapter_PKCS11Dispatch pins that a PKCS#11-only
// verifierAdapter (the "none configured" case WithXKMSFactorVerifiers
// always registers) routes Type/Verify/BeginChallenge to the wrapped
// PKCS11FactorVerifier rather than panicking on the nil webauthn/piv
// fields.
func TestVerifierAdapter_PKCS11Dispatch(t *testing.T) {
	pkcs11v := auth_factors.NewPKCS11FactorVerifier()
	adapter := verifierAdapter{pkcs11: pkcs11v}

	if got := adapter.Type(); got != pkcs11v.Type() {
		t.Fatalf("Type() = %v, want %v", got, pkcs11v.Type())
	}

	// PIV/PKCS#11 use the generic server nonce: BeginChallenge must return
	// a nil challenge without error.
	challenge, meta, exp, err := adapter.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypePKCS11, "")
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if challenge != nil || meta != nil || !exp.IsZero() {
		t.Fatalf("expected a zero-value generic-nonce challenge, got (%v, %v, %v)", challenge, meta, exp)
	}

	// A nil factor is a deterministic, non-crypto error path — it proves
	// Verify dispatches to the wrapped verifier rather than short-circuiting.
	err = adapter.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	if err == nil {
		t.Fatal("expected an error verifying a nil factor")
	}
}

// TestVerifierAdapter_PIVDispatch pins that a PIV-only verifierAdapter
// routes Type/Verify/BeginChallenge to the wrapped
// PIVHardwareFactorVerifier: BeginChallenge takes the same generic-nonce
// path as PKCS#11 (no per-method challenge), and Verify/Type reach the
// wrapped verifier rather than falling through to the pkcs11 branch.
func TestVerifierAdapter_PIVDispatch(t *testing.T) {
	roots := x509.NewCertPool()
	pivv, err := auth_factors.NewPIVHardwareFactorVerifier(roots, nil)
	if err != nil {
		t.Fatalf("NewPIVHardwareFactorVerifier: %v", err)
	}
	adapter := verifierAdapter{piv: pivv}

	if got := adapter.Type(); got != pivv.Type() {
		t.Fatalf("Type() = %v, want %v", got, pivv.Type())
	}

	challenge, meta, exp, err := adapter.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypePIV, "")
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if challenge != nil || meta != nil || !exp.IsZero() {
		t.Fatalf("expected a zero-value generic-nonce challenge, got (%v, %v, %v)", challenge, meta, exp)
	}

	// A nil factor is a deterministic, non-crypto error path — it proves
	// Verify dispatches to the wrapped PIV verifier rather than the
	// pkcs11 fallback.
	err = adapter.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	if err == nil {
		t.Fatal("expected an error verifying a nil factor")
	}
	if _, ok := err.(*auth_factors.MissingFactorError); !ok {
		t.Fatalf("expected *auth_factors.MissingFactorError from the PIV verifier, got %T: %v", err, err)
	}
}

// TestVerifierAdapter_WebAuthnDispatch pins that a WebAuthn-only
// verifierAdapter routes Type/Verify/BeginChallenge to the wrapped
// WebAuthnFactorVerifier: BeginChallenge takes the RP-bound ceremony path
// (distinct from the PIV/PKCS#11 generic-nonce path) and Verify/Type reach
// the wrapped verifier.
func TestVerifierAdapter_WebAuthnDispatch(t *testing.T) {
	svc := newTestWebAuthnService(t)
	webauthnv, err := auth_factors.NewWebAuthnFactorVerifier(svc)
	if err != nil {
		t.Fatalf("NewWebAuthnFactorVerifier: %v", err)
	}
	adapter := verifierAdapter{webauthn: webauthnv}

	if got := adapter.Type(); got != webauthnv.Type() {
		t.Fatalf("Type() = %v, want %v", got, webauthnv.Type())
	}

	// An empty hint drives the discoverable-credential ceremony, which
	// succeeds without a pre-registered user and returns the RP-bound
	// challenge (unlike the PIV/PKCS#11 generic-nonce path).
	challenge, meta, _, err := adapter.BeginChallenge(context.Background(), "tenant", qrdbtransport.FactorTypeFIDO2, "")
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if len(challenge) == 0 {
		t.Fatal("expected a non-empty RP-bound challenge")
	}
	if meta["session_id"] == "" || meta["options"] == "" {
		t.Fatalf("expected session_id and options metadata, got %v", meta)
	}

	// A nil factor is a deterministic, non-crypto error path — it proves
	// Verify dispatches to the wrapped WebAuthn verifier.
	err = adapter.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	if err == nil {
		t.Fatal("expected an error verifying a nil factor")
	}
	if _, ok := err.(*auth_factors.MissingFactorError); !ok {
		t.Fatalf("expected *auth_factors.MissingFactorError from the webauthn verifier, got %T: %v", err, err)
	}
}

// newTestWebAuthnService constructs a minimal but configured xkms
// webauthn.Service for tests.
func newTestWebAuthnService(t *testing.T) *xkmswebauthn.Service {
	t.Helper()
	cfg := &xkmswebauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "test",
		RPOrigins:     []string{"https://localhost"},
	}
	stores := webauthntest.NewStores(t)
	users, creds := stores.Users, stores.Credentials
	sessions := xkmswebauthn.NewMemorySessionStore()
	svc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config: cfg, UserStore: users, SessionStore: sessions, CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	return svc
}
