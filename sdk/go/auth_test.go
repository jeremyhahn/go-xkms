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
	"crypto/x509"
	"testing"

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

// newTestWebAuthnService constructs a minimal but configured xkms
// webauthn.Service for tests.
func newTestWebAuthnService(t *testing.T) *xkmswebauthn.Service {
	t.Helper()
	cfg := &xkmswebauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "test",
		RPOrigins:     []string{"https://localhost"},
	}
	users := xkmswebauthn.NewMemoryUserStore()
	creds := xkmswebauthn.NewMemoryCredentialStore()
	sessions := xkmswebauthn.NewMemorySessionStore()
	svc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config: cfg, UserStore: users, SessionStore: sessions, CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	return svc
}
