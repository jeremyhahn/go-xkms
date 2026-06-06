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

package auth_factors

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// stubWebAuthnService satisfies the embedded webauthn.Service shape we
// need for construction. We only exercise the verifier paths that don't
// touch the underlying ceremony.
func newStubVerifier(t *testing.T) *WebAuthnFactorVerifier {
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
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	v, err := NewWebAuthnFactorVerifier(svc)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func TestWebAuthnFactorVerifier_NewNilService(t *testing.T) {
	if _, err := NewWebAuthnFactorVerifier(nil); err == nil {
		t.Fatalf("expected error for nil service")
	} else {
		var nse *NilServiceError
		if !errors.As(err, &nse) {
			t.Fatalf("expected *NilServiceError, got %T (%v)", err, err)
		}
	}
}

func TestWebAuthnFactorVerifier_Type(t *testing.T) {
	v := newStubVerifier(t)
	if got := v.Type(); got != qrdbtransport.FactorTypeFIDO2 {
		t.Fatalf("Type() = %q want %q", got, qrdbtransport.FactorTypeFIDO2)
	}
}

func TestWebAuthnFactorVerifier_NilFactor(t *testing.T) {
	v := newStubVerifier(t)
	err := v.Verify(context.Background(), nil, qrdbtransport.VerifyChallenge{})
	var mfe *MissingFactorError
	if !errors.As(err, &mfe) {
		t.Fatalf("expected *MissingFactorError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_RevokedFactor(t *testing.T) {
	v := newStubVerifier(t)
	now := time.Now().UTC()
	factor := &qrdbsdk.AuthFactor{
		ID:        "f1",
		UserID:    1,
		Type:      qrdbsdk.AuthFactorFIDO2,
		RevokedAt: &now,
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{})
	var fre *qrdbsdk.FactorRevokedError
	if !errors.As(err, &fre) {
		t.Fatalf("expected *FactorRevokedError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_WrongType(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:     "f1",
		UserID: 1,
		Type:   qrdbsdk.AuthFactorMTLS, // wrong type
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{})
	var ftue *qrdbsdk.FactorTypeUnsupportedError
	if !errors.As(err, &ftue) {
		t.Fatalf("expected *FactorTypeUnsupportedError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_MissingSessionID(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("credential-id"),
	}
	// No method metadata at all — the verifier surfaces a typed error.
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
	})
	var mme *MissingMethodMetadataError
	if !errors.As(err, &mme) {
		t.Fatalf("expected *MissingMethodMetadataError, got %T (%v)", err, err)
	}
}

func TestWebAuthnFactorVerifier_CredentialMismatch(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("real-credential-id"),
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id": "different-id",
			"session_id":    "abc",
		},
	})
	var cme *CredentialMismatchError
	if !errors.As(err, &cme) {
		t.Fatalf("expected *CredentialMismatchError, got %T (%v)", err, err)
	}
}

// TestWebAuthnFactorVerifier_VerifyRequiresAssertion confirms that the unified
// qrdb login path verifies the WebAuthn assertion: a challenge that carries a
// session id but NO assertion is rejected (the verifier no longer punts to the
// HTTP handler — it performs the verification itself via webauthn.Service).
func TestWebAuthnFactorVerifier_VerifyRequiresAssertion(t *testing.T) {
	v := newStubVerifier(t)
	factor := &qrdbsdk.AuthFactor{
		ID:         "f1",
		UserID:     1,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: []byte("cred"),
	}
	err := v.Verify(context.Background(), factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"credential_id": "cred",
			"session_id":    "abc",
		},
	})
	var mme *MissingMethodMetadataError
	if !errors.As(err, &mme) {
		t.Fatalf("expected *MissingMethodMetadataError, got %T (%v)", err, err)
	}
	if mme.Field != "assertion" {
		t.Fatalf("expected missing field %q, got %q", "assertion", mme.Field)
	}
}
