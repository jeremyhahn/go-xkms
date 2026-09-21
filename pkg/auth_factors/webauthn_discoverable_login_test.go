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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// newEC2Credential returns a virtualwebauthn EC2 credential whose P-256
// public key has full-length (32-byte) X and Y coordinates. Mirrors
// pkg/webauthn's helper of the same purpose: virtualwebauthn strips leading
// zero bytes from coordinates (~1/128 of random keys), which the go-webauthn
// COSE parser correctly rejects, so tests regenerate until both coordinates
// are full-length rather than tolerate a flaky failure.
func newEC2Credential(t *testing.T) virtualwebauthn.Credential {
	t.Helper()
	for i := 0; i < 128; i++ {
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		parsed, err := x509.ParsePKCS8PrivateKey(cred.Key.Data)
		if err != nil {
			t.Fatalf("parse EC2 credential key: %v", err)
		}
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
		}
		size := (priv.Curve.Params().BitSize + 7) / 8 // 32 bytes for P-256
		if len(priv.X.Bytes()) == size && len(priv.Y.Bytes()) == size {
			return cred
		}
	}
	t.Fatal("could not generate EC2 credential with full-length coordinates")
	return virtualwebauthn.Credential{}
}

// TestWebAuthnFactorVerifier_DiscoverableLogin_BeginToVerify_Succeeds is the
// full-seam regression for go-xkms#558. It drives the exact production pair
// the issue traced: WebAuthnFactorVerifier.BeginChallenge (an empty hint, the
// discoverable/usernameless ceremony) followed by WebAuthnFactorVerifier.
// Verify, which re-derives a user handle from the resolved qrdb factor before
// calling xkms's Service.FinishLogin — the step that used to route a
// discoverable session into the user-identified branch and fail with "ID
// mismatch for User and Session" on every usernameless login.
//
// A test that fakes the qrdb transport client (as the unit tests in
// webauthn_test.go and auth_factors_extra_test.go do) never reaches Verify's
// assertion-parsing step, so it cannot see this failure; this test drives
// real xkms webauthn.Service stores and a real virtualwebauthn assertion
// through both adapter methods, entirely in memory.
func TestWebAuthnFactorVerifier_DiscoverableLogin_BeginToVerify_Succeeds(t *testing.T) {
	ctx := context.Background()

	allowPublicRegistration := true
	cfg := &xkmswebauthn.Config{
		RPID:                    "localhost",
		RPDisplayName:           "test",
		RPOrigins:               []string{"https://localhost"},
		ResidentKeyRequirement:  "preferred",
		AllowPublicRegistration: &allowPublicRegistration,
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

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// === Enroll the user's credential directly against the RP service, the
	// same way BeginRegistration/FinishRegistration do outside the qrdb
	// ceremony (registration is not part of this seam). ===
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "passkey@example.com", "Passkey User")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	if err != nil {
		t.Fatalf("marshal registration options: %v", err)
	}
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	var ccr protocol.CredentialCreationResponse
	if uErr := json.Unmarshal([]byte(attestationResponse), &ccr); uErr != nil {
		t.Fatalf("unmarshal attestation response: %v", uErr)
	}
	parsedAttResponse, err := ccr.Parse()
	if err != nil {
		t.Fatalf("parse attestation response: %v", err)
	}
	_, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	authenticator.AddCredential(credential)

	credentials, err := svc.GetCredentials(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("expected 1 enrolled credential, got %d", len(credentials))
	}

	// The qrdb-side factor that would have been persisted by FactorClient.
	// Enroll: its UserID round-trips through xkmswebauthn.HandleFromUserID
	// to the same handle the WebAuthn user was registered with, exactly as
	// production factor resolution does.
	qrdbUserID, err := xkmswebauthn.UserIDFromHandle(user.WebAuthnID())
	if err != nil {
		t.Fatalf("UserIDFromHandle: %v", err)
	}
	factor := &qrdbsdk.AuthFactor{
		ID:         "f-passkey",
		UserID:     qrdbUserID,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: credentials[0].ID,
	}

	// === BeginChallenge with an empty hint: the discoverable/usernameless
	// ceremony a caller drives when it has no username to key a lookup on. ===
	_, meta, _, err := v.BeginChallenge(ctx, "system", qrdbtransport.FactorTypeFIDO2, "")
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	sessionID := meta["session_id"]
	if sessionID == "" {
		t.Fatal("BeginChallenge did not return a session_id")
	}

	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(meta["options"])
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}

	// The authenticator reports the user handle in the assertion, as a real
	// passkey does for a client-side discoverable credential.
	discoverableAuth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: user.WebAuthnID(),
	})
	discoverableAuth.AddCredential(credential)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, discoverableAuth, credential, *parsedLoginOptions)

	// === Verify: resolves the factor to a non-empty user handle (factor.
	// UserID != 0) and drives FinishLogin with it, exactly as production
	// does once qrdb has matched the credential id to an enrolled factor. ===
	challenge := qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"session_id":    sessionID,
			"assertion":     assertionResponse,
			"credential_id": string(credentials[0].ID),
		},
	}
	if vErr := v.Verify(ctx, factor, challenge); vErr != nil {
		t.Fatalf("Verify (discoverable login, begin-to-finish): %v", vErr)
	}
}
