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
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
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

// factorFixture is a WebAuthnFactorVerifier over real in-memory xkms
// webauthn stores holding one account with an enrolled passkey, plus the
// qrdb-side factor record that names it.
type factorFixture struct {
	v          *WebAuthnFactorVerifier
	rp         virtualwebauthn.RelyingParty
	credential virtualwebauthn.Credential
	user       xkmswebauthn.User
	factor     *qrdbsdk.AuthFactor
	stores     *webauthntest.Stores
}

// newFactorFixture enrols email's passkey directly against the RP service,
// the same way BeginRegistration/FinishRegistration do outside the qrdb
// ceremony (registration is not part of the factor seam).
func newFactorFixture(t *testing.T, email string) *factorFixture {
	t.Helper()
	ctx := context.Background()

	allowPublicRegistration := true
	cfg := &xkmswebauthn.Config{
		RPID:                    "localhost",
		RPDisplayName:           "test",
		RPOrigins:               []string{"https://localhost"},
		ResidentKeyRequirement:  "preferred",
		AllowPublicRegistration: &allowPublicRegistration,
	}
	stores := webauthntest.NewStores(t)
	svc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config:          cfg,
		UserStore:       stores.Users,
		SessionStore:    xkmswebauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	v, err := NewWebAuthnFactorVerifier(svc)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	f := &factorFixture{
		v:          v,
		rp:         virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		credential: newEC2Credential(t),
		stores:     stores,
	}

	regOptions, regSessionID, err := svc.BeginRegistration(ctx, email, "Passkey User")
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
	attestationResponse := virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), f.credential, *parsedRegOptions)
	var ccr protocol.CredentialCreationResponse
	if uErr := json.Unmarshal([]byte(attestationResponse), &ccr); uErr != nil {
		t.Fatalf("unmarshal attestation response: %v", uErr)
	}
	parsedAttResponse, err := ccr.Parse()
	if err != nil {
		t.Fatalf("parse attestation response: %v", err)
	}
	if _, f.user, err = svc.FinishRegistration(ctx, regSessionID, parsedAttResponse); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	credentials, err := svc.GetCredentials(ctx, f.user.WebAuthnID())
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
	qrdbUserID, err := xkmswebauthn.UserIDFromHandle(f.user.WebAuthnID())
	if err != nil {
		t.Fatalf("UserIDFromHandle: %v", err)
	}
	f.factor = &qrdbsdk.AuthFactor{
		ID:         "f-passkey",
		UserID:     qrdbUserID,
		Type:       qrdbsdk.AuthFactorFIDO2,
		Credential: credentials[0].ID,
	}
	return f
}

// setStanding rewrites the enrolled account's lifecycle and auth-method
// policy on its qrdb record.
func (f *factorFixture) setStanding(t *testing.T, state qrdbsdk.Lifecycle, methods []string) {
	t.Helper()
	f.stores.SetStanding(t, f.user.Email(), state, methods)
}

// discoverableLogin drives BeginChallenge with an empty hint (the
// discoverable/usernameless ceremony) followed by Verify, returning Verify's
// result.
func (f *factorFixture) discoverableLogin(t *testing.T) error {
	t.Helper()
	_, meta, _, err := f.v.BeginChallenge(context.Background(), "system", qrdbtransport.FactorTypeFIDO2, "")
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
		UserHandle: f.user.WebAuthnID(),
	})
	discoverableAuth.AddCredential(f.credential)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(f.rp, discoverableAuth, f.credential, *parsedLoginOptions)

	// Verify resolves the factor to a non-empty user handle (factor.UserID
	// != 0) and drives FinishLogin with it, exactly as production does once
	// qrdb has matched the credential id to an enrolled factor.
	return f.v.Verify(context.Background(), f.factor, qrdbtransport.VerifyChallenge{
		Type: qrdbtransport.FactorTypeFIDO2,
		MethodMetadata: map[string]string{
			"session_id":    sessionID,
			"assertion":     assertionResponse,
			"credential_id": string(f.factor.Credential),
		},
	})
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
	f := newFactorFixture(t, "passkey@example.com")
	if err := f.discoverableLogin(t); err != nil {
		t.Fatalf("Verify (discoverable login, begin-to-finish): %v", err)
	}
}

// TestWebAuthnFactorVerifier_RefusesAccountNotInGoodStanding is go-xkms#1298
// on the qrdb factor seam: a valid passkey must not satisfy the FIDO2 factor
// of an account that is not active, or whose auth-method policy withdraws
// WebAuthn.
func TestWebAuthnFactorVerifier_RefusesAccountNotInGoodStanding(t *testing.T) {
	cases := map[string]struct {
		state   qrdbsdk.Lifecycle
		methods []string
	}{
		"suspended":          {state: qrdbsdk.LifecycleSuspended},
		"disabled":           {state: qrdbsdk.LifecycleDisabled},
		"locked":             {state: qrdbsdk.LifecycleLocked},
		"webauthn withdrawn": {state: qrdbsdk.LifecycleActive, methods: []string{"mtls"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFactorFixture(t, "passkey@example.com")
			f.setStanding(t, tc.state, tc.methods)

			err := f.discoverableLogin(t)
			var verifyErr *SignatureVerifyError
			if !errors.As(err, &verifyErr) {
				t.Fatalf("Verify = %v, want *SignatureVerifyError", err)
			}
			if !strings.Contains(err.Error(), "verification failed") {
				t.Errorf("Verify error %q does not report a verification failure", err)
			}
		})
	}
}

// TestWebAuthnFactorVerifier_BeginChallenge_HintForAccountNotInGoodStanding
// proves a hint naming an account that may not log in opens the same
// ceremony an unknown hint does — discoverable, no credentials advertised —
// while an active account's hint scopes the ceremony to its passkey.
func TestWebAuthnFactorVerifier_BeginChallenge_HintForAccountNotInGoodStanding(t *testing.T) {
	const email = "passkey@example.com"
	f := newFactorFixture(t, email)

	allowed := func(hint string) []protocol.CredentialDescriptor {
		t.Helper()
		_, meta, _, err := f.v.BeginChallenge(context.Background(), "system", qrdbtransport.FactorTypeFIDO2, hint)
		if err != nil {
			t.Fatalf("BeginChallenge(%q): %v", hint, err)
		}
		var options protocol.CredentialAssertion
		if err := json.Unmarshal([]byte(meta["options"]), &options); err != nil {
			t.Fatalf("decode options: %v", err)
		}
		return options.Response.AllowedCredentials
	}

	if got := allowed(email); len(got) != 1 {
		t.Fatalf("active account hint advertised %d credentials, want 1", len(got))
	}
	if got := allowed("nobody@example.com"); len(got) != 0 {
		t.Fatalf("unknown hint advertised %d credentials, want 0", len(got))
	}

	f.setStanding(t, qrdbsdk.LifecycleSuspended, nil)
	if got := allowed(email); len(got) != 0 {
		t.Fatalf("suspended account hint advertised %d credentials, want the unknown hint's 0", len(got))
	}

	f.setStanding(t, qrdbsdk.LifecycleActive, []string{"piv"})
	if got := allowed(email); len(got) != 0 {
		t.Fatalf("webauthn-withdrawn account hint advertised %d credentials, want 0", len(got))
	}
}

// TestWebAuthnFactorVerifier_BeginChallenge_UsernameHint covers the
// first-boot admin: a user with a username and no email. Its username hint
// must scope the ceremony to its credentials, as an email hint does for a
// user that has one (go-xkms#1759).
func TestWebAuthnFactorVerifier_BeginChallenge_UsernameHint(t *testing.T) {
	ctx := context.Background()
	client, _, err := testutil.NewQRDBFakeClient()
	if err != nil {
		t.Fatalf("fake qrdb client: %v", err)
	}
	stores := webauthntest.NewStoresFor(t, client.Users())
	svc, err := xkmswebauthn.NewService(xkmswebauthn.ServiceParams{
		Config: &xkmswebauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "test",
			RPOrigins:     []string{"https://localhost"},
		},
		UserStore:       stores.Users,
		SessionStore:    xkmswebauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	if err != nil {
		t.Fatalf("webauthn service: %v", err)
	}
	v, err := NewWebAuthnFactorVerifier(svc)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	enroll := func(req *qrdbtransport.CreateUserRequest, credID string) {
		t.Helper()
		req.TenantID = webauthntest.TenantID
		if _, err := client.Users().CreateUser(ctx, req); err != nil {
			t.Fatalf("CreateUser(%q): %v", req.Username, err)
		}
		user, err := stores.Users.GetByUsername(ctx, req.Username)
		if err != nil {
			t.Fatalf("GetByUsername(%q): %v", req.Username, err)
		}
		cred := &xkmswebauthn.Credential{ID: []byte(credID), UserID: user.WebAuthnID(), PublicKey: []byte("pk")}
		if err := stores.Credentials.Save(ctx, cred); err != nil {
			t.Fatalf("save credential: %v", err)
		}
	}
	enroll(&qrdbtransport.CreateUserRequest{Username: "admin", WithoutEmailLoginKey: true}, "admin-cred")
	enroll(&qrdbtransport.CreateUserRequest{Username: "bob", Email: "bob@example.com"}, "bob-cred")

	allowed := func(hint string) []string {
		t.Helper()
		_, meta, _, err := v.BeginChallenge(ctx, "system", qrdbtransport.FactorTypeFIDO2, hint)
		if err != nil {
			t.Fatalf("BeginChallenge(%q): %v", hint, err)
		}
		var options protocol.CredentialAssertion
		if err := json.Unmarshal([]byte(meta["options"]), &options); err != nil {
			t.Fatalf("decode options: %v", err)
		}
		ids := make([]string, 0, len(options.Response.AllowedCredentials))
		for _, c := range options.Response.AllowedCredentials {
			ids = append(ids, string(c.CredentialID))
		}
		return ids
	}

	tests := []struct {
		hint string
		want []string
	}{
		{hint: "admin", want: []string{"admin-cred"}},
		{hint: "bob", want: []string{"bob-cred"}},
		{hint: "bob@example.com", want: []string{"bob-cred"}},
		{hint: "nobody", want: []string{}},
		{hint: "nobody@example.com", want: []string{}},
	}
	for _, tt := range tests {
		if got := allowed(tt.hint); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("hint %q advertised %q, want %q", tt.hint, got, tt.want)
		}
	}
}
