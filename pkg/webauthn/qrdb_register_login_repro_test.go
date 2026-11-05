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

package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// TestQRDBAdapter_RegisterThenLogin_SameProcess reproduces the production
// WebAuthn credential-persistence disconnect: FinishRegistration succeeds
// against the qrdb-backed stores, but a subsequent BeginLogin in the SAME
// process for the SAME user surfaces ErrNoCredentials.
//
// The scenario mirrors quicbaas's invite-activation -> passkey-login flow:
//
//  1. The user already exists (first-boot created the admin user), so
//     BeginRegistration resolves the user via GetByEmail rather than
//     creating a fresh one.
//  2. FinishRegistration persists the credential through the qrdb
//     CredentialStore adapter.
//  3. BeginLogin resolves the same user via GetByEmail and reads its
//     credentials back; it MUST find the credential persisted in step 2.
//
// This drives the exact xkms Service + qrdb adapter pair that production
// wires (no mocks of the layer under test; only the qrdb transport is a
// faithful in-memory stand-in for the embedded node).
func TestQRDBAdapter_RegisterThenLogin_SameProcess(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "localhost",
		RPDisplayName:           "QuicBaaS",
		RPOrigins:               []string{"https://localhost"},
		AllowPublicRegistration: openRegistration(),
	}

	users := newFakeUserClient()
	userStore, credStore, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users:      users,
		DAOFactory: newTestDAOFactory(),
		KV:         testutil.NewQRDBFakeTransport(),
		TenantID:   "system",
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       userStore,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: credStore,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	const email = "admin@system.qrdb.local"

	// Pre-create the user exactly as CreateUser does for an invited account
	// (go-xkms#1294 part B): a PENDING qrdb user in the "system" tenant whose
	// username is the admin email. BeginInviteRegistration must then resolve
	// THIS user, not create a second one.
	created, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: email,
		Email:    email,
		TenantID: "system",
		Pending:  true,
	})
	if err != nil {
		t.Fatalf("pre-create admin user: %v", err)
	}

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// === REGISTRATION (invite activation) ===
	regOptions, regSessionID, err := svc.BeginInviteRegistration(ctx, email)
	if err != nil {
		t.Fatalf("BeginInviteRegistration: %v", err)
	}
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	if err != nil {
		t.Fatalf("marshal reg options: %v", err)
	}
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, err := parseAttestationResponse(attestationResponse)
	if err != nil {
		t.Fatalf("parse attestation response: %v", err)
	}
	if _, err := svc.FinishInviteRegistration(ctx, regSessionID, parsedAttResponse); err != nil {
		t.Fatalf("FinishInviteRegistration: %v", err)
	}
	authenticator.AddCredential(credential)

	// Activation is the invite orchestration layer's job (pkg/xkms), not
	// webauthn.Service's; reproduce it directly against the fake client so
	// the account can log in below, exactly as a real redemption leaves it.
	if _, err := users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{
		ID:        created.ID,
		Lifecycle: string(qrdbsdk.LifecycleActive),
	}); err != nil {
		t.Fatalf("activate invited user: %v", err)
	}

	// === LOGIN (immediately after, same process, same service instance) ===
	// Resolve the user by email exactly as quicbaas BeginLogin does, then
	// start the assertion ceremony. This MUST NOT return ErrNoCredentials.
	loginUser, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail (login): %v", err)
	}
	_, _, err = svc.BeginLogin(ctx, loginUser.WebAuthnID())
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			t.Fatalf("REPRODUCED BUG: BeginLogin returned ErrNoCredentials immediately after a successful FinishRegistration for %q (login handle=%x)", email, loginUser.WebAuthnID())
		}
		t.Fatalf("BeginLogin: %v", err)
	}
}

// TestQRDBAdapter_BinaryCredentialID_RoundTrips is the direct unit-level
// regression for the persistence disconnect: a credential whose id contains
// non-UTF-8 bytes must survive Save -> per-user-index -> GetByUserID intact.
// Before the fix the index stored string(cred.ID), so encoding/json replaced
// every invalid UTF-8 byte with U+FFFD and GetByUserID returned zero creds.
func TestQRDBAdapter_BinaryCredentialID_RoundTrips(t *testing.T) {
	ctx := context.Background()
	us, cs := newTestStores(t)

	u, err := us.Create(ctx, "binary@example.com", "Binary User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A credential id with bytes that are invalid UTF-8 (0x94, 0xff, 0x80,
	// 0xfe) — exactly the kind a real authenticator produces.
	binaryID := []byte{0x94, 0xd2, 0x7a, 0xff, 0x80, 0xfe, 0x00, 0x16}
	cred := &Credential{ID: binaryID, UserID: u.WebAuthnID()}
	if err := cs.Save(ctx, cred); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := cs.GetByUserID(ctx, u.WebAuthnID())
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential after save, got %d (binary id lost in index round-trip)", len(got))
	}
	if string(got[0].ID) != string(binaryID) {
		t.Fatalf("credential id corrupted: got %x want %x", got[0].ID, binaryID)
	}

	// GetByCredentialID with the raw binary id must also resolve.
	byID, err := cs.GetByCredentialID(ctx, binaryID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if string(byID.ID) != string(binaryID) {
		t.Fatalf("GetByCredentialID returned wrong id: got %x want %x", byID.ID, binaryID)
	}
}

// TestCredIDSegmentRoundTrip exercises the canonical credential-id encoding
// helpers directly, including the malformed-segment error path.
