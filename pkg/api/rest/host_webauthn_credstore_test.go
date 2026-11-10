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

package rest

import (
	"context"
	"errors"
	waprotocol "github.com/go-webauthn/webauthn/protocol"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// recordingCredentialStore is a write-through decorator over a
// webauthn.CredentialStore: it delegates every call to the wrapped store and
// records the credential ids it saw pass through Save. It is the shape a
// composer uses in production (go-quicbaas wraps the same qrdb-backed store
// to enroll a qrdb auth factor alongside the credential), reduced to the one
// observable this test needs.
type recordingCredentialStore struct {
	webauthn.CredentialStore

	mu    sync.Mutex
	saved [][]byte
}

// Save delegates to the wrapped store first and records the credential only
// on success -- a decorator that recorded a failed write would report a
// passkey the relying party does not have.
func (r *recordingCredentialStore) Save(ctx context.Context, cred *webauthn.Credential) error {
	if err := r.CredentialStore.Save(ctx, cred); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.saved = append(r.saved, cred.ID)
	return nil
}

// savedIDs returns a copy of the recorded credential ids.
func (r *recordingCredentialStore) savedIDs() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.saved))
	copy(out, r.saved)
	return out
}

// registerPasskey drives a complete registration ceremony against svc with a
// mock authenticator and returns the credential id the authenticator
// enrolled. It fails the test on any ceremony error: these tests are about
// where the credential lands, so a ceremony that did not complete is never
// an acceptable outcome.
func registerPasskey(t *testing.T, svc *webauthn.Service, rpID, origin, email string) []byte {
	t.Helper()
	ctx := context.Background()

	authenticator, err := webauthn.NewMockAuthenticator(rpID)
	require.NoError(t, err)

	options, sessionID, err := svc.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	handle, ok := options.Response.User.ID.(waprotocol.URLEncodedBase64)
	require.True(t, ok)

	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, handle, origin)
	require.NoError(t, err)

	_, registered, err := svc.FinishRegistration(ctx, sessionID, attestation)
	require.NoError(t, err)
	require.NotNil(t, registered)

	return authenticator.CredentialID
}

// qrdbWebAuthnConfig returns the relying-party config these tests register
// against, with public registration open so the ceremony creates the user.
func qrdbWebAuthnConfig() *webauthn.Config {
	allow := true
	return WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
		RPID:                    "example.com",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: &allow,
	})
}

// independentQRDBCredentialStore builds a SECOND credential store over the
// same client and DAO factory, so a test can read what the relying party
// actually persisted instead of asking the store instance it was handed.
func independentQRDBCredentialStore(t *testing.T, client *qrdbsdk.Client, factory *qrdbsdk.DAOFactory) webauthn.CredentialStore {
	t.Helper()
	_, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:      client.Users(),
		DAOFactory: factory,
		TenantID:   DefaultWebAuthnTenant,
	})
	require.NoError(t, err)
	return creds
}

// TestBuildWebAuthnService_CredentialStoreDecoratorSeesRegistration is the
// go-xkms#350 regression: a composer that decorates the credential store
// must observe every credential the module's own registration ceremony
// enrolls. Without the seam the module's relying party wrote straight to the
// qrdb store, so a credential registered through it carried none of the
// composer's side effects (in production: no qrdb fido2 auth factor, so the
// unified login ceremony answered "factor not found").
func TestBuildWebAuthnService_CredentialStoreDecoratorSeesRegistration(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	factory := testutil.NewMemoryDAOFactory()

	var decoratorCalls int
	var recorder *recordingCredentialStore

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: client,
		DAOFactory: factory,
		CredentialStoreDecorator: func(inner webauthn.CredentialStore) webauthn.CredentialStore {
			decoratorCalls++
			require.NotNil(t, inner, "the decorator receives the qrdb-backed store, never nil")
			recorder = &recordingCredentialStore{CredentialStore: inner}
			return recorder
		},
	})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, 1, decoratorCalls, "the store is decorated once at construction, not per ceremony")
	require.NotNil(t, recorder)

	credID := registerPasskey(t, svc, "example.com", "https://example.com", "alice@example.com")

	saved := recorder.savedIDs()
	require.Len(t, saved, 1, "the decorator must see exactly one Save from a completed FinishRegistration")
	assert.Equal(t, credID, saved[0], "the decorator must see the credential the authenticator enrolled")

	// Delegation is the other half of the contract: the wrapped qrdb store
	// must still hold the credential, so decorating cannot cost the relying
	// party its persistence.
	persisted, err := independentQRDBCredentialStore(t, client, factory).GetByCredentialID(context.Background(), credID)
	require.NoError(t, err, "the decorated write must still reach the qrdb-backed store")
	assert.Equal(t, credID, persisted.ID)
}

// TestBuildWebAuthnService_NoDecoratorPersistsToQRDBStore pins the default:
// an unset seam leaves the qrdb-backed store BuildWebAuthnService derives in
// place, and a registration lands there exactly as before.
func TestBuildWebAuthnService_NoDecoratorPersistsToQRDBStore(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	factory := testutil.NewMemoryDAOFactory()

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: client,
		DAOFactory: factory,
	})
	require.NoError(t, err)

	credID := registerPasskey(t, svc, "example.com", "https://example.com", "bob@example.com")

	persisted, err := independentQRDBCredentialStore(t, client, factory).GetByCredentialID(context.Background(), credID)
	require.NoError(t, err, "without a decorator the credential still lands in the qrdb store")
	assert.Equal(t, credID, persisted.ID)
}

// TestBuildWebAuthnService_CredentialStoreDecoratorReturningNil is the
// fail-closed path: a decorator that hands back no store would leave the
// relying party unable to persist or read a passkey, so construction must
// fail with a typed error rather than produce a service whose registrations
// vanish.
func TestBuildWebAuthnService_CredentialStoreDecoratorReturningNil(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	factory := testutil.NewMemoryDAOFactory()

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: client,
		DAOFactory: factory,
		CredentialStoreDecorator: func(webauthn.CredentialStore) webauthn.CredentialStore {
			return nil
		},
	})
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrWebAuthnCredentialStoreDecoratorNil)

	var buildErr *WebAuthnServiceBuildError
	assert.True(t, errors.As(err, &buildErr), "the failure keeps the builder's typed wrapper")
}

// TestBuildWebAuthnService_CredentialStoreDecoratorReturningTypedNil covers
// the Go footgun the plain nil check misses: a decorator that hands back a
// (*T)(nil) produces a non-nil interface that panics on the first Save --
// mid-ceremony, long after the wiring mistake was made. Construction must
// refuse it with the same typed error as an untyped nil.
func TestBuildWebAuthnService_CredentialStoreDecoratorReturningTypedNil(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	factory := testutil.NewMemoryDAOFactory()

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: client,
		DAOFactory: factory,
		CredentialStoreDecorator: func(webauthn.CredentialStore) webauthn.CredentialStore {
			var typedNil *recordingCredentialStore
			return typedNil
		},
	})
	require.Error(t, err)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrWebAuthnCredentialStoreDecoratorNil)
}

// TestBuildWebAuthnService_CredentialStoreDecoratorErrorPropagates proves the
// seam does not swallow a decorator's own write failure: a decorated Save
// that fails must fail the ceremony, not leave a credential the composer's
// side effects never covered.
func TestBuildWebAuthnService_CredentialStoreDecoratorErrorPropagates(t *testing.T) {
	client, _ := newFakeQRDBClient(t)
	factory := testutil.NewMemoryDAOFactory()

	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: client,
		DAOFactory: factory,
		CredentialStoreDecorator: func(inner webauthn.CredentialStore) webauthn.CredentialStore {
			return &failingCredentialStore{CredentialStore: inner}
		},
	})
	require.NoError(t, err)

	ctx := context.Background()
	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)

	options, sessionID, err := svc.BeginRegistration(ctx, "carol@example.com", "carol@example.com")
	require.NoError(t, err)
	handle, ok := options.Response.User.ID.(waprotocol.URLEncodedBase64)
	require.True(t, ok)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, handle, "https://example.com")
	require.NoError(t, err)

	_, _, err = svc.FinishRegistration(ctx, sessionID, attestation)
	require.Error(t, err, "a decorator that cannot complete its side effect must fail the ceremony")
	assert.ErrorIs(t, err, errDecoratedSaveFailed)
}

// errDecoratedSaveFailed is the sentinel failingCredentialStore returns from
// Save, so the test asserts on identity rather than on a message.
var errDecoratedSaveFailed = errors.New("rest_test: decorated save failed")

// failingCredentialStore refuses every Save, standing in for a composer's
// side effect (an auth-factor write) that cannot be completed.
type failingCredentialStore struct {
	webauthn.CredentialStore
}

// Save reports the decorator's own failure without touching the wrapped
// store.
func (f *failingCredentialStore) Save(context.Context, *webauthn.Credential) error {
	return errDecoratedSaveFailed
}
