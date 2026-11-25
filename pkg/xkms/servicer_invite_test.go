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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// This file covers the enrollment-invitation orchestration in
// servicer_invite.go end to end (go-xkms#1294 part B): CreateUser mints an
// invite, and BeginInviteRegistration/FinishInviteRegistration (FIDO2) and
// ActivateInvitePIV redeem it, activating the account exactly once.
//
// The webauthn.Service under test is real, wired through webauthn's qrdb
// adapter to the same mockUserClient CreateUser writes through, exactly as
// production shares one qrdb client between the two.

// newInviteEC2Credential returns a virtualwebauthn EC2 credential whose
// P-256 public key has full-length (32-byte) X and Y coordinates.
// virtualwebauthn encodes coordinates with big.Int.Bytes(), which strips
// leading zero bytes (~1/128 of random keys); the go-webauthn COSE parser
// correctly rejects short coordinates, so a real authenticator always
// zero-pads. Regenerating until both coordinates are full-length keeps this
// deterministic without weakening the (correct) parser.
func newInviteEC2Credential(t *testing.T) virtualwebauthn.Credential {
	t.Helper()
	for i := 0; i < 128; i++ {
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		parsed, err := x509.ParsePKCS8PrivateKey(cred.Key.Data)
		require.NoError(t, err)
		priv, ok := parsed.(*ecdsa.PrivateKey)
		require.True(t, ok)
		size := (priv.Curve.Params().BitSize + 7) / 8
		if len(priv.X.Bytes()) == size && len(priv.Y.Bytes()) == size {
			return cred
		}
	}
	t.Fatal("could not generate EC2 credential with full-length coordinates")
	return virtualwebauthn.Credential{}
}

// inviteFixture wires a real XKMSService with a real webauthn.Service, a real
// qrdb invite store (over an in-memory KV store) and a mock qrdb user client
// that both services read, so they agree on one pending account.
type inviteFixture struct {
	svc       *XKMSService
	users     *mockUserClient
	rp        virtualwebauthn.RelyingParty
	inviteTTL time.Duration
	tenant    string
	// certBindings returns the thumbprints AddCertBinding recorded for a user.
	certBindings func(userID uint64) []string
	// credentials is the webauthn credential store the fixture wires.
	credentials webauthn.CredentialStore
	// setGetUserGate installs a hook run at the start of every GetUser;
	// call it before any concurrent use.
	setGetUserGate func(func())
	// setBeforeWrite installs a hook run at the start of every account
	// write, before the write reads the account; call it before any
	// concurrent use.
	setBeforeWrite func(func(userID uint64))
	// setLifecycle sets an account's lifecycle, as an administrator's
	// disable or enable would.
	setLifecycle func(userID uint64, lifecycle qrdbsdk.Lifecycle)
	// addAccount stores one more qrdb account; call it before any
	// concurrent use.
	addAccount func(*qrdbtransport.User)
}

const inviteFixtureQRDBUserID = uint64(42)
const inviteFixtureEmail = "invitee@example.com"

// inviteFixtureQRDBUserIDB and inviteFixtureEmailB are the fixture's second
// pending account.
const (
	inviteFixtureQRDBUserIDB = uint64(43)
	inviteFixtureEmailB      = "invitee-b@example.com"
)
const inviteFixtureTenant = "system"

// newInviteFixture builds the fixture with the account already pending in
// the qrdb mock.
func newInviteFixture(t *testing.T) *inviteFixture {
	t.Helper()
	return newInviteFixtureIn(t, inviteFixtureTenant)
}

// newInviteFixtureIn builds the fixture with the pending account owned by
// tenant. The qrdb mock's by-id calls act, like go-qrdb's routing user
// service, on the tenant bound on ctx (system when unbound).
func newInviteFixtureIn(t *testing.T, tenant string) *inviteFixture {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// qrdb side: mockUserClient tracks the pending accounts by qrdb id. A
	// second pending account (inviteFixtureQRDBUserIDB) lets a test hold
	// two live invitations at once. mu guards the accounts and the cert
	// bindings: the concurrent-activation test drives them from two
	// goroutines.
	var mu sync.Mutex
	accounts := map[uint64]*qrdbtransport.User{
		inviteFixtureQRDBUserID: {
			ID: inviteFixtureQRDBUserID, Username: inviteFixtureEmail, Email: inviteFixtureEmail,
			Name: "Invitee", TenantID: tenant, Lifecycle: string(qrdbsdk.LifecyclePending),
		},
		inviteFixtureQRDBUserIDB: {
			ID: inviteFixtureQRDBUserIDB, Username: inviteFixtureEmailB, Email: inviteFixtureEmailB,
			Name: "Invitee B", TenantID: tenant, Lifecycle: string(qrdbsdk.LifecyclePending),
		},
	}
	bindings := map[uint64][]string{}
	// getUserGate, when set (before any concurrent call), runs at the
	// start of every GetUser: a test uses it as a barrier.
	var getUserGate func()
	// beforeWrite, when set, runs at the start of every write to an
	// account, outside mu: a test uses it to change the account between
	// the invite's pending check and its activation.
	var beforeWrite func(userID uint64)
	runBeforeWrite := func(userID uint64) {
		if beforeWrite != nil {
			beforeWrite(userID)
		}
	}
	snapshot := func(u *qrdbtransport.User) *qrdbtransport.User {
		c := *u
		return &c
	}
	// notPending is qrdb's refusal of a conditional activation.
	notPending := func(u *qrdbtransport.User) error {
		return &qrdbuser.AccountNotPendingError{
			ID: u.ID, Lifecycle: qrdbuser.Lifecycle(u.Lifecycle), HasCredential: len(bindings[u.ID]) > 0,
		}
	}
	users := &mockUserClient{
		getUser: func(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
			if getUserGate != nil {
				getUserGate()
			}
			mu.Lock()
			defer mu.Unlock()
			u, ok := accounts[id]
			if !ok || inviteCallerTenant(ctx) != u.TenantID {
				return nil, &qrdbtransport.UserNotFoundError{ID: id}
			}
			return snapshot(u), nil
		},
		getUserByEmail: func(_ context.Context, tenantID, email string) (*qrdbtransport.User, error) {
			mu.Lock()
			defer mu.Unlock()
			for _, u := range accounts {
				if u.TenantID == tenantID && u.Email == email {
					return snapshot(u), nil
				}
			}
			return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
		},
		updateUser: func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
			runBeforeWrite(req.ID)
			mu.Lock()
			defer mu.Unlock()
			u, ok := accounts[req.ID]
			if !ok || inviteCallerTenant(ctx) != u.TenantID {
				return nil, &qrdbtransport.UserNotFoundError{ID: req.ID}
			}
			if req.Lifecycle != "" {
				u.Lifecycle = req.Lifecycle
			}
			return snapshot(u), nil
		},
		addCertBinding: func(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
			runBeforeWrite(userID)
			mu.Lock()
			defer mu.Unlock()
			u, ok := accounts[userID]
			if !ok {
				return nil, &qrdbtransport.UserNotFoundError{ID: userID}
			}
			bindings[userID] = append(bindings[userID], thumbprint)
			return snapshot(u), nil
		},
		// The two conditional activations judge the account as they
		// write it, under mu, as qrdb's conditional commit does.
		activatePendingUser: func(ctx context.Context, userID uint64) (*qrdbtransport.User, error) {
			runBeforeWrite(userID)
			mu.Lock()
			defer mu.Unlock()
			u, ok := accounts[userID]
			if !ok || inviteCallerTenant(ctx) != u.TenantID {
				return nil, &qrdbtransport.UserNotFoundError{ID: userID}
			}
			if u.Lifecycle != string(qrdbsdk.LifecyclePending) {
				return nil, notPending(u)
			}
			u.Lifecycle = string(qrdbsdk.LifecycleActive)
			return snapshot(u), nil
		},
		activateWithCertBinding: func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
			runBeforeWrite(userID)
			mu.Lock()
			defer mu.Unlock()
			u, ok := accounts[userID]
			if !ok || inviteCallerTenant(ctx) != u.TenantID {
				return nil, &qrdbtransport.UserNotFoundError{ID: userID}
			}
			if u.Lifecycle != string(qrdbsdk.LifecyclePending) || len(bindings[userID]) > 0 {
				return nil, notPending(u)
			}
			bindings[userID] = append(bindings[userID], thumbprint)
			u.Lifecycle = string(qrdbsdk.LifecycleActive)
			return snapshot(u), nil
		},
	}
	svc.SetUserClients(users, &mockRoleClient{})
	certBindings := func(userID uint64) []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bindings[userID]...)
	}

	// webauthn side: the SAME qrdb account, by its qrdb-id-derived handle.
	waStores := webauthntest.NewStoresFor(t, users)

	cfg := &webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "xkms test",
		RPOrigins:     []string{"https://example.com"},
	}
	waSvc, err := webauthn.NewService(webauthn.ServiceParams{
		Config:          cfg,
		UserStore:       waStores.Users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: waStores.Credentials,
	})
	require.NoError(t, err)
	svc.SetWebAuthn(waSvc)

	inviteStore, err := invitetest.New(singleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(inviteStore)

	return &inviteFixture{
		svc: svc, users: users,
		rp:           virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		inviteTTL:    time.Hour,
		tenant:       tenant,
		certBindings: certBindings,
		credentials:  waStores.Credentials,
		setGetUserGate: func(g func()) {
			getUserGate = g
		},
		setBeforeWrite: func(h func(userID uint64)) {
			beforeWrite = h
		},
		setLifecycle: func(userID uint64, lifecycle qrdbsdk.Lifecycle) {
			mu.Lock()
			defer mu.Unlock()
			accounts[userID].Lifecycle = string(lifecycle)
		},
		addAccount: func(u *qrdbtransport.User) {
			mu.Lock()
			defer mu.Unlock()
			accounts[u.ID] = u
		},
	}
}

// mintInvite issues a token for the fixture's pending account.
func (f *inviteFixture) mintInvite(t *testing.T) string {
	t.Helper()
	info, err := f.svc.createInvite(context.Background(), f.tenant, inviteFixtureQRDBUserID, f.inviteTTL)
	require.NoError(t, err)
	require.NotEmpty(t, info.Token)
	return info.Token
}

// attestInvite drives a virtual authenticator against optionsJSON and
// returns the resulting attestation response JSON, ready for
// FinishInviteRegistration.
func (f *inviteFixture) attestInvite(t *testing.T, optionsJSON string, credential virtualwebauthn.Credential) string {
	t.Helper()
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &creation))
	responseJSON, err := json.Marshal(creation.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(responseJSON))
	require.NoError(t, err)
	return virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), credential, *parsedOptions)
}

// beginRegistration, finishRegistration, getInvite and activatePIV wrap the
// transport.InviteServicer wire shape so the tests below read positionally,
// the way the pre-#1294-multi-transport methods did.

func (f *inviteFixture) beginRegistration(tenantID, token string) (*xkmstransport.BeginInviteRegistrationResponse, error) {
	return f.svc.BeginInviteRegistration(context.Background(), &xkmstransport.BeginInviteRegistrationRequest{TenantID: tenantID, Token: token})
}

func (f *inviteFixture) finishRegistration(tenantID, token, sessionID, attestationJSON string) (*xkmstransport.FinishInviteRegistrationResponse, error) {
	return f.svc.FinishInviteRegistration(context.Background(), &xkmstransport.FinishInviteRegistrationRequest{
		TenantID: tenantID, Token: token, SessionID: sessionID, AttestationJSON: attestationJSON,
	})
}

func (f *inviteFixture) getInvite(tenantID, token string) (*xkmstransport.GetInviteResponse, error) {
	return f.svc.GetInvite(context.Background(), &xkmstransport.GetInviteRequest{TenantID: tenantID, Token: token})
}

// activatePIV redeems through the fixture's InviteUserService: PIV
// redemption needs the node's conditional activation, which the client
// path lacks.
func (f *inviteFixture) activatePIV(tenantID, token string, certPEM []byte) (*xkmstransport.ActivateInvitePIVResponse, error) {
	return f.svc.ActivateInvitePIV(context.Background(), &xkmstransport.ActivateInvitePIVRequest{TenantID: tenantID, Token: token, CertPEM: string(certPEM)})
}

func TestBeginInviteRegistration_Success(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	resp, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.SessionID)
	assert.Contains(t, resp.OptionsJSON, inviteFixtureEmail)
	assert.Equal(t, xkmstransport.InviteCeremonyCreate, resp.Ceremony, "a fresh invitation asks for a new credential")
}

func TestBeginInviteRegistration_UnknownToken(t *testing.T) {
	f := newInviteFixture(t)

	_, err := f.beginRegistration(inviteFixtureTenant, "not-a-real-token")
	require.ErrorIs(t, err, ErrInviteUnusable)
}

func TestBeginInviteRegistration_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BeginInviteRegistration(context.Background(), &xkmstransport.BeginInviteRegistrationRequest{TenantID: inviteFixtureTenant, Token: "tok"})
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestFinishInviteRegistration_ActivatesAndRedeemsExactlyOnce(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)

	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))

	result, err := f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)

	// The account is active in qrdb...
	u, err := f.users.GetUser(context.Background(), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), u.Lifecycle)

	// ...and the invitation is spent: a second lookup is the one opaque
	// answer every unusable invite gets.
	_, err = f.getInvite(inviteFixtureTenant, token)
	require.ErrorIs(t, err, ErrInviteUnusable)
}

func TestFinishInviteRegistration_RefusesUnknownToken(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))

	_, err = f.finishRegistration(inviteFixtureTenant, "wrong-token", begin.SessionID, attestation)
	require.ErrorIs(t, err, ErrInviteUnusable)

	// The real token is untouched: it must still redeem.
	result, err := f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)
}

// TestInviteRedemption_RefusesNonSystemTenant pins row 21 of the #2183
// narrowing: redemption serves invitations of the system tenant only, and
// an invitation of any other tenant is refused with the opaque answer every
// unusable invite gets, on every redemption path, leaving the account as it
// was. Tenant-scoped redemption is go-xkms #2202.
func TestInviteRedemption_RefusesNonSystemTenant(t *testing.T) {
	f := newInviteFixture(t)
	const tenant = "acme"
	info, err := f.svc.createInvite(context.Background(), tenant, inviteFixtureQRDBUserID, f.inviteTTL)
	require.NoError(t, err)
	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	_, err = f.getInvite(tenant, info.Token)
	require.ErrorIs(t, err, ErrInviteUnusable)
	// The passkey paths answer ErrInviteTenantNotServed: a passkey enrolled
	// in another tenant could never sign in.
	_, err = f.beginRegistration(tenant, info.Token)
	require.ErrorIs(t, err, ErrInviteTenantNotServed)
	_, err = f.finishRegistration(tenant, info.Token, "session", "{}")
	require.ErrorIs(t, err, ErrInviteTenantNotServed)
	_, err = f.activatePIV(tenant, info.Token, pemEncodeCert(leafCert))
	require.ErrorIs(t, err, ErrInviteUnusable)

	u, err := f.users.GetUser(context.Background(), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecyclePending), u.Lifecycle)
}

// TestInviteRegistration_BindsTheInvitedAccountNotAnEmailMatch pins the
// verify13 P1 on servicer_invite.go: the WebAuthn ceremony binds to the
// account the invitation names, by its user ID, never to whichever account
// an email lookup finds. Here another pending account carries the same
// email and sorts first; it must stay unenrolled and pending.
func TestInviteRegistration_BindsTheInvitedAccountNotAnEmailMatch(t *testing.T) {
	f := newInviteFixture(t)
	const otherID = uint64(7)
	f.addAccount(&qrdbtransport.User{
		ID: otherID, Username: "other", Email: inviteFixtureEmail,
		Name: "Other", TenantID: inviteFixtureTenant, Lifecycle: string(qrdbsdk.LifecyclePending),
	})
	token := f.mintInvite(t)

	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
	result, err := f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)

	invited, err := f.users.GetUser(context.Background(), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), invited.Lifecycle)
	other, err := f.users.GetUser(context.Background(), otherID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecyclePending), other.Lifecycle, "the same-email account must not be enrolled or activated")
}

// TestFinishInviteRegistration_MismatchedSessionEnrolsNothing pins that
// finishing account A's ceremony session under account B's invitation is
// refused before any credential is stored: afterwards both A and B redeem
// their own invitations (a stored credential on A would make A's fresh
// ceremony refuse).
func TestFinishInviteRegistration_MismatchedSessionEnrolsNothing(t *testing.T) {
	f := newInviteFixture(t)
	const otherID = uint64(8)
	f.addAccount(&qrdbtransport.User{
		ID: otherID, Username: "b@example.com", Email: "b@example.com",
		Name: "B", TenantID: inviteFixtureTenant, Lifecycle: string(qrdbsdk.LifecyclePending),
	})
	tokenA := f.mintInvite(t)
	infoB, err := f.svc.createInvite(context.Background(), inviteFixtureTenant, otherID, f.inviteTTL)
	require.NoError(t, err)
	tokenB := infoB.Token

	beginA, err := f.beginRegistration(inviteFixtureTenant, tokenA)
	require.NoError(t, err)
	attestation := f.attestInvite(t, beginA.OptionsJSON, newInviteEC2Credential(t))
	_, err = f.finishRegistration(inviteFixtureTenant, tokenB, beginA.SessionID, attestation)
	require.ErrorIs(t, err, ErrInviteUnusable)

	for _, tc := range []struct {
		token string
		id    uint64
	}{{tokenA, inviteFixtureQRDBUserID}, {tokenB, otherID}} {
		begin, err := f.beginRegistration(inviteFixtureTenant, tc.token)
		require.NoError(t, err, "account %d must still be able to begin its own invite ceremony", tc.id)
		attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
		result, err := f.finishRegistration(inviteFixtureTenant, tc.token, begin.SessionID, attestation)
		require.NoError(t, err)
		assert.Equal(t, tc.id, result.UserID)
	}
}

// failActivationOnce makes the next lifecycle update fail without
// committing, as a qrdb write lost after the credential was persisted.
func (f *inviteFixture) failActivationOnce(t *testing.T) {
	t.Helper()
	activate := f.users.activatePendingUser
	failed := false
	f.users.activatePendingUser = func(ctx context.Context, userID uint64) (*qrdbtransport.User, error) {
		if !failed {
			failed = true
			return nil, errors.New("injected: activation not committed")
		}
		return activate(ctx, userID)
	}
}

func (f *inviteFixture) lifecycle(t *testing.T, id uint64) string {
	t.Helper()
	u, err := f.users.GetUser(context.Background(), id)
	require.NoError(t, err)
	return u.Lifecycle
}

// An activation that fails after WebAuthn stored the credential is
// resumable: the account stays pending and the invitation unredeemed, and a
// new begin answers with a WebAuthn get for the enrolled credential whose
// valid assertion completes the activation once (verify P1
// servicer_invite.go:332; Company Agent: possession, not public data).
func TestFinishInviteRegistration_ResumesActivationAfterFailure(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)
	credential, attestation := f.enrolThenFailActivation(t, token)

	// Re-sending the attestation proves nothing (its credential ID and
	// public key are public data): it is refused, and nothing changes.
	_, err := f.finishRegistration(inviteFixtureTenant, token, "spent-session", attestation)
	require.Error(t, err)
	f.requirePendingUnredeemed(t, token, inviteFixtureQRDBUserID)

	// The resume is a fresh WebAuthn get for the enrolled credential.
	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	assert.Equal(t, xkmstransport.InviteCeremonyGet, begin.Ceremony, "a resume asks the client for a WebAuthn get")
	assertion := f.assertInvite(t, begin.OptionsJSON, credential)
	result, err := f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, assertion)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), f.lifecycle(t, inviteFixtureQRDBUserID))
	_, err = f.getInvite(inviteFixtureTenant, token)
	require.ErrorIs(t, err, ErrInviteUnusable)

	// The resume ran once: a replay of the assertion is refused.
	_, err = f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, assertion)
	require.ErrorIs(t, err, ErrInviteUnusable)
}

// Each resume finish without a valid assertion by the enrolled credential
// over the resume session's own challenge is refused, leaving the account
// pending and the invitation unredeemed.
func TestFinishInviteRegistration_ResumeRefusesWithoutPossessionProof(t *testing.T) {
	cases := []struct {
		name      string
		assertion func(f *inviteFixture, t *testing.T, token string, credential virtualwebauthn.Credential) (sessionID, assertion string)
	}{
		{"no assertion", func(f *inviteFixture, t *testing.T, token string, _ virtualwebauthn.Credential) (string, string) {
			begin, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			return begin.SessionID, "{}"
		}},
		{"invalid signature", func(f *inviteFixture, t *testing.T, token string, credential virtualwebauthn.Credential) (string, string) {
			begin, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			return begin.SessionID, tamperAssertionSignature(t, f.assertInvite(t, begin.OptionsJSON, credential))
		}},
		{"assertion over another challenge", func(f *inviteFixture, t *testing.T, token string, credential virtualwebauthn.Credential) (string, string) {
			first, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			second, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			return second.SessionID, f.assertInvite(t, first.OptionsJSON, credential)
		}},
		{"assertion over a stale challenge", func(f *inviteFixture, t *testing.T, token string, credential virtualwebauthn.Credential) (string, string) {
			stale, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			_, err = f.finishRegistration(inviteFixtureTenant, token, stale.SessionID, "{}")
			require.Error(t, err)
			return stale.SessionID, f.assertInvite(t, stale.OptionsJSON, credential)
		}},
		{"assertion signed by another credential", func(f *inviteFixture, t *testing.T, token string, _ virtualwebauthn.Credential) (string, string) {
			begin, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			return begin.SessionID, f.assertInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInviteFixture(t)
			token := f.mintInvite(t)
			credential, _ := f.enrolThenFailActivation(t, token)
			sessionID, assertion := tc.assertion(f, t, token, credential)
			_, err := f.finishRegistration(inviteFixtureTenant, token, sessionID, assertion)
			require.Error(t, err)
			f.requirePendingUnredeemed(t, token, inviteFixtureQRDBUserID)
		})
	}
}

// The resume is bound to the invitation's own account: another invitation
// cannot carry it, and a consumed invitation resumes nothing.
func TestFinishInviteRegistration_ResumeRefusesAnotherAccountAndConsumedInvite(t *testing.T) {
	f := newInviteFixture(t)
	const otherID = uint64(8)
	f.addAccount(&qrdbtransport.User{
		ID: otherID, Username: "b@example.com", Email: "b@example.com",
		Name: "B", TenantID: inviteFixtureTenant, Lifecycle: string(qrdbsdk.LifecyclePending),
	})
	tokenA := f.mintInvite(t)
	infoB, err := f.svc.createInvite(context.Background(), inviteFixtureTenant, otherID, f.inviteTTL)
	require.NoError(t, err)
	tokenB := infoB.Token

	credentialB, _ := f.enrolThenFailActivation(t, tokenB)
	beginB, err := f.beginRegistration(inviteFixtureTenant, tokenB)
	require.NoError(t, err)
	assertionB := f.assertInvite(t, beginB.OptionsJSON, credentialB)

	// A's invitation cannot carry B's resume to activation.
	_, err = f.finishRegistration(inviteFixtureTenant, tokenA, beginB.SessionID, assertionB)
	require.Error(t, err)
	f.requirePendingUnredeemed(t, tokenA, inviteFixtureQRDBUserID)
	assert.Equal(t, string(qrdbsdk.LifecyclePending), f.lifecycle(t, otherID))

	// Once B's invitation is consumed, B's enrolment no longer resumes.
	_, err = f.svc.inviteStore.Redeem(context.Background(), inviteFixtureTenant, tokenB)
	require.NoError(t, err)
	_, err = f.beginRegistration(inviteFixtureTenant, tokenB)
	require.ErrorIs(t, err, ErrInviteUnusable)
	beginB, err = f.beginRegistration(inviteFixtureTenant, tokenA)
	require.NoError(t, err)
	_, err = f.finishRegistration(inviteFixtureTenant, tokenB, beginB.SessionID, assertionB)
	require.ErrorIs(t, err, ErrInviteUnusable)
	assert.Equal(t, string(qrdbsdk.LifecyclePending), f.lifecycle(t, otherID))
}

// enrolThenFailActivation runs token's invite ceremony with a fresh
// credential while the activation fails once, so the credential is stored
// and the account stays pending. It returns the credential and attestation.
func (f *inviteFixture) enrolThenFailActivation(t *testing.T, token string) (virtualwebauthn.Credential, string) {
	t.Helper()
	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	credential := newInviteEC2Credential(t)
	attestation := f.attestInvite(t, begin.OptionsJSON, credential)
	f.failActivationOnce(t)
	_, err = f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
	require.Error(t, err)
	return credential, attestation
}

func (f *inviteFixture) requirePendingUnredeemed(t *testing.T, token string, id uint64) {
	t.Helper()
	assert.Equal(t, string(qrdbsdk.LifecyclePending), f.lifecycle(t, id))
	_, err := f.getInvite(inviteFixtureTenant, token)
	require.NoError(t, err, "the invitation must stay unredeemed")
}

// assertInvite answers a resume begin's WebAuthn get options with
// credential's assertion.
func (f *inviteFixture) assertInvite(t *testing.T, optionsJSON string, credential virtualwebauthn.Credential) string {
	t.Helper()
	var request protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(optionsJSON), &request))
	require.NotEmpty(t, request.Response.AllowedCredentials, "a resume begin answers with get options")
	responseJSON, err := json.Marshal(request.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(responseJSON))
	require.NoError(t, err)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(credential)
	return virtualwebauthn.CreateAssertionResponse(f.rp, authenticator, credential, *parsedOptions)
}

// tamperAssertionSignature flips the last byte of an assertion's signature.
func tamperAssertionSignature(t *testing.T, assertionJSON string) string {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(assertionJSON), &body))
	response, ok := body["response"].(map[string]any)
	require.True(t, ok)
	encoded, ok := response["signature"].(string)
	require.True(t, ok)
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	sig[len(sig)-1] ^= 0xff
	response["signature"] = base64.RawURLEncoding.EncodeToString(sig)
	out, err := json.Marshal(body)
	require.NoError(t, err)
	return string(out)
}

func TestGetInvite_Success(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	meta, err := f.getInvite(inviteFixtureTenant, token)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureEmail, meta.Email)
	assert.Equal(t, "Invitee", meta.DisplayName)
	assert.Contains(t, meta.Methods, "webauthn")
	assert.Contains(t, meta.Methods, "piv")
}

func TestGetInvite_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetInvite(context.Background(), &xkmstransport.GetInviteRequest{TenantID: inviteFixtureTenant, Token: "tok"})
	require.ErrorIs(t, err, ErrNotConfigured)
}

// ============================================================================
// PIV activation
// ============================================================================

// generateInvitePIVChain returns a self-signed CA and a ClientAuth leaf it
// issued, mirroring pkg/xkms/servicer_ca_test.go's createSelfSignedCert but
// producing a chain (root + leaf) rather than a single self-signed cert:
// ActivateInvitePIV verifies the PRESENTED certificate against the CA's
// bundle, so the two must be different certificates linked by signature.
func generateInvitePIVChain(t *testing.T) (caCert *x509.Certificate, leafCert *x509.Certificate, leafErr error) {
	t.Helper()
	return generateInvitePIVChainFor(t, inviteFixtureTenant)
}

// generateInvitePIVChainFor is generateInvitePIVChain with a leaf that names
// tenant the way qrdb's TenantFromClientCert reads it: tenant as the first
// OU and a spiffe://<tenant>/user/<name> SAN, the form PIV login derives the
// account's tenant from.
func generateInvitePIVChainFor(t *testing.T, tenant string) (caCert *x509.Certificate, leafCert *x509.Certificate, leafErr error) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms test invite CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "invitee", OrganizationalUnit: []string{tenant}},
		URIs:         []*url.URL{{Scheme: "spiffe", Host: tenant, Path: "/user/invitee"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err = x509.ParseCertificate(leafDER)
	return caCert, leafCert, err
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestActivateInvitePIV_Success(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	result, err := f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)

	u, err := f.users.GetUser(context.Background(), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), u.Lifecycle)

	_, err = f.getInvite(inviteFixtureTenant, token)
	require.ErrorIs(t, err, ErrInviteUnusable)
}

// disableBeforeFirstWrite makes an administrator disable the invited
// account after the invite's pending check and before its activation
// writes anything: the first account write sees a disabled account.
func (f *inviteFixture) disableBeforeFirstWrite(t *testing.T) {
	t.Helper()
	var once sync.Once
	f.setBeforeWrite(func(userID uint64) {
		once.Do(func() { f.setLifecycle(userID, qrdbsdk.LifecycleDisabled) })
	})
}

// TestInviteRedemption_AccountDisabledDuringRedemptionStaysDisabled covers
// an administrative disable landing between an invite finish's pending
// check and its activation (Codex P1 on #2296): the activation is
// conditional on the account still being pending, so the finish fails and
// never reinstates the disabled account, for the passkey and the PIV path.
func TestInviteRedemption_AccountDisabledDuringRedemptionStaysDisabled(t *testing.T) {
	t.Run("passkey", func(t *testing.T) {
		f := newInviteFixture(t)
		token := f.mintInvite(t)

		begin, err := f.beginRegistration(inviteFixtureTenant, token)
		require.NoError(t, err)
		attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))

		f.disableBeforeFirstWrite(t)
		_, err = f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
		require.Error(t, err)

		assert.Equal(t, string(qrdbsdk.LifecycleDisabled), f.lifecycle(t, inviteFixtureQRDBUserID),
			"a disable during redemption must not be undone by the activation")
	})

	t.Run("piv", func(t *testing.T) {
		f := newInviteFixture(t)
		token := f.mintInvite(t)

		caCert, leafCert, err := generateInvitePIVChain(t)
		require.NoError(t, err)
		f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

		f.disableBeforeFirstWrite(t)
		_, err = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
		require.Error(t, err)

		assert.Equal(t, string(qrdbsdk.LifecycleDisabled), f.lifecycle(t, inviteFixtureQRDBUserID),
			"a disable during redemption must not be undone by the activation")
		assert.Empty(t, f.certBindings(inviteFixtureQRDBUserID),
			"a refused activation binds no certificate")
	})
}

// mintInviteFor mints an invitation for the fixture account userID.
func (f *inviteFixture) mintInviteFor(t *testing.T, userID uint64) string {
	t.Helper()
	info, err := f.svc.createInvite(context.Background(), f.tenant, userID, f.inviteTTL)
	require.NoError(t, err)
	require.NotEmpty(t, info.Token)
	return info.Token
}

// A ceremony begun with user A's invitation cannot be finished with user
// B's: the session belongs to A, the token to B, and the finish refuses
// before any credential is persisted, activating neither account and
// leaving B's invitation redeemable.
func TestFinishInviteRegistration_RefusesSessionOfAnotherInvitation(t *testing.T) {
	f := newInviteFixture(t)
	tokenA := f.mintInviteFor(t, inviteFixtureQRDBUserID)
	tokenB := f.mintInviteFor(t, inviteFixtureQRDBUserIDB)

	begin, err := f.beginRegistration(inviteFixtureTenant, tokenA)
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))

	_, err = f.finishRegistration(inviteFixtureTenant, tokenB, begin.SessionID, attestation)
	require.ErrorIs(t, err, ErrInviteUnusable)

	ctx := bindInviteTenant(context.Background(), inviteFixtureTenant)
	for _, id := range []uint64{inviteFixtureQRDBUserID, inviteFixtureQRDBUserIDB} {
		creds, cErr := f.credentials.GetByUserID(ctx, webauthn.HandleFromUserID(id))
		require.NoError(t, cErr)
		assert.Empty(t, creds, "no credential may be stored for user %d", id)

		u, uErr := f.users.GetUser(ctx, id)
		require.NoError(t, uErr)
		assert.Equal(t, string(qrdbsdk.LifecyclePending), u.Lifecycle, "user %d must stay pending", id)
	}

	_, err = f.getInvite(inviteFixtureTenant, tokenB)
	require.NoError(t, err, "B's invitation must stay redeemable")
}

// Two concurrent PIV activations of one invitation: exactly one wins, the
// loser gets ErrInviteUnusable, and the account ends with one cert binding.
func TestActivateInvitePIV_ConcurrentClaimsOneWinner(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	ca1, leaf1, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	ca2, leaf2, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	bundle := append(pemEncodeCert(ca1), pemEncodeCert(ca2)...)
	f.svc.SetCA(&mockCA{bundlePEM: bundle})

	leaves := [][]byte{pemEncodeCert(leaf1), pemEncodeCert(leaf2)}
	// Both requests read the account (the pending check) before either
	// goes on: the interleaving that let both bind before the claim.
	var arrived sync.WaitGroup
	arrived.Add(len(leaves))
	var gateMu sync.Mutex
	calls := 0
	f.setGetUserGate(func() {
		gateMu.Lock()
		calls++
		first := calls <= len(leaves)
		gateMu.Unlock()
		if first {
			arrived.Done()
			arrived.Wait()
		}
	})
	start := make(chan struct{})
	errs := make([]error, len(leaves))
	var wg sync.WaitGroup
	for i := range leaves {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = f.activatePIV(inviteFixtureTenant, token, leaves[i])
		}(i)
	}
	close(start)
	wg.Wait()

	var wins int
	for _, e := range errs {
		if e == nil {
			wins++
			continue
		}
		assert.ErrorIs(t, e, ErrInviteUnusable)
	}
	assert.Equal(t, 1, wins, "exactly one activation must win")
	assert.Len(t, f.certBindings(inviteFixtureQRDBUserID), 1, "exactly one certificate may be bound")
}

// A request whose chain fails verification does not claim the invitation:
// a following valid request still activates.
func TestActivateInvitePIV_RejectedChainLeavesInvitationRedeemable(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	_, strangerLeaf, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	_, err = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(strangerLeaf))
	var rejected *ErrPIVCertRejected
	require.ErrorAs(t, err, &rejected)
	assert.Empty(t, f.certBindings(inviteFixtureQRDBUserID))

	_, err = f.getInvite(inviteFixtureTenant, token)
	require.NoError(t, err, "a rejected chain must not spend the invitation")

	result, err := f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)
	assert.Len(t, f.certBindings(inviteFixtureQRDBUserID), 1)
}

// TestActivateInvitePIV_FailedActivationLeavesInvitationRedeemable: a
// storage error in the certificate-binding activation spends no invitation,
// so the invitee can retry with the same token.
func TestActivateInvitePIV_FailedActivationLeavesInvitationRedeemable(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	activate := f.users.activateWithCertBinding
	errStorage := errors.New("storage unavailable")
	failed := false
	f.users.activateWithCertBinding = func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
		if !failed {
			failed = true
			return nil, errStorage
		}
		return activate(ctx, userID, thumbprint, notAfterUnix)
	}

	_, err = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	require.ErrorIs(t, err, errStorage)
	assert.Empty(t, f.certBindings(inviteFixtureQRDBUserID))

	_, err = f.getInvite(inviteFixtureTenant, token)
	require.NoError(t, err, "a failed activation must not spend the invitation")

	result, err := f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)
	assert.Len(t, f.certBindings(inviteFixtureQRDBUserID), 1)

	_, err = f.getInvite(inviteFixtureTenant, token)
	require.ErrorIs(t, err, ErrInviteUnusable, "a confirmed activation redeems the invitation")
}

// A certificate the CA trusts but that names another tenant (here a
// system-tenant certificate presented with an acme-tenant invitation) is
// refused before anything is claimed or bound: PIV login derives the tenant
// from the certificate under the pinned trust domain, so such a binding
// could never be found. The invitation stays redeemable and the account
// pending; the acme certificate then activates the same invitation.
func TestActivateInvitePIV_RefusesCertificateOfAnotherTenant(t *testing.T) {
	const tenant = "acme"
	f := newInviteFixtureIn(t, tenant)
	f.svc.SetSPIFFETrustDomain("xkms.test")
	token := f.mintInvite(t)

	// Both issuing CAs are in the trusted bundle: chain trust alone admits
	// either certificate.
	systemCA, systemLeaf, err := generateInvitePIVChainFor(t, qrdbsdk.SystemTenantID)
	require.NoError(t, err)
	acmeCA, acmeLeaf, err := generateInvitePIVChainFor(t, tenant)
	require.NoError(t, err)
	bundle := append(pemEncodeCert(systemCA), pemEncodeCert(acmeCA)...)
	f.svc.SetCA(&mockCA{bundlePEM: bundle})

	_, err = f.activatePIV(tenant, token, pemEncodeCert(systemLeaf))
	var rejected *ErrPIVCertRejected
	require.ErrorAs(t, err, &rejected, "a certificate of another tenant must be refused")
	assert.Empty(t, f.certBindings(inviteFixtureQRDBUserID), "no binding for a refused certificate")

	_, err = f.getInvite(tenant, token)
	require.NoError(t, err, "a refused certificate must not spend the invitation")
	u, err := f.svc.inviteUserClient().GetUser(bindInviteTenant(context.Background(), tenant), inviteFixtureQRDBUserID)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecyclePending), u.Lifecycle, "the account must stay pending")

	// The invited tenant's certificate activates the same invitation.
	result, err := f.activatePIV(tenant, token, pemEncodeCert(acmeLeaf))
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)
	assert.Len(t, f.certBindings(inviteFixtureQRDBUserID), 1)
}

func TestActivateInvitePIV_RejectsUntrustedCert(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)

	// A DIFFERENT CA than the one the trust pool holds.
	_, untrustedLeaf, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	otherCA, _, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(otherCA)})

	_, err = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(untrustedLeaf))
	var rejected *ErrPIVCertRejected
	require.True(t, errors.As(err, &rejected))

	// The invite is untouched by a rejected certificate: it must still be
	// usable.
	meta, err := f.getInvite(inviteFixtureTenant, token)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureEmail, meta.Email)
}

func TestActivateInvitePIV_RejectsMalformedPEM(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)
	caCert, _, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	_, err = f.activatePIV(inviteFixtureTenant, token, []byte("not a pem"))
	var decodeErr *ErrPIVCertDecode
	require.True(t, errors.As(err, &decodeErr))
}

func TestActivateInvitePIV_UnknownToken(t *testing.T) {
	f := newInviteFixture(t)
	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	_, err = f.activatePIV(inviteFixtureTenant, "not-a-real-token", pemEncodeCert(leafCert))
	require.ErrorIs(t, err, ErrInviteUnusable)
}

func TestActivateInvitePIV_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ActivateInvitePIV(context.Background(), &xkmstransport.ActivateInvitePIVRequest{TenantID: inviteFixtureTenant, Token: "tok", CertPEM: "pem"})
	require.ErrorIs(t, err, ErrNotConfigured)
}

// ============================================================================
// effectiveInviteTTL / buildInviteURL
// ============================================================================

func TestEffectiveInviteTTL_DefaultsAndCaps(t *testing.T) {
	svc := &XKMSService{}
	// No config: qrdb's own default, and the fallback 7-day cap.
	assert.Equal(t, qrdbsdk.DefaultInviteTTL, svc.effectiveInviteTTL(0))
	assert.Equal(t, defaultMaxInviteTTL, svc.effectiveInviteTTL(30*24*time.Hour))

	svc.SetInviteConfig(InviteConfig{DefaultTTL: 2 * time.Hour, MaxTTL: 6 * time.Hour})
	assert.Equal(t, 2*time.Hour, svc.effectiveInviteTTL(0))
	assert.Equal(t, 6*time.Hour, svc.effectiveInviteTTL(24*time.Hour))
	assert.Equal(t, 3*time.Hour, svc.effectiveInviteTTL(3*time.Hour))
}

func TestBuildInviteURL(t *testing.T) {
	svc := &XKMSService{}
	svc.SetInviteConfig(InviteConfig{PublicBaseURL: "https://kms.example.com/ui/"})
	assert.Equal(t, "https://kms.example.com/ui/#/invite/acme/tok123", svc.buildInviteURL("acme", "tok123"))

	svc.SetInviteConfig(InviteConfig{})
	assert.Equal(t, "/#/invite/acme/tok123", svc.buildInviteURL("acme", "tok123"))
}
