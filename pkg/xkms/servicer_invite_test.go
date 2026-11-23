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
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
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
	accounts  []*qrdbtransport.User
}

const inviteFixtureQRDBUserID = uint64(42)
const inviteFixtureEmail = "invitee@example.com"
const inviteFixtureTenant = "system"

// newInviteFixture builds the fixture with the account already pending in
// the qrdb mock.
func newInviteFixture(t *testing.T) *inviteFixture {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// qrdb side: mockUserClient tracks the pending accounts by qrdb id. A
	// test may append accounts (f.accounts); an email lookup answers the
	// lowest-ID match in the tenant, as an ambiguous login key would.
	f := &inviteFixture{}
	f.accounts = []*qrdbtransport.User{{
		ID: inviteFixtureQRDBUserID, Username: inviteFixtureEmail, Email: inviteFixtureEmail,
		Name: "Invitee", TenantID: inviteFixtureTenant, Lifecycle: string(qrdbsdk.LifecyclePending),
	}}
	byID := func(id uint64) *qrdbtransport.User {
		for _, u := range f.accounts {
			if u.ID == id {
				return u
			}
		}
		return nil
	}
	users := &mockUserClient{
		getUser: func(_ context.Context, id uint64) (*qrdbtransport.User, error) {
			if u := byID(id); u != nil {
				return u, nil
			}
			return nil, &qrdbtransport.UserNotFoundError{ID: id}
		},
		getUserByEmail: func(_ context.Context, tenantID, email string) (*qrdbtransport.User, error) {
			var found *qrdbtransport.User
			for _, u := range f.accounts {
				if u.TenantID == tenantID && u.Email == email && (found == nil || u.ID < found.ID) {
					found = u
				}
			}
			if found == nil {
				return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
			}
			return found, nil
		},
		updateUser: func(_ context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
			u := byID(req.ID)
			if u == nil {
				return nil, &qrdbtransport.UserNotFoundError{ID: req.ID}
			}
			if req.Lifecycle != "" {
				u.Lifecycle = req.Lifecycle
			}
			return u, nil
		},
		addCertBinding: func(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
			if u := byID(userID); u != nil {
				return u, nil
			}
			return nil, &qrdbtransport.UserNotFoundError{ID: userID}
		},
	}
	svc.SetUserClients(users, &mockRoleClient{})

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

	f.svc, f.users = svc, users
	f.rp = virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]}
	f.inviteTTL = time.Hour
	return f
}

// mintInvite issues a token for the fixture's pending account.
func (f *inviteFixture) mintInvite(t *testing.T) string {
	t.Helper()
	info, err := f.svc.createInvite(context.Background(), inviteFixtureTenant, inviteFixtureQRDBUserID, f.inviteTTL)
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
	f.svc.SetInviteUserService(fixtureInviteUsers{f: f})
	return f.svc.ActivateInvitePIV(context.Background(), &xkmstransport.ActivateInvitePIVRequest{TenantID: tenantID, Token: token, CertPEM: string(certPEM)})
}

// fixtureInviteUsers is the fixture's accounts as an InviteUserService.
// ActivateWithCertBinding refuses a non-pending account the way qrdb's
// conditional activation does.
type fixtureInviteUsers struct{ f *inviteFixture }

func (u fixtureInviteUsers) account(id uint64) (*qrdbsdk.User, error) {
	a, err := u.f.users.GetUser(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return &qrdbsdk.User{ID: a.ID, Username: a.Username, Email: a.Email, Name: a.Name, TenantID: a.TenantID, Lifecycle: qrdbsdk.Lifecycle(a.Lifecycle)}, nil
}

func (u fixtureInviteUsers) GetUser(_ context.Context, id uint64) (*qrdbsdk.User, error) {
	return u.account(id)
}

func (u fixtureInviteUsers) UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error) {
	if _, err := u.f.users.UpdateUser(ctx, &qrdbtransport.UpdateUserRequest{ID: req.ID, Lifecycle: string(req.Lifecycle)}); err != nil {
		return nil, err
	}
	return u.account(req.ID)
}

func (u fixtureInviteUsers) ActivateWithCertBinding(ctx context.Context, userID uint64, _ string, _ int64) (*qrdbsdk.User, error) {
	a, err := u.account(userID)
	if err != nil {
		return nil, err
	}
	if a.Lifecycle != qrdbsdk.LifecyclePending {
		return nil, &qrdbuser.AccountNotPendingError{ID: userID, Lifecycle: a.Lifecycle}
	}
	return u.UpdateUser(ctx, &qrdbsdk.UpdateUserRequest{ID: userID, Lifecycle: qrdbsdk.LifecycleActive})
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
	_, err = f.beginRegistration(tenant, info.Token)
	require.ErrorIs(t, err, ErrInviteUnusable)
	_, err = f.finishRegistration(tenant, info.Token, "session", "{}")
	require.ErrorIs(t, err, ErrInviteUnusable)
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
	f.accounts = append(f.accounts, &qrdbtransport.User{
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
	f.accounts = append(f.accounts, &qrdbtransport.User{
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
	update := f.users.updateUser
	failed := false
	f.users.updateUser = func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
		if !failed && req.Lifecycle == string(qrdbsdk.LifecycleActive) {
			failed = true
			return nil, errors.New("injected: activation not committed")
		}
		return update(ctx, req)
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
	f.accounts = append(f.accounts, &qrdbtransport.User{
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
		Subject:      pkix.Name{CommonName: "invitee PIV cert"},
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

// TestActivateInvitePIV_RefusedWhileWebAuthnFinishActivates: a WebAuthn
// finish that saved its passkey but has not yet activated the account holds
// the account's first-credential claim, so a PIV activation of the same
// invitation in that window is refused and binds nothing.
func TestActivateInvitePIV_RefusedWhileWebAuthnFinishActivates(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)
	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	bindings := 0
	bind := f.users.addCertBinding
	f.users.addCertBinding = func(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
		bindings++
		return bind(ctx, userID, thumbprint, notAfterUnix)
	}
	var pivErr error
	pivRan := false
	update := f.users.updateUser
	f.users.updateUser = func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
		if !pivRan {
			pivRan = true
			_, pivErr = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
		}
		return update(ctx, req)
	}

	begin, err := f.beginRegistration(inviteFixtureTenant, token)
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
	result, err := f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
	require.NoError(t, err)
	assert.Equal(t, inviteFixtureQRDBUserID, result.UserID)

	require.True(t, pivRan, "the PIV activation ran inside the WebAuthn activation")
	require.ErrorIs(t, pivErr, ErrInviteUnusable)
	assert.Zero(t, bindings, "the refused PIV activation bound no certificate")
}

// TestActivateInvitePIV_CommitOutcomeUnknownKeepsTheClaim pins the Codex
// round-2 P1 on servicer_invite.go: qrdb's ActivateWithCertBinding can commit
// and then return CommitOutcomeUnknownError (its reconciliation read failed).
// The PIV activation must not release the first-credential claim on that
// error: a WebAuthn finish that began before it must not claim afresh and
// enrol a passkey on the now certificate-bound account. Whether the service's
// own reconciliation read succeeds (the account is active: commit the claim)
// or fails too (outcome still unknown: keep the fence), the finish is refused.
func TestActivateInvitePIV_CommitOutcomeUnknownKeepsTheClaim(t *testing.T) {
	for _, readFails := range []bool{false, true} {
		name := "reconciled"
		if readFails {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			f := newInviteFixture(t)
			token := f.mintInvite(t)
			caCert, leafCert, err := generateInvitePIVChain(t)
			require.NoError(t, err)
			f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

			inPIV, committed := false, false
			update := f.users.updateUser
			f.users.updateUser = func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
				u, err := update(ctx, req)
				if inPIV && err == nil && req.Lifecycle == string(qrdbsdk.LifecycleActive) {
					committed = true
					return nil, &qrdbuser.CommitOutcomeUnknownError{ID: req.ID, Err: errors.New("injected: reconciliation read failed")}
				}
				return u, err
			}
			// The PIV activation runs inside the finish's first account
			// read: the finish has seen the account pending and goes on to
			// claim, as an already-running finish would.
			var pivErr error
			inFinish, pivRan := false, false
			get := f.users.getUser
			f.users.getUser = func(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
				if inPIV && committed && readFails {
					return nil, errors.New("injected: read failed")
				}
				u, err := get(ctx, id)
				if inFinish && !pivRan && err == nil {
					pivRan = true
					snapshot := *u
					inPIV = true
					_, pivErr = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
					inPIV = false
					return &snapshot, nil
				}
				return u, err
			}

			begin, err := f.beginRegistration(inviteFixtureTenant, token)
			require.NoError(t, err)
			attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
			inFinish = true
			_, err = f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
			inFinish = false

			require.True(t, pivRan, "the PIV activation ran inside the WebAuthn finish")
			require.True(t, committed, "the PIV activation committed")
			require.Error(t, pivErr, "an unknown commit outcome is not a success")
			require.Error(t, err, "the WebAuthn finish must not enrol a passkey on the certificate-bound account")
		})
	}
}

// TestActivateInvitePIV_RecoveredClaimFencesTheCertBinding is Codex round-3
// P1 1: a PIV request claims the first credential and stalls before its
// certificate-binding commit; its ten-minute lease runs out (controlled
// clock), another ceremony recovers the claim while the account is pending,
// saves and commits a passkey and pauses before activation. The stalled PIV
// request then resumes. Having lost the claim, it must not bind its
// certificate: one invitation must never enrol both credentials.
func TestActivateInvitePIV_RecoveredClaimFencesTheCertBinding(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)
	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	// The WebAuthn side runs on a lease clock the test moves.
	now := time.Now()
	waUsers, waCreds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:      f.users,
		DAOFactory: testutil.NewMemoryDAOFactory(),
		TenantID:   webauthntest.TenantID,
		Clock:      func() time.Time { return now },
	})
	require.NoError(t, err)
	waSvc, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          f.rp.ID,
			RPDisplayName: f.rp.Name,
			RPOrigins:     []string{f.rp.Origin},
		},
		UserStore:       waUsers,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: waCreds,
	})
	require.NoError(t, err)
	f.svc.SetWebAuthn(waSvc)

	var (
		inPIV, inFinish         bool
		finishRan, pivCommitted bool
		pivReq                  *qrdbtransport.UpdateUserRequest
		pivUser                 *qrdbtransport.User
		pivCommitErr            error
		finishErr               error
	)
	update := f.users.updateUser
	f.users.updateUser = func(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
		active := req.Lifecycle == string(qrdbsdk.LifecycleActive)
		switch {
		case inPIV && active && !finishRan:
			// The PIV request stalls before its certificate-binding
			// commit, past its claim's lease; another ceremony runs.
			finishRan, inPIV, pivReq = true, false, req
			now = now.Add(11 * time.Minute)
			begin, err := f.beginRegistration(inviteFixtureTenant, token)
			if err != nil {
				finishErr = err
			} else {
				attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
				inFinish = true
				_, finishErr = f.finishRegistration(inviteFixtureTenant, token, begin.SessionID, attestation)
				inFinish = false
			}
			if !pivCommitted {
				return update(ctx, req)
			}
			return pivUser, pivCommitErr
		case inFinish && active && !pivCommitted:
			// The recovering ceremony saved and committed its passkey
			// and pauses before activation: the stalled PIV request
			// resumes and commits now.
			pivCommitted = true
			pivUser, pivCommitErr = update(ctx, pivReq)
		}
		return update(ctx, req)
	}

	inPIV = true
	_, pivErr := f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	inPIV = false

	require.True(t, finishRan, "the PIV request stalled and another ceremony ran")
	require.NoError(t, finishErr, "the expired claim was recovered and the passkey enrolled")
	passkeys, err := waCreds.GetByUserID(context.Background(), webauthn.HandleFromUserID(inviteFixtureQRDBUserID))
	require.NoError(t, err)
	require.NotEmpty(t, passkeys, "the recovering ceremony saved its passkey")
	pivBound := pivCommitted && pivCommitErr == nil
	require.False(t, pivBound, "a PIV request that lost its claim must not bind its certificate: the invitation enrolled both a certificate and a passkey (PIV result: %v)", pivErr)
}

// TestActivateInvitePIV_RefusedAfterFailedWebAuthnActivation: once a
// WebAuthn finish stored the account's passkey, a PIV activation cannot
// sidestep the WebAuthn resume's possession proof.
func TestActivateInvitePIV_RefusedAfterFailedWebAuthnActivation(t *testing.T) {
	f := newInviteFixture(t)
	token := f.mintInvite(t)
	f.enrolThenFailActivation(t, token)

	caCert, leafCert, err := generateInvitePIVChain(t)
	require.NoError(t, err)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	_, err = f.activatePIV(inviteFixtureTenant, token, pemEncodeCert(leafCert))
	require.ErrorIs(t, err, ErrInviteUnusable)
	f.requirePendingUnredeemed(t, token, inviteFixtureQRDBUserID)
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
