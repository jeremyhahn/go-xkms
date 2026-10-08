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

	// qrdb side: mockUserClient tracks the pending account by qrdb id.
	qrdbUser := &qrdbtransport.User{
		ID: inviteFixtureQRDBUserID, Username: inviteFixtureEmail, Email: inviteFixtureEmail,
		Name: "Invitee", TenantID: inviteFixtureTenant, Lifecycle: string(qrdbsdk.LifecyclePending),
	}
	users := &mockUserClient{
		getUser: func(_ context.Context, id uint64) (*qrdbtransport.User, error) {
			if id != qrdbUser.ID {
				return nil, &qrdbtransport.UserNotFoundError{ID: id}
			}
			return qrdbUser, nil
		},
		getUserByEmail: func(_ context.Context, tenantID, email string) (*qrdbtransport.User, error) {
			if tenantID != qrdbUser.TenantID || email != qrdbUser.Email {
				return nil, &qrdbtransport.UserNotFoundError{Lookup: qrdbtransport.UserLookupKey(tenantID, email)}
			}
			return qrdbUser, nil
		},
		updateUser: func(_ context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
			if req.ID != qrdbUser.ID {
				return nil, &qrdbtransport.UserNotFoundError{ID: req.ID}
			}
			if req.Lifecycle != "" {
				qrdbUser.Lifecycle = req.Lifecycle
			}
			return qrdbUser, nil
		},
		addCertBinding: func(_ context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
			if userID != qrdbUser.ID {
				return nil, &qrdbtransport.UserNotFoundError{ID: userID}
			}
			return qrdbUser, nil
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

	return &inviteFixture{
		svc: svc, users: users,
		rp:        virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		inviteTTL: time.Hour,
	}
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
