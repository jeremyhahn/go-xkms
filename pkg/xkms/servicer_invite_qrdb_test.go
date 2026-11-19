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
	"errors"
	"math/big"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
)

// qrdbNodeInviteUsers is the embedded node's user service as
// pkg/server's nodeInviteUsers hands it to invitation redemption: the
// node's UserServicer, with the conditional first-credential activation
// qrdb's tenant-routed service implements (qrdbuser.CertActivator).
type qrdbNodeInviteUsers struct{ qrdbuser.UserServicer }

func (u qrdbNodeInviteUsers) ActivateWithCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbsdk.User, error) {
	activator, ok := u.UserServicer.(qrdbuser.CertActivator)
	if !ok {
		return nil, errors.New("node user service does not implement qrdbuser.CertActivator")
	}
	return activator.ActivateWithCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

const pivInviteRaceChildEnv = "XKMS_PIV_INVITE_RACE_CHILD"

// TestActivateInvitePIV_ConcurrentRedemptionBindsOneCertificate pins the
// Codex round-4 P1 on servicer_invite.go (ruling 952): concurrent
// redemptions of ONE PIV invitation, each with its own CA-chained
// certificate, against the real qrdb user store, activate the account
// once with exactly one certificate binding. Every loser gets the opaque
// ErrInviteUnusable and leaves no binding behind. It runs in a child
// process, as the other standalone-node tests do.
func TestActivateInvitePIV_ConcurrentRedemptionBindsOneCertificate(t *testing.T) {
	if os.Getenv(pivInviteRaceChildEnv) == "1" {
		concurrentPIVRedemption(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestActivateInvitePIV_ConcurrentRedemptionBindsOneCertificate$", "-test.count=1")
	cmd.Env = append(os.Environ(), pivInviteRaceChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "concurrent PIV redemption child process failed:\n%s", out)
}

func concurrentPIVRedemption(t *testing.T) {
	ctx := context.Background()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(ctx, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	users := node.UserService()
	sysCtx := qrdbsdk.ContextWithTenant(ctx, inviteFixtureTenant)
	account, err := users.CreateUser(sysCtx, &qrdbuser.CreateUserRequest{
		Username: "piv-invitee", Email: "piv-invitee@example.com", Name: "PIV Invitee",
		TenantID: inviteFixtureTenant, Pending: true,
	})
	require.NoError(t, err)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	svc.SetInviteUserService(qrdbNodeInviteUsers{UserServicer: users})
	inviteStore, err := invitetest.New(singleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(inviteStore)

	const n = 16
	caCert, leaves := generateInvitePIVLeaves(t, n)
	svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})
	info, err := svc.createInvite(ctx, inviteFixtureTenant, account.ID, time.Hour)
	require.NoError(t, err)

	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = svc.ActivateInvitePIV(ctx, &xkmstransport.ActivateInvitePIVRequest{
				TenantID: inviteFixtureTenant, Token: info.Token, CertPEM: string(pemEncodeCert(leaves[i])),
			})
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, err := range errs {
		if err == nil {
			assert.Equal(t, -1, winner, "redemptions %d and %d both succeeded", winner, i)
			winner = i
			continue
		}
		assert.ErrorIs(t, err, ErrInviteUnusable, "redemption %d lost but did not get ErrInviteUnusable", i)
	}
	require.NotEqual(t, -1, winner, "no redemption succeeded")

	got, err := users.GetUser(sysCtx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecycleActive, got.Lifecycle)
	require.Len(t, got.CertBindings, 1, "exactly one certificate is bound")
	assert.True(t, got.HasCertBinding(qrdbsdk.ComputeSPKIThumbprint(leaves[winner])), "the binding is the winner's certificate")

	_, err = svc.GetInvite(ctx, &xkmstransport.GetInviteRequest{TenantID: inviteFixtureTenant, Token: info.Token})
	require.ErrorIs(t, err, ErrInviteUnusable, "the invitation is spent")
}

// generateInvitePIVLeaves returns one CA and n ClientAuth leaves it issued,
// each over its own key.
func generateInvitePIVLeaves(t *testing.T, n int) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms test invite race CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaves := make([]*x509.Certificate, n)
	for i := range leaves {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: "invitee PIV cert"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
		require.NoError(t, err)
		leaves[i], err = x509.ParseCertificate(leafDER)
		require.NoError(t, err)
	}
	return caCert, leaves
}

const inviteDisableRaceChildEnv = "XKMS_INVITE_DISABLE_RACE_CHILD"

// disableBeforeActivationUsers is the embedded node's user service with an
// administrator's disable injected at the activation call: after the
// WebAuthn ceremony was validated (and its lifecycle check passed) and
// before the activation reaches the store.
type disableBeforeActivationUsers struct {
	qrdbNodeInviteUsers
	fired bool
}

func (u *disableBeforeActivationUsers) UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error) {
	if !u.fired && req.Lifecycle == qrdbsdk.LifecycleActive {
		u.fired = true
		if _, err := u.UserServicer.UpdateUser(ctx, &qrdbsdk.UpdateUserRequest{ID: req.ID, Lifecycle: qrdbsdk.LifecycleDisabled}); err != nil {
			return nil, err
		}
	}
	return u.UserServicer.UpdateUser(ctx, req)
}

// TestFinishInviteRegistration_DisableDuringActivationStaysDisabled pins
// the Codex round-5 P1 on servicer_invite.go (ruling 968): an account an
// administrator disables after the invitation ceremony was validated and
// before the activation commits stays disabled on the real qrdb user
// store, the redemption fails, and the invitation is not spent. It runs in
// a child process, as the other standalone-node tests do.
func TestFinishInviteRegistration_DisableDuringActivationStaysDisabled(t *testing.T) {
	if os.Getenv(inviteDisableRaceChildEnv) == "1" {
		disableDuringInviteActivation(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFinishInviteRegistration_DisableDuringActivationStaysDisabled$", "-test.count=1")
	cmd.Env = append(os.Environ(), inviteDisableRaceChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "disable-during-activation child process failed:\n%s", out)
}

func disableDuringInviteActivation(t *testing.T) {
	ctx := context.Background()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(ctx, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	users := node.UserService()
	sysCtx := qrdbsdk.ContextWithTenant(ctx, inviteFixtureTenant)
	account, err := users.CreateUser(sysCtx, &qrdbuser.CreateUserRequest{
		Username: inviteFixtureEmail, Email: inviteFixtureEmail, Name: "Invitee",
		TenantID: inviteFixtureTenant, Pending: true,
	})
	require.NoError(t, err)

	// The WebAuthn side reads the fixture's accounts: give the fixture's
	// pending account the real account's ID so both sides name one account.
	f := newInviteFixture(t)
	f.accounts[0].ID = account.ID
	f.svc.SetInviteUserService(&disableBeforeActivationUsers{qrdbNodeInviteUsers: qrdbNodeInviteUsers{UserServicer: users}})
	info, err := f.svc.createInvite(ctx, inviteFixtureTenant, account.ID, f.inviteTTL)
	require.NoError(t, err)

	begin, err := f.beginRegistration(inviteFixtureTenant, info.Token)
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))
	_, err = f.finishRegistration(inviteFixtureTenant, info.Token, begin.SessionID, attestation)
	require.ErrorIs(t, err, ErrInviteUnusable, "an activation over a disabled account must be refused")

	got, err := users.GetUser(sysCtx, account.ID)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.LifecycleDisabled, got.Lifecycle, "the administrator's disable must stand")
	_, err = f.svc.inviteStore.Lookup(ctx, inviteFixtureTenant, info.Token)
	require.NoError(t, err, "a refused activation must not spend the invitation")
}
