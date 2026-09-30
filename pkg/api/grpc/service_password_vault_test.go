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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
)

// The personal-vault RPCs driven through a real XKMSService over a real
// TenantPasswordStoreManager and BarrierRegistry
// (newTenantPasswordGRPCService).

// vaultTenant is the tenant the vault tests act in.
const vaultTenant = "tenant-1"

// vaultPassphrase is the passphrase the vault tests enroll.
const vaultPassphrase = "correct horse battery staple"

// vaultUserCtx returns a context carrying subject's identity in vaultTenant.
func vaultUserCtx(subject string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: subject, TenantID: vaultTenant})
}

// testPasskey returns subject's test passkey on the wire.
func testPasskey(subject string) *pb.PasswordVaultCredential {
	return pbconv.VaultCredentialToPB(vaulttest.Passkey(subject))
}

// passphraseCredential returns a passphrase credential.
func passphraseCredential(passphrase string) *pb.PasswordVaultCredential {
	return &pb.PasswordVaultCredential{Factor: "passphrase", Passphrase: passphrase}
}

// enrollPasskey enrolls cred on the caller's vault and returns the result.
func enrollPasskey(t *testing.T, svc *Service, ctx context.Context, cred *pb.PasswordVaultCredential) *pb.PasswordVaultEnrollResponse {
	t.Helper()
	resp, err := svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: cred})
	require.NoError(t, err)
	return resp
}

// lockVault closes the caller's session.
func lockVault(t *testing.T, svc *Service, ctx context.Context) {
	t.Helper()
	_, err := svc.PasswordStoreLock(ctx, &pb.PasswordStoreLockRequest{})
	require.NoError(t, err)
}

// unlockVault opens the caller's session with cred and returns the error.
func unlockVault(svc *Service, ctx context.Context, cred *pb.PasswordVaultCredential) error {
	_, err := svc.PasswordStoreUnlock(ctx, &pb.PasswordStoreUnlockRequest{Credential: cred})
	return err
}

func TestPasswordVault_PassphraseLifecycle(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)

	status0, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	require.NoError(t, err)
	assert.False(t, status0.Initialized)
	assert.False(t, status0.Unlocked)

	enrolled, err := svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: passphraseCredential(vaultPassphrase)})
	require.NoError(t, err)
	assert.NotEmpty(t, enrolled.RecoveryCode, "the first enrollment issues the recovery code")
	assert.Equal(t, "passphrase", enrolled.Factor.Factor)
	assert.NotEmpty(t, enrolled.Factor.Id)

	status1, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	require.NoError(t, err)
	assert.True(t, status1.Initialized)
	assert.True(t, status1.Unlocked, "the first enrollment opens the session")

	lockVault(t, svc, ctx)
	assert.Equal(t, codes.Unauthenticated, status.Code(unlockVault(svc, ctx, passphraseCredential("not the passphrase"))))
	require.NoError(t, unlockVault(svc, ctx, passphraseCredential(vaultPassphrase)))
}

func TestPasswordVault_PasskeyEnrollAndUnlock(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	passkey := testPasskey("test-user")
	enrolled := enrollPasskey(t, svc, ctx, passkey)
	assert.NotEmpty(t, enrolled.RecoveryCode)
	assert.Equal(t, passkey.CredentialId, enrolled.Factor.CredentialId)

	// Status reports what a client needs to evaluate hmac-secret.
	vault, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	require.NoError(t, err)
	var found bool
	for _, f := range vault.Factors {
		if f.Factor == "passkey" {
			found = true
			assert.Equal(t, passkey.CredentialId, f.CredentialId)
			assert.Equal(t, passkey.PrfSalt, f.PrfSalt)
		}
	}
	assert.True(t, found, "the passkey is listed")

	lockVault(t, svc, ctx)
	wrong := testPasskey("test-user")
	wrong.Secret = make([]byte, 32)
	assert.Equal(t, codes.Unauthenticated, status.Code(unlockVault(svc, ctx, wrong)))

	// Unlocking needs only the credential ID and the PRF output.
	require.NoError(t, unlockVault(svc, ctx, &pb.PasswordVaultCredential{
		Factor: "passkey", CredentialId: passkey.CredentialId, Secret: passkey.Secret,
	}))
}

func TestPasswordVault_EnrollErrors(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)

	_, err := svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: passphraseCredential("short")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a passphrase under the minimum length")

	enrollPasskey(t, svc, ctx, testPasskey("test-user"))
	_, err = svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: testPasskey("test-user")})
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "the same passkey twice")

	lockVault(t, svc, ctx)
	_, err = svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: testPasskey("another-key")})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "a later enrollment needs the session open")

	_, err = svc.PasswordVaultEnroll(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestPasswordVault_Rotate(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	enrolled := enrollPasskey(t, svc, ctx, testPasskey("test-user"))

	rotated := testPasskey("test-user")
	rotated.Secret = []byte("0123456789abcdef0123456789abcdef")
	resp, err := svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: enrolled.Factor.Id, Credential: rotated})
	require.NoError(t, err)
	assert.Empty(t, resp.RecoveryCode, "a rotation issues no recovery code")

	lockVault(t, svc, ctx)
	assert.Equal(t, codes.Unauthenticated, status.Code(unlockVault(svc, ctx, testPasskey("test-user"))), "the old secret stops working")
	require.NoError(t, unlockVault(svc, ctx, rotated))

	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: "no-such-factor", Credential: rotated})
	assert.Equal(t, codes.NotFound, status.Code(err))

	current := resp.Factor.Id
	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: current, Credential: passphraseCredential(vaultPassphrase)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a rotation keeps the factor type")

	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{Credential: rotated})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "factor_id is required")

	lockVault(t, svc, ctx)
	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: current, Credential: rotated})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "rotation needs the session open")
}

func TestPasswordVault_RemoveFactor(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	first := enrollPasskey(t, svc, ctx, testPasskey("key-one"))
	second := enrollPasskey(t, svc, ctx, testPasskey("key-two"))

	_, err := svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: second.Factor.Id})
	require.NoError(t, err)

	_, err = svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: first.Factor.Id})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "the last factor cannot be removed")

	_, err = svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: second.Factor.Id})
	assert.Equal(t, codes.NotFound, status.Code(err), "a removed factor is gone")

	_, err = svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "factor_id is required")

	lockVault(t, svc, ctx)
	assert.Equal(t, codes.Unauthenticated, status.Code(unlockVault(svc, ctx, testPasskey("key-two"))), "the removed passkey no longer unlocks")
}

func TestPasswordVault_RecoverIsOneTime(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)
	enrolled := enrollPasskey(t, svc, ctx, testPasskey("lost-key"))
	lockVault(t, svc, ctx)

	recovered, err := svc.PasswordVaultRecover(ctx, &pb.PasswordVaultRecoverRequest{
		RecoveryCode: enrolled.RecoveryCode,
		Credential:   testPasskey("new-key"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, enrolled.RecoveryCode, recovered.RecoveryCode, "recovery replaces the code")

	vault, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	require.NoError(t, err)
	assert.True(t, vault.Unlocked, "recovery opens the session")

	lockVault(t, svc, ctx)
	_, err = svc.PasswordVaultRecover(ctx, &pb.PasswordVaultRecoverRequest{
		RecoveryCode: enrolled.RecoveryCode,
		Credential:   testPasskey("third-key"),
	})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "a used recovery code is spent")

	require.NoError(t, unlockVault(svc, ctx, testPasskey("new-key")))
}

// One user's vault operations never read or change another user's vault.
func TestPasswordVault_UsersAreIsolated(t *testing.T) {
	svc, alice := newTenantPasswordGRPCService(t)
	bob := vaultUserCtx("bob")
	aliceFactor := enrollPasskey(t, svc, alice, testPasskey("test-user"))

	bobVault, err := svc.PasswordVaultStatus(bob, &pb.PasswordVaultStatusRequest{})
	require.NoError(t, err)
	assert.False(t, bobVault.Initialized, "Alice's enrollment does not initialize Bob's vault")

	assert.Equal(t, codes.FailedPrecondition, status.Code(unlockVault(svc, bob, testPasskey("test-user"))),
		"Alice's passkey is not a factor of Bob's vault")

	enrollPasskey(t, svc, bob, testPasskey("bob"))
	_, err = svc.PasswordVaultRemoveFactor(bob, &pb.PasswordVaultRemoveFactorRequest{FactorId: aliceFactor.Factor.Id})
	assert.Equal(t, codes.NotFound, status.Code(err), "Bob cannot address Alice's factor")

	lockVault(t, svc, alice)
	require.NoError(t, unlockVault(svc, alice, testPasskey("test-user")))
}

// A request without an identity has no personal vault.
func TestPasswordVault_NoIdentityIsUnimplemented(t *testing.T) {
	svc, _ := newTenantPasswordGRPCService(t)
	ctx := context.Background()

	_, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{Credential: testPasskey("x")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: "f", Credential: testPasskey("x")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: "f"})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = svc.PasswordVaultRecover(ctx, &pb.PasswordVaultRecoverRequest{RecoveryCode: "c", Credential: testPasskey("x")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestPasswordVault_NotConfiguredIsUnavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	ctx := vaultUserCtx("test-user")

	_, err := svc.PasswordVaultStatus(ctx, &pb.PasswordVaultStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = svc.PasswordVaultEnroll(ctx, &pb.PasswordVaultEnrollRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = svc.PasswordVaultRotate(ctx, &pb.PasswordVaultRotateRequest{FactorId: "f"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = svc.PasswordVaultRemoveFactor(ctx, &pb.PasswordVaultRemoveFactorRequest{FactorId: "f"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = svc.PasswordVaultRecover(ctx, &pb.PasswordVaultRecoverRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestPasswordVault_NilRequestsAreInvalid(t *testing.T) {
	svc, ctx := newTenantPasswordGRPCService(t)

	_, err := svc.PasswordVaultRotate(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.PasswordVaultRemoveFactor(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.PasswordVaultRecover(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
