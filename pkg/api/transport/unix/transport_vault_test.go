// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The personal-vault methods over the bufconn harness. The mock server
// (mockKeystoreServer) echoes what it received into its answers, so each
// test proves the request reached the server intact and the answer came
// back intact.

// vaultTestFactorID is the one factor ID the mock server knows.
const vaultTestFactorID = "factor-1"

// PasswordVaultStatus answers a fixed vault with one passkey.
func (s *mockKeystoreServer) PasswordVaultStatus(_ context.Context, _ *pb.PasswordVaultStatusRequest) (*pb.PasswordVaultStatusResponse, error) {
	return &pb.PasswordVaultStatusResponse{
		Initialized: true,
		Unlocked:    true,
		Factors: []*pb.PasswordVaultFactor{{
			Id: vaultTestFactorID, Factor: "passkey", Label: "key", CreatedAt: "2026-01-02T03:04:05Z",
			CredentialId: []byte("cred"), PrfSalt: []byte("salt"),
		}},
	}, nil
}

// PasswordVaultEnroll echoes the credential into the enrolled factor.
func (s *mockKeystoreServer) PasswordVaultEnroll(_ context.Context, req *pb.PasswordVaultEnrollRequest) (*pb.PasswordVaultEnrollResponse, error) {
	cred := req.GetCredential()
	if cred.GetFactor() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential is required")
	}
	return &pb.PasswordVaultEnrollResponse{
		Factor: &pb.PasswordVaultFactor{
			Id: vaultTestFactorID, Factor: cred.GetFactor(), Label: cred.GetLabel(),
			CredentialId: cred.GetCredentialId(), PrfSalt: cred.GetPrfSalt(),
		},
		RecoveryCode: "code-" + cred.GetPassphrase() + string(cred.GetSecret()),
	}, nil
}

// PasswordVaultRotate knows only vaultTestFactorID.
func (s *mockKeystoreServer) PasswordVaultRotate(_ context.Context, req *pb.PasswordVaultRotateRequest) (*pb.PasswordVaultEnrollResponse, error) {
	if req.GetFactorId() != vaultTestFactorID {
		return nil, status.Error(codes.NotFound, "vault factor not found")
	}
	return &pb.PasswordVaultEnrollResponse{
		Factor: &pb.PasswordVaultFactor{Id: "factor-2", Factor: req.GetCredential().GetFactor()},
	}, nil
}

// PasswordVaultRemoveFactor knows only vaultTestFactorID.
func (s *mockKeystoreServer) PasswordVaultRemoveFactor(_ context.Context, req *pb.PasswordVaultRemoveFactorRequest) (*pb.PasswordVaultRemoveFactorResponse, error) {
	if req.GetFactorId() != vaultTestFactorID {
		return nil, status.Error(codes.NotFound, "vault factor not found")
	}
	return &pb.PasswordVaultRemoveFactorResponse{}, nil
}

// PasswordVaultRecover accepts only the recovery code "code-1".
func (s *mockKeystoreServer) PasswordVaultRecover(_ context.Context, req *pb.PasswordVaultRecoverRequest) (*pb.PasswordVaultEnrollResponse, error) {
	if req.GetRecoveryCode() != "code-1" {
		return nil, status.Error(codes.Unauthenticated, "credential rejected")
	}
	return &pb.PasswordVaultEnrollResponse{
		Factor:       &pb.PasswordVaultFactor{Id: "factor-3", Factor: req.GetCredential().GetFactor()},
		RecoveryCode: "code-2",
	}, nil
}

func TestPasswordVaultStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordVaultStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.Initialized)
	assert.True(t, resp.Unlocked)
	require.Len(t, resp.Factors, 1)
	assert.Equal(t, transport.PasswordVaultFactor{
		ID: vaultTestFactorID, Factor: "passkey", Label: "key", CreatedAt: "2026-01-02T03:04:05Z",
		CredentialID: []byte("cred"), PRFSalt: []byte("salt"),
	}, resp.Factors[0])
}

func TestPasswordVaultEnroll_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordVaultEnroll(context.Background(), &transport.PasswordVaultEnrollRequest{
		PasswordVaultCredential: transport.PasswordVaultCredential{
			Factor: "passkey", CredentialID: []byte("cred"), PRFSalt: []byte("salt"), Secret: []byte("prf"), Label: "key",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "code-prf", resp.RecoveryCode, "the secret reached the server")
	assert.Equal(t, "passkey", resp.Factor.Factor)
	assert.Equal(t, "key", resp.Factor.Label)
	assert.Equal(t, []byte("cred"), resp.Factor.CredentialID)
	assert.Equal(t, []byte("salt"), resp.Factor.PRFSalt)
}

func TestPasswordVaultEnroll_ServerRejects(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	_, err := tr.PasswordVaultEnroll(context.Background(), &transport.PasswordVaultEnrollRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = tr.PasswordVaultEnroll(context.Background(), nil)
	assert.Error(t, err)
}

func TestPasswordVaultRotate_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordVaultRotate(context.Background(), &transport.PasswordVaultRotateRequest{
		FactorID:                vaultTestFactorID,
		PasswordVaultCredential: transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "correct horse"},
	})
	require.NoError(t, err)
	assert.Equal(t, "factor-2", resp.Factor.ID)
	assert.Equal(t, "passphrase", resp.Factor.Factor)

	_, err = tr.PasswordVaultRotate(context.Background(), &transport.PasswordVaultRotateRequest{FactorID: "other"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestPasswordVaultRemoveFactor_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	require.NoError(t, tr.PasswordVaultRemoveFactor(context.Background(), &transport.PasswordVaultRemoveFactorRequest{FactorID: vaultTestFactorID}))

	err := tr.PasswordVaultRemoveFactor(context.Background(), &transport.PasswordVaultRemoveFactorRequest{FactorID: "other"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestPasswordVaultRecover_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordVaultRecover(context.Background(), &transport.PasswordVaultRecoverRequest{
		RecoveryCode:            "code-1",
		PasswordVaultCredential: transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "correct horse"},
	})
	require.NoError(t, err)
	assert.Equal(t, "code-2", resp.RecoveryCode)
	assert.Equal(t, "passphrase", resp.Factor.Factor)

	_, err = tr.PasswordVaultRecover(context.Background(), &transport.PasswordVaultRecoverRequest{RecoveryCode: "spent"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestPasswordVault_NotConnected(t *testing.T) {
	tr := &Transport{}
	ctx := context.Background()

	_, err := tr.PasswordVaultStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.ErrorIs(t, tr.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{}), ErrNotConnected)
	_, err = tr.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPasswordGenerate_CharsetCrossesTheWire(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.PasswordGenerate(context.Background(), &transport.PasswordGenerateRequest{Length: 16, Charset: "alphanumeric"})
	require.NoError(t, err)
	assert.Equal(t, "alphanumeric", resp.Password)
}

func TestPasswordStoreUnlock_CredentialCrossesTheWire(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	err := tr.PasswordStoreUnlock(context.Background(), &transport.PasswordStoreUnlockRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an empty credential reaches the server as empty")
}
