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

package pbconv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func TestVaultCredential_RoundTrip(t *testing.T) {
	in := transport.PasswordVaultCredential{
		Factor: "passkey", Passphrase: "p", CredentialID: []byte("cred"),
		PRFSalt: []byte("salt"), Secret: []byte("secret"), Label: "key", RPID: "kms.example.com",
	}
	assert.Equal(t, in, VaultCredentialFromPB(VaultCredentialToPB(in)))

	key := transport.PasswordVaultCredential{
		Factor: "tpm", PublicKey: []byte("spki"), Certificate: []byte("cert"), KeyFingerprint: "ab12",
		Secret: []byte("secret"), KeyRef: transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "vault", TPMPolicy: "platform"},
	}
	assert.Equal(t, key, VaultCredentialFromPB(VaultCredentialToPB(key)), "every key-factor field crosses the wire")
	assert.Equal(t, transport.PasswordVaultCredential{}, VaultCredentialFromPB(nil), "a nil credential is the zero credential")
}

func TestVaultStatus_RoundTrip(t *testing.T) {
	in := &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Unlocked:    true,
		Factors: []transport.PasswordVaultFactor{
			{ID: "f1", Factor: "passphrase", Label: "pp", CreatedAt: "2026-01-02T03:04:05Z"},
			{ID: "f2", Factor: "passkey", CredentialID: []byte("cred"), PRFSalt: []byte("salt"), RPID: "kms.example.com"},
			{
				ID: "f3", Factor: "piv", KeyFingerprint: "ab12", KeyAlgorithm: "RSA-OAEP-256", KeyChallenge: []byte("ct"),
				KeyCheck: []byte("kcv"), KeyRef: transport.PasswordVaultKeyRef{Backend: "pkcs11", KeyID: "piv-9d"}, CertificateSubject: "CN=alice",
			},
		},
		PasskeyRPID: "kms.example.com",
	}
	assert.Equal(t, in, VaultStatusFromPB(VaultStatusToPB(in)))

	empty := VaultStatusFromPB(&pb.PasswordVaultStatusResponse{})
	assert.False(t, empty.Initialized)
	assert.NotNil(t, empty.Factors, "an empty vault lists no factors, not a nil list")
	assert.Empty(t, empty.Factors)
}

func TestVaultEnrollResponse_RoundTrip(t *testing.T) {
	in := &transport.PasswordVaultEnrollResponse{
		Factor:       transport.PasswordVaultFactor{ID: "f1", Factor: "passkey", CredentialID: []byte("cred")},
		RecoveryCode: "ABCD-EFGH",
	}
	assert.Equal(t, in, VaultEnrollResponseFromPB(VaultEnrollResponseToPB(in)))
	assert.Equal(t, &transport.PasswordVaultEnrollResponse{}, VaultEnrollResponseFromPB(&pb.PasswordVaultEnrollResponse{}))
}

// failingVaultClient answers every vault RPC with err.
type failingVaultClient struct {
	pb.KeystoreServiceClient
	err error
}

func (f failingVaultClient) PasswordVaultStatus(context.Context, *pb.PasswordVaultStatusRequest, ...grpc.CallOption) (*pb.PasswordVaultStatusResponse, error) {
	return nil, f.err
}
func (f failingVaultClient) PasswordVaultEnroll(context.Context, *pb.PasswordVaultEnrollRequest, ...grpc.CallOption) (*pb.PasswordVaultEnrollResponse, error) {
	return nil, f.err
}
func (f failingVaultClient) PasswordVaultRotate(context.Context, *pb.PasswordVaultRotateRequest, ...grpc.CallOption) (*pb.PasswordVaultEnrollResponse, error) {
	return nil, f.err
}
func (f failingVaultClient) PasswordVaultRemoveFactor(context.Context, *pb.PasswordVaultRemoveFactorRequest, ...grpc.CallOption) (*pb.PasswordVaultRemoveFactorResponse, error) {
	return nil, f.err
}
func (f failingVaultClient) PasswordVaultRecover(context.Context, *pb.PasswordVaultRecoverRequest, ...grpc.CallOption) (*pb.PasswordVaultEnrollResponse, error) {
	return nil, f.err
}

// TestPasswordVaultClient_Errors proves the client refuses a nil request
// before any RPC and returns the server's error unchanged.
func TestPasswordVaultClient_Errors(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("rpc failed")
	c := PasswordVaultClient{Client: failingVaultClient{err: rpcErr}}

	_, err := c.PasswordVaultStatus(ctx)
	require.ErrorIs(t, err, rpcErr)

	calls := map[string]struct{ nilReq, withReq func() error }{
		"enroll": {
			func() error { _, err := c.PasswordVaultEnroll(ctx, nil); return err },
			func() error {
				_, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{})
				return err
			},
		},
		"rotate": {
			func() error { _, err := c.PasswordVaultRotate(ctx, nil); return err },
			func() error {
				_, err := c.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{})
				return err
			},
		},
		"remove": {
			func() error { return c.PasswordVaultRemoveFactor(ctx, nil) },
			func() error { return c.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{}) },
		},
		"recover": {
			func() error { _, err := c.PasswordVaultRecover(ctx, nil); return err },
			func() error {
				_, err := c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{})
				return err
			},
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call.nilReq(), ErrNilRequest)
			require.ErrorIs(t, call.withReq(), rpcErr)
		})
	}
}
