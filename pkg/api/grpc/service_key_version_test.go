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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// keyVersionServer serves the real Service over a real XKMSService (one
// software backend and an in-memory version store) on an in-memory gRPC
// connection, and returns the generated client for it.
func keyVersionServer(t *testing.T) (*Service, pb.KeystoreServiceClient) {
	t.Helper()
	service := setupServiceTest(t)
	t.Cleanup(xkms.Reset)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, service)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return service, pb.NewKeystoreServiceClient(conn)
}

// genRotated generates an ECDSA key over RPC and rotates it once.
func genRotated(t *testing.T, client pb.KeystoreServiceClient, keyID string) {
	t.Helper()
	ctx := context.Background()
	_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: keyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	rotated, err := client.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: keyID, Backend: "software"})
	require.NoError(t, err)
	require.Equal(t, uint32(2), rotated.GetKeyVersion())
}

// TestKeyVersionRPCs_EndToEnd drives every key-version RPC through the
// shared pbconv.KeyVersionClient against the real server: listing, the
// state changes, retirement and a scope rotation, with the key_version
// fields of sign and verify on the wire.
func TestKeyVersionRPCs_EndToEnd(t *testing.T) {
	_, client := keyVersionServer(t)
	ctx := context.Background()
	kv := pbconv.KeyVersionClient{Client: client}

	_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	oldSig, err := client.Sign(ctx, &pb.SignRequest{KeyId: "k", Backend: "software", Data: []byte("d")})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), oldSig.GetKeyVersion())
	_, err = client.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)

	verified, err := client.Verify(ctx, &pb.VerifyRequest{KeyId: "k", Backend: "software", Data: []byte("d"), Signature: oldSig.GetSignature()})
	require.NoError(t, err)
	assert.True(t, verified.GetValid())
	assert.Equal(t, uint32(1), verified.GetKeyVersion())

	listed, err := kv.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), listed.CurrentVersion)
	require.Len(t, listed.Versions, 2)
	assert.True(t, listed.Versions[1].Current)
	assert.NotEmpty(t, listed.Versions[0].PublicKeyPEM)

	disabled, err := kv.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionDisabled, disabled.State)
	assert.True(t, disabled.Changed)
	enabled, err := kv.EnableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionEnabled, enabled.State)

	all, err := kv.DisableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, []uint32{1}, all.Versions)
	all, err = kv.EnableAllKeyVersions(ctx, &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "k"})
	require.NoError(t, err)
	assert.Equal(t, 1, all.Count)

	retired, err := kv.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyVersionRetired, retired.State)

	scope, err := kv.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, scope.Rotated)
	require.Len(t, scope.Results, 1)
	assert.Equal(t, uint32(3), scope.Results[0].KeyVersion)
}

// TestKeyVersionRPCs_MapErrors proves each key-version refusal reaches the
// wire with its class's code.
func TestKeyVersionRPCs_MapErrors(t *testing.T) {
	service, client := keyVersionServer(t)
	ctx := context.Background()
	genRotated(t, client, "k")

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"disable current", func() error {
			_, err := client.DisableKeyVersion(ctx, &pb.DisableKeyVersionRequest{KeyId: "k", Backend: "software", Version: 2})
			return err
		}, codes.FailedPrecondition},
		{"retire current", func() error {
			_, err := client.RetireKeyVersion(ctx, &pb.RetireKeyVersionRequest{KeyId: "k", Backend: "software", Version: 2})
			return err
		}, codes.FailedPrecondition},
		{"unknown version", func() error {
			_, err := client.EnableKeyVersion(ctx, &pb.EnableKeyVersionRequest{KeyId: "k", Backend: "software", Version: 9})
			return err
		}, codes.NotFound},
		{"negative version", func() error {
			_, err := client.EnableKeyVersion(ctx, &pb.EnableKeyVersionRequest{KeyId: "k", Backend: "software", Version: -1})
			return err
		}, codes.InvalidArgument},
		{"missing key", func() error {
			_, err := client.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{KeyId: "ghost", Backend: "software"})
			return err
		}, codes.NotFound},
		{"version name", func() error {
			_, err := client.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{KeyId: "k--v2", Backend: "software"})
			return err
		}, codes.InvalidArgument},
		{"reserved key ID", func() error {
			_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "x--v3", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
			return err
		}, codes.InvalidArgument},
		{"cbc without key_version", func() error {
			_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "aes", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"})
			require.NoError(t, err)
			enc, err := client.Encrypt(ctx, &pb.EncryptRequest{KeyId: "aes", Backend: "software", Plaintext: []byte("0123456789abcdef"), Mode: "cbc-pad"})
			require.NoError(t, err)
			_, err = client.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "aes", Backend: "software"})
			require.NoError(t, err)
			_, err = client.Decrypt(ctx, &pb.DecryptRequest{KeyId: "aes", Backend: "software", Ciphertext: enc.GetCiphertext(), Iv: enc.GetIv(), Mode: "cbc-pad"})
			return err
		}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err)
			assert.Equal(t, tt.code, status.Code(err), err.Error())
		})
	}

	// Without a version store the version operations are unavailable.
	service.xkmsService.SetKeyVersionStore(nil)
	_, err := client.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "k", Backend: "software"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestKeyVersionRPCs_TenantBinding proves a tenant caller rotates only its
// own tenant: naming another in RotateScopeKeys reads as not found.
func TestKeyVersionRPCs_TenantBinding(t *testing.T) {
	service, _ := keyVersionServer(t)
	acme := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u", TenantID: "acme"})

	_, err := service.RotateScopeKeys(acme, &pb.RotateScopeKeysRequest{TenantId: "globex"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	resp, err := service.RotateScopeKeys(acme, &pb.RotateScopeKeysRequest{})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.GetTenantId())
	assert.Empty(t, resp.GetResults())
}

// TestKeyVersionRPCs_NilService proves every key-version RPC answers
// Unavailable, not a panic, when no service is wired.
func TestKeyVersionRPCs_NilService(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	calls := map[string]func() error{
		"list":        func() error { _, err := s.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{}); return err },
		"enable":      func() error { _, err := s.EnableKeyVersion(ctx, &pb.EnableKeyVersionRequest{}); return err },
		"disable":     func() error { _, err := s.DisableKeyVersion(ctx, &pb.DisableKeyVersionRequest{}); return err },
		"retire":      func() error { _, err := s.RetireKeyVersion(ctx, &pb.RetireKeyVersionRequest{}); return err },
		"enable-all":  func() error { _, err := s.EnableAllKeyVersions(ctx, &pb.EnableAllKeyVersionsRequest{}); return err },
		"disable-all": func() error { _, err := s.DisableAllKeyVersions(ctx, &pb.DisableAllKeyVersionsRequest{}); return err },
		"rotate-all":  func() error { _, err := s.RotateScopeKeys(ctx, &pb.RotateScopeKeysRequest{}); return err },
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}
