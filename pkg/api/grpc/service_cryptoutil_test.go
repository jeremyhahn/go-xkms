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
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// cryptoUtilServer is keyVersionServer with two AES-GCM keys.
func cryptoUtilServer(t *testing.T) (*Service, pb.KeystoreServiceClient) {
	t.Helper()
	service, client := keyVersionServer(t)
	for _, req := range []*pb.GenerateKeyRequest{
		{KeyId: "aes", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"},
		{KeyId: "aes2", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"},
	} {
		_, err := client.GenerateKey(context.Background(), req)
		require.NoError(t, err)
	}
	return service, client
}

// decryptWith decrypts an encrypt result under keyID.
func decryptWith(t *testing.T, client pb.KeystoreServiceClient, keyID string, enc *pb.EncryptResponse) []byte {
	t.Helper()
	resp, err := client.Decrypt(context.Background(), &pb.DecryptRequest{
		KeyId: keyID, Backend: "software", Ciphertext: enc.GetCiphertext(), Nonce: enc.GetNonce(), Tag: enc.GetTag(),
		GcmNonceMode: enc.GetGcmNonceMode(), KeyVersion: enc.GetKeyVersion(),
	})
	require.NoError(t, err)
	return resp.GetPlaintext()
}

// TestCryptoUtilRPCs_EndToEnd drives every crypto utility verb over gRPC and
// checks each answer by the inverse operation.
func TestCryptoUtilRPCs_EndToEnd(t *testing.T) {
	_, client := cryptoUtilServer(t)
	ctx := context.Background()

	enc, err := client.Encrypt(ctx, &pb.EncryptRequest{KeyId: "aes", Backend: "software", Plaintext: []byte("secret")})
	require.NoError(t, err)
	rewrapped, err := client.Rewrap(ctx, &pb.RewrapRequest{
		Source: &pb.DecryptRequest{
			KeyId: "aes", Backend: "software", Ciphertext: enc.GetCiphertext(), Nonce: enc.GetNonce(), Tag: enc.GetTag(),
			GcmNonceMode: enc.GetGcmNonceMode(), KeyVersion: enc.GetKeyVersion(),
		},
		TargetKeyId: "aes2", TargetBackend: "software",
	})
	require.NoError(t, err)
	assert.Equal(t, enc.GetKeyVersion(), rewrapped.GetSourceKeyVersion())
	assert.Equal(t, []byte("secret"), decryptWith(t, client, "aes2", rewrapped.GetWrapped()))

	batch, err := client.EncryptBatch(ctx, &pb.EncryptBatchRequest{KeyId: "aes", Backend: "software", Items: []*pb.EncryptBatchItem{
		{Plaintext: []byte("one")}, {Plaintext: []byte("two"), AdditionalData: []byte("aad")},
	}})
	require.NoError(t, err)
	require.Len(t, batch.GetResults(), 2)
	items := make([]*pb.DecryptBatchItem, len(batch.GetResults()))
	for i, res := range batch.GetResults() {
		require.Empty(t, res.GetError())
		r := res.GetResult()
		items[i] = &pb.DecryptBatchItem{Ciphertext: r.GetCiphertext(), Nonce: r.GetNonce(), Tag: r.GetTag(), GcmNonceMode: r.GetGcmNonceMode(), KeyVersion: r.GetKeyVersion()}
	}
	items[1].AdditionalData = []byte("aad")
	opened, err := client.DecryptBatch(ctx, &pb.DecryptBatchRequest{KeyId: "aes", Backend: "software", Items: items})
	require.NoError(t, err)
	require.Len(t, opened.GetResults(), 2)
	assert.Equal(t, []byte("one"), opened.GetResults()[0].GetPlaintext())
	assert.Equal(t, []byte("two"), opened.GetResults()[1].GetPlaintext())
	assert.Equal(t, enc.GetKeyVersion(), opened.GetResults()[0].GetKeyVersion())

	dk, err := client.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "aes", Backend: "software", KeySize: 32})
	require.NoError(t, err)
	assert.Len(t, dk.GetPlaintext(), 32)
	assert.Equal(t, dk.GetPlaintext(), decryptWith(t, client, "aes", dk.GetWrapped()))
	wrapped, err := client.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "aes", Backend: "software", KeySize: 32})
	require.NoError(t, err)
	assert.Len(t, decryptWith(t, client, "aes", wrapped.GetWrapped()), 32)

	mac, err := client.GenerateHMAC(ctx, &pb.GenerateHMACRequest{KeyId: "aes", Backend: "software", Data: []byte("data")})
	require.NoError(t, err)
	assert.Len(t, mac.GetMac(), sha256.Size)
	assert.Equal(t, uint32(1), mac.GetKeyVersion())
	valid, err := client.VerifyHMAC(ctx, &pb.VerifyHMACRequest{KeyId: "aes", Backend: "software", Data: []byte("data"), Mac: mac.GetMac()})
	require.NoError(t, err)
	assert.True(t, valid.GetValid())
	assert.Equal(t, uint32(1), valid.GetKeyVersion())
	tampered, err := client.VerifyHMAC(ctx, &pb.VerifyHMACRequest{KeyId: "aes", Backend: "software", Data: []byte("datum"), Mac: mac.GetMac()})
	require.NoError(t, err)
	assert.False(t, tampered.GetValid())

	random, err := client.GenerateRandom(ctx, &pb.GenerateRandomRequest{Length: 24})
	require.NoError(t, err)
	assert.Len(t, random.GetRandom(), 24)

	digest, err := client.Hash(ctx, &pb.HashRequest{Data: []byte("abc"), Hash: "sha256"})
	require.NoError(t, err)
	want := sha256.Sum256([]byte("abc"))
	assert.Equal(t, want[:], digest.GetDigest())
}

// TestCryptoUtilRPCs_MapErrors pins the gRPC code each service error maps to,
// with no partial response.
func TestCryptoUtilRPCs_MapErrors(t *testing.T) {
	_, client := cryptoUtilServer(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() (any, error)
		code codes.Code
	}{
		{"rewrap from a missing key", func() (any, error) {
			return client.Rewrap(ctx, &pb.RewrapRequest{Source: &pb.DecryptRequest{KeyId: "ghost", Backend: "software", Ciphertext: []byte("x")}, TargetKeyId: "aes2"})
		}, codes.NotFound},
		{"rewrap without a source names no key", func() (any, error) {
			return client.Rewrap(ctx, &pb.RewrapRequest{TargetKeyId: "aes2"})
		}, codes.NotFound},
		{"batch encrypt under a missing key", func() (any, error) {
			return client.EncryptBatch(ctx, &pb.EncryptBatchRequest{KeyId: "ghost", Backend: "software", Items: []*pb.EncryptBatchItem{{Plaintext: []byte("x")}}})
		}, codes.NotFound},
		{"batch decrypt under a missing key", func() (any, error) {
			return client.DecryptBatch(ctx, &pb.DecryptBatchRequest{KeyId: "ghost", Backend: "software", Items: []*pb.DecryptBatchItem{{Ciphertext: []byte("x")}}})
		}, codes.NotFound},
		{"data key under a missing key", func() (any, error) {
			return client.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "ghost", Backend: "software", KeySize: 32})
		}, codes.NotFound},
		{"wrapped data key under a missing key", func() (any, error) {
			return client.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{KeyId: "ghost", Backend: "software", KeySize: 32})
		}, codes.NotFound},
		{"hmac under a missing key", func() (any, error) {
			return client.GenerateHMAC(ctx, &pb.GenerateHMACRequest{KeyId: "ghost", Backend: "software", Data: []byte("d")})
		}, codes.NotFound},
		{"verify hmac under a missing key", func() (any, error) {
			return client.VerifyHMAC(ctx, &pb.VerifyHMACRequest{KeyId: "ghost", Backend: "software", Data: []byte("d"), Mac: []byte("m")})
		}, codes.NotFound},
		{"random of no length", func() (any, error) {
			return client.GenerateRandom(ctx, &pb.GenerateRandomRequest{})
		}, codes.InvalidArgument},
		{"hash of an unknown algorithm", func() (any, error) {
			return client.Hash(ctx, &pb.HashRequest{Data: []byte("abc"), Hash: "md4"})
		}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.call()
			require.Error(t, err)
			assert.Equal(t, tt.code, status.Code(err), err.Error())
			assert.Nil(t, resp)
		})
	}
}

// TestCryptoUtilRPCs_TenantBinding checks that a tenant caller never reaches
// a key of the default scope.
func TestCryptoUtilRPCs_TenantBinding(t *testing.T) {
	service, _ := cryptoUtilServer(t)
	acme := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u", TenantID: "acme"})

	_, err := service.GenerateDataKey(acme, &pb.GenerateDataKeyRequest{KeyId: "aes", Backend: "software", KeySize: 32})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = service.GenerateHMAC(acme, &pb.GenerateHMACRequest{KeyId: "aes", Backend: "software", Data: []byte("d")})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestCryptoUtilRPCs_NilService checks every handler refuses as Unavailable
// when no service is configured.
func TestCryptoUtilRPCs_NilService(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	calls := map[string]func() error{
		"rewrap":        func() error { _, err := s.Rewrap(ctx, &pb.RewrapRequest{}); return err },
		"encrypt-batch": func() error { _, err := s.EncryptBatch(ctx, &pb.EncryptBatchRequest{}); return err },
		"decrypt-batch": func() error { _, err := s.DecryptBatch(ctx, &pb.DecryptBatchRequest{}); return err },
		"data-key":      func() error { _, err := s.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"wrapped-key":   func() error { _, err := s.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"hmac":          func() error { _, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{}); return err },
		"verify-hmac":   func() error { _, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{}); return err },
		"random":        func() error { _, err := s.GenerateRandom(ctx, &pb.GenerateRandomRequest{}); return err },
		"hash":          func() error { _, err := s.Hash(ctx, &pb.HashRequest{}); return err },
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}
