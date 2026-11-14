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
)

// TestCryptoUtilityRPCs_EndToEnd drives the crypto utility RPCs against the
// real service: batch encryption round trips, rewrapping, data keys, HMAC,
// random bytes and hashing.
func TestCryptoUtilityRPCs_EndToEnd(t *testing.T) {
	s := keyManagementService(t)
	ctx := context.Background()
	_, err := s.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "target", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"})
	require.NoError(t, err)

	sealed, err := s.EncryptBatch(ctx, &pb.EncryptBatchRequest{Backend: "software", KeyId: "aead", Items: []*pb.EncryptBatchItem{
		{Plaintext: []byte("one")},
		{Plaintext: []byte("two"), AdditionalData: []byte("aad")},
	}})
	require.NoError(t, err)
	require.Len(t, sealed.GetResults(), 2)
	items := make([]*pb.DecryptBatchItem, 0, 2)
	for i, result := range sealed.GetResults() {
		require.Empty(t, result.GetError())
		enc := result.GetResult()
		item := &pb.DecryptBatchItem{Ciphertext: enc.GetCiphertext(), Nonce: enc.GetNonce(), Tag: enc.GetTag(), GcmNonceMode: enc.GetGcmNonceMode()}
		if i == 1 {
			item.AdditionalData = []byte("aad")
		}
		items = append(items, item)
	}
	opened, err := s.DecryptBatch(ctx, &pb.DecryptBatchRequest{Backend: "software", KeyId: "aead", Items: items})
	require.NoError(t, err)
	require.Len(t, opened.GetResults(), 2)
	assert.Equal(t, []byte("one"), opened.GetResults()[0].GetPlaintext())
	assert.Equal(t, []byte("two"), opened.GetResults()[1].GetPlaintext())

	first := sealed.GetResults()[0].GetResult()
	rewrapped, err := s.Rewrap(ctx, &pb.RewrapRequest{
		Source:        &pb.DecryptRequest{Backend: "software", KeyId: "aead", Ciphertext: first.GetCiphertext(), Nonce: first.GetNonce(), Tag: first.GetTag(), GcmNonceMode: first.GetGcmNonceMode()},
		TargetKeyId:   "target",
		TargetBackend: "software",
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), rewrapped.GetSourceKeyVersion())
	assert.NotEmpty(t, rewrapped.GetWrapped().GetCiphertext())

	dataKey, err := s.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{Backend: "software", KeyId: "aead", KeySize: 32})
	require.NoError(t, err)
	assert.Len(t, dataKey.GetPlaintext(), 32)
	assert.NotEmpty(t, dataKey.GetWrapped().GetCiphertext())
	wrappedKey, err := s.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{Backend: "software", KeyId: "aead", KeySize: 32})
	require.NoError(t, err)
	assert.NotEmpty(t, wrappedKey.GetWrapped().GetCiphertext())

	mac, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{Backend: "software", KeyId: "aead", Data: []byte("message")})
	require.NoError(t, err)
	assert.NotEmpty(t, mac.GetMac())
	valid, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{Backend: "software", KeyId: "aead", Data: []byte("message"), Mac: mac.GetMac()})
	require.NoError(t, err)
	assert.True(t, valid.GetValid())
	invalid, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{Backend: "software", KeyId: "aead", Data: []byte("tampered"), Mac: mac.GetMac()})
	require.NoError(t, err)
	assert.False(t, invalid.GetValid())

	random, err := s.GenerateRandom(ctx, &pb.GenerateRandomRequest{Length: 24})
	require.NoError(t, err)
	assert.Len(t, random.GetRandom(), 24)

	digest, err := s.Hash(ctx, &pb.HashRequest{Data: []byte("message"), Hash: "SHA-256"})
	require.NoError(t, err)
	want := sha256.Sum256([]byte("message"))
	assert.Equal(t, want[:], digest.GetDigest())
}

// TestCryptoUtilityRPCs_MapErrors proves the crypto utility refusals reach
// the caller with their class's code.
func TestCryptoUtilityRPCs_MapErrors(t *testing.T) {
	s := keyManagementService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"hmac with an unknown hash", func() error {
			_, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{Backend: "software", KeyId: "aead", Hash: "WHIRLPOOL", Data: []byte("m")})
			return err
		}, codes.InvalidArgument},
		{"hmac under a missing key", func() error {
			_, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{Backend: "software", KeyId: "ghost", Data: []byte("m")})
			return err
		}, codes.NotFound},
		{"verify hmac with an unknown hash", func() error {
			_, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{Backend: "software", KeyId: "aead", Hash: "WHIRLPOOL", Data: []byte("m")})
			return err
		}, codes.InvalidArgument},
		{"hash with an unknown function", func() error {
			_, err := s.Hash(ctx, &pb.HashRequest{Data: []byte("m"), Hash: "WHIRLPOOL"})
			return err
		}, codes.InvalidArgument},
		{"random of no bytes", func() error {
			_, err := s.GenerateRandom(ctx, &pb.GenerateRandomRequest{Length: 0})
			return err
		}, codes.InvalidArgument},
		{"encrypt batch under a missing key", func() error {
			_, err := s.EncryptBatch(ctx, &pb.EncryptBatchRequest{Backend: "software", KeyId: "ghost", Items: []*pb.EncryptBatchItem{{Plaintext: []byte("m")}}})
			return err
		}, codes.NotFound},
		{"decrypt batch under a missing key", func() error {
			_, err := s.DecryptBatch(ctx, &pb.DecryptBatchRequest{Backend: "software", KeyId: "ghost", Items: []*pb.DecryptBatchItem{{Ciphertext: []byte("m")}}})
			return err
		}, codes.NotFound},
		{"data key under a missing key", func() error {
			_, err := s.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{Backend: "software", KeyId: "ghost", KeySize: 32})
			return err
		}, codes.NotFound},
		{"wrapped data key under a missing key", func() error {
			_, err := s.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{Backend: "software", KeyId: "ghost", KeySize: 32})
			return err
		}, codes.NotFound},
		{"rewrap from a missing key", func() error {
			_, err := s.Rewrap(ctx, &pb.RewrapRequest{Source: &pb.DecryptRequest{Backend: "software", KeyId: "ghost", Ciphertext: []byte("m")}, TargetKeyId: "aead", TargetBackend: "software"})
			return err
		}, codes.NotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err)
			assert.Equal(t, tt.code, status.Code(err), err.Error())
		})
	}
}
