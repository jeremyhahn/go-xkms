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
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// keyManagementService returns the real Service over a software backend with
// a key version store and a key policy store, holding an ECDSA signing key
// "signer" and an AES-GCM key "aead".
func keyManagementService(t *testing.T) *Service {
	t.Helper()
	s, client := keyVersionServer(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	s.xkmsService.SetKeyPolicyStore(store)

	ctx := context.Background()
	_, err = client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "signer", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	_, err = client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "aead", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"})
	require.NoError(t, err)
	return s
}

// TestKeyManagementRPCs_EndToEnd drives the key management RPCs against the
// real service: the public key, metadata, policy, rotation policy, safety
// limits, backend status and revocation.
func TestKeyManagementRPCs_EndToEnd(t *testing.T) {
	s := keyManagementService(t)
	ctx := context.Background()

	pub, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)
	_, err = x509.ParsePKIXPublicKey(pub.GetPublicKey())
	require.NoError(t, err)
	assert.Equal(t, "signer", pub.GetKeyId())

	updated, err := s.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{Backend: "software", KeyId: "signer", Description: "billing", Tags: map[string]string{"team": "billing"}})
	require.NoError(t, err)
	assert.Equal(t, "billing", updated.GetMetadata().GetDescription())
	metadata, err := s.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "billing", metadata.GetMetadata().GetTags()["team"])

	set, err := s.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{Backend: "software", KeyId: "signer", Policy: &pb.KeyPolicy{MaxUsageCount: 3}})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), set.GetPolicyVersion())
	policy, err := s.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), policy.GetPolicy().GetMaxUsageCount())
	deleted, err := s.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "signer", deleted.GetKeyId())

	rotation, err := s.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{Backend: "software", KeyId: "signer", Policy: &pb.RotationPolicy{IntervalSeconds: 86400}})
	require.NoError(t, err)
	assert.Equal(t, int64(86400), rotation.GetPolicy().GetIntervalSeconds())
	gotRotation, err := s.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)
	assert.Equal(t, int64(86400), gotRotation.GetPolicy().GetIntervalSeconds())
	_, err = s.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{Backend: "software", KeyId: "signer"})
	require.NoError(t, err)

	_, err = s.SetKeySafety(ctx, &pb.SetKeySafetyRequest{Backend: "software", KeyId: "aead", MaxOperations: 100})
	require.NoError(t, err)
	report, err := s.SafetyReport(ctx, &pb.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Len(t, report.GetAllItems(), 1)
	_, err = s.SafetyCheck(ctx, &pb.SafetyCheckRequest{})
	require.NoError(t, err)
	_, err = s.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{Backend: "software", KeyId: "aead"})
	require.NoError(t, err)

	algorithms, err := s.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, algorithms.GetAlgorithms())
	backend, err := s.BackendStatus(ctx, &pb.BackendStatusRequest{Backend: "software"})
	require.NoError(t, err)
	assert.NotEmpty(t, backend.GetStatus())

	disabled, err := s.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{Backend: "software", KeyId: "signer", Status: pb.KeyStatus_KEY_STATUS_DISABLED})
	require.NoError(t, err)
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_DISABLED, disabled.GetStatus())
	revoked, err := s.RevokeKey(ctx, &pb.RevokeKeyRequest{Backend: "software", KeyId: "signer", Reason: "retired"})
	require.NoError(t, err)
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_COMPROMISED, revoked.GetStatus())
}

// TestKeyManagementRPCs_MapErrors proves the key management refusals reach
// the caller with their class's code.
func TestKeyManagementRPCs_MapErrors(t *testing.T) {
	s := keyManagementService(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"symmetric public key", func() error {
			_, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{Backend: "software", KeyId: "aead"})
			return err
		}, codes.InvalidArgument},
		{"missing key", func() error {
			_, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{Backend: "software", KeyId: "ghost"})
			return err
		}, codes.NotFound},
		{"require mfa", func() error {
			_, err := s.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{Backend: "software", KeyId: "signer", Policy: &pb.KeyPolicy{RequireMfa: true}})
			return err
		}, codes.Unimplemented},
		{"report format", func() error {
			_, err := s.SafetyReport(ctx, &pb.SafetyReportRequest{Format: "xml"})
			return err
		}, codes.InvalidArgument},
		{"unsettable status", func() error {
			_, err := s.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{Backend: "software", KeyId: "signer", Status: pb.KeyStatus_KEY_STATUS_COMPROMISED})
			return err
		}, codes.InvalidArgument},
		{"backend test before a first seal", func() error {
			_, err := s.BackendTest(ctx, &pb.BackendTestRequest{Backend: "software"})
			return err
		}, codes.Unimplemented},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err)
			assert.Equal(t, tt.code, status.Code(err), err.Error())
		})
	}

	// Without a policy store the policy-backed operations are unavailable.
	s.xkmsService.SetKeyPolicyStore(nil)
	_, err := s.SetKeySafety(ctx, &pb.SetKeySafetyRequest{Backend: "software", KeyId: "aead", MaxOperations: 10})
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
}

// TestKeyManagementAndCryptoUtilityRPCs_NilService proves every key
// management and crypto utility RPC answers Unavailable, not a panic, when
// no service is wired.
func TestKeyManagementAndCryptoUtilityRPCs_NilService(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	calls := map[string]func() error{
		"get public key":      func() error { _, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{}); return err },
		"revoke":              func() error { _, err := s.RevokeKey(ctx, &pb.RevokeKeyRequest{}); return err },
		"update status":       func() error { _, err := s.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{}); return err },
		"get metadata":        func() error { _, err := s.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{}); return err },
		"update metadata":     func() error { _, err := s.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{}); return err },
		"set policy":          func() error { _, err := s.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{}); return err },
		"get policy":          func() error { _, err := s.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{}); return err },
		"delete policy":       func() error { _, err := s.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{}); return err },
		"set rotation policy": func() error { _, err := s.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{}); return err },
		"get rotation policy": func() error { _, err := s.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{}); return err },
		"del rotation policy": func() error {
			_, err := s.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{})
			return err
		},
		"supported algorithms": func() error { _, err := s.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{}); return err },
		"backend status":       func() error { _, err := s.BackendStatus(ctx, &pb.BackendStatusRequest{}); return err },
		"backend test":         func() error { _, err := s.BackendTest(ctx, &pb.BackendTestRequest{}); return err },
		"set safety":           func() error { _, err := s.SetKeySafety(ctx, &pb.SetKeySafetyRequest{}); return err },
		"clear safety":         func() error { _, err := s.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{}); return err },
		"safety check":         func() error { _, err := s.SafetyCheck(ctx, &pb.SafetyCheckRequest{}); return err },
		"safety report":        func() error { _, err := s.SafetyReport(ctx, &pb.SafetyReportRequest{}); return err },
		"rewrap":               func() error { _, err := s.Rewrap(ctx, &pb.RewrapRequest{}); return err },
		"encrypt batch":        func() error { _, err := s.EncryptBatch(ctx, &pb.EncryptBatchRequest{}); return err },
		"decrypt batch":        func() error { _, err := s.DecryptBatch(ctx, &pb.DecryptBatchRequest{}); return err },
		"data key":             func() error { _, err := s.GenerateDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"wrapped data key":     func() error { _, err := s.GenerateWrappedDataKey(ctx, &pb.GenerateDataKeyRequest{}); return err },
		"hmac":                 func() error { _, err := s.GenerateHMAC(ctx, &pb.GenerateHMACRequest{}); return err },
		"verify hmac":          func() error { _, err := s.VerifyHMAC(ctx, &pb.VerifyHMACRequest{}); return err },
		"random":               func() error { _, err := s.GenerateRandom(ctx, &pb.GenerateRandomRequest{}); return err },
		"hash":                 func() error { _, err := s.Hash(ctx, &pb.HashRequest{}); return err },
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}
