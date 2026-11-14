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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// keyManagementServer is keyVersionServer with a key policy store wired.
func keyManagementServer(t *testing.T) (*Service, pb.KeystoreServiceClient) {
	t.Helper()
	service, client := keyVersionServer(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	service.xkmsService.SetKeyPolicyStore(store)
	return service, client
}

// TestKeyManagementRPCs_EndToEnd drives the key policy verbs over gRPC: a set
// policy reads back field for field, and is gone after delete.
func TestKeyManagementRPCs_EndToEnd(t *testing.T) {
	_, client := keyManagementServer(t)
	ctx := context.Background()
	_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)

	policy := &pb.KeyPolicy{
		AllowedPrincipals: []string{"alice", "bob"},
		DeniedPrincipals:  []string{"mallory"},
		RotationRequired:  true,
		MaxUsageCount:     42,
	}
	set, err := client.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: "k", Backend: "software", Policy: policy})
	require.NoError(t, err)
	assert.Equal(t, "k", set.GetKeyId())
	assert.NotZero(t, set.GetPolicyVersion())

	got, err := client.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	p := got.GetPolicy()
	assert.Equal(t, policy.AllowedPrincipals, p.GetAllowedPrincipals())
	assert.Equal(t, policy.DeniedPrincipals, p.GetDeniedPrincipals())
	assert.True(t, p.GetRotationRequired())
	assert.Equal(t, policy.MaxUsageCount, p.GetMaxUsageCount())
	assert.Equal(t, set.GetPolicyVersion(), p.GetVersion())

	deleted, err := client.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "k", deleted.GetKeyId())

	got, err = client.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Nil(t, got.GetPolicy(), "a deleted policy leaves RBAC alone")
}

// TestKeyManagementRPCs_Lifecycle drives the remaining key management verbs
// over gRPC and checks each answer against the request it carried.
func TestKeyManagementRPCs_Lifecycle(t *testing.T) {
	_, client := keyManagementServer(t)
	ctx := context.Background()
	_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	_, err = client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "aes", Backend: "software", KeyType: "secret", Algorithm: "aes-256-gcm"})
	require.NoError(t, err)

	pub, err := client.GetPublicKey(ctx, &pb.GetPublicKeyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "k", pub.GetKeyId())
	assert.NotEmpty(t, pub.GetPublicKey())
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, pub.GetAlgorithm())

	rot, err := client.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{KeyId: "k", Backend: "software", Policy: &pb.RotationPolicy{Enabled: true, IntervalSeconds: 3600}})
	require.NoError(t, err)
	assert.Equal(t, "k", rot.GetKeyId())
	assert.Positive(t, rot.GetPolicy().GetNextRotation(), "an enabled policy schedules the next rotation")
	gotRot, err := client.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, int64(3600), gotRot.GetPolicy().GetIntervalSeconds())
	assert.True(t, gotRot.GetPolicy().GetEnabled())
	delRot, err := client.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "k", delRot.GetKeyId())
	gotRot, err = client.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.False(t, gotRot.GetPolicy().GetEnabled())

	updated, err := client.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{KeyId: "k", Backend: "software", Name: "signer", Description: "test key", Tags: map[string]string{"env": "test"}})
	require.NoError(t, err)
	assert.Equal(t, "signer", updated.GetMetadata().GetName())
	meta, err := client.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "k", meta.GetMetadata().GetKeyId())
	assert.Equal(t, "signer", meta.GetMetadata().GetName())
	assert.Equal(t, "test key", meta.GetMetadata().GetDescription())
	assert.Equal(t, map[string]string{"env": "test"}, meta.GetMetadata().GetTags())

	disabled, err := client.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{KeyId: "k", Backend: "software", Status: pb.KeyStatus_KEY_STATUS_DISABLED})
	require.NoError(t, err)
	assert.Equal(t, "k", disabled.GetKeyId())
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_DISABLED, disabled.GetStatus())
	revoked, err := client.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "k", Backend: "software", Reason: "compromised"})
	require.NoError(t, err)
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_COMPROMISED, revoked.GetStatus())
	_, err = client.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{KeyId: "k", Backend: "software", Status: pb.KeyStatus_KEY_STATUS_ENABLED})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "a revoked key cannot change status")

	algs, err := client.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{Backend: "software"})
	require.NoError(t, err)
	assert.Contains(t, algs.GetAlgorithms(), "ECDSA-P256")

	backend, err := client.BackendStatus(ctx, &pb.BackendStatusRequest{Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "software", backend.GetBackendType())
	assert.True(t, backend.GetCapabilities()["keys"])

	safety, err := client.SetKeySafety(ctx, &pb.SetKeySafetyRequest{KeyId: "aes", Backend: "software", MaxOperations: 10, WarningPercent: 80})
	require.NoError(t, err)
	assert.Equal(t, "aes", safety.GetKeyId())
	report, err := client.SafetyReport(ctx, &pb.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Equal(t, int32(1), report.GetTotalKeys())
	check, err := client.SafetyCheck(ctx, &pb.SafetyCheckRequest{})
	require.NoError(t, err)
	assert.Empty(t, check.GetWarnings(), "an unused key is under its warning threshold")
	cleared, err := client.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{KeyId: "aes", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "aes", cleared.GetKeyId())
	report, err = client.SafetyReport(ctx, &pb.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Zero(t, report.GetTotalKeys())
}

// TestKeyManagementRPCs_MapErrors pins the gRPC code each service error maps
// to, with no partial response.
func TestKeyManagementRPCs_MapErrors(t *testing.T) {
	_, client := keyManagementServer(t)
	ctx := context.Background()
	_, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{KeyId: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)

	tests := []struct {
		name string
		call func() (any, error)
		code codes.Code
	}{
		{"public key of a missing key", func() (any, error) {
			return client.GetPublicKey(ctx, &pb.GetPublicKeyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"revoke a missing key", func() (any, error) {
			return client.RevokeKey(ctx, &pb.RevokeKeyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"status revoked", func() (any, error) {
			return client.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{KeyId: "k", Backend: "software", Status: pb.KeyStatus_KEY_STATUS_COMPROMISED})
		}, codes.InvalidArgument},
		{"metadata of a missing key", func() (any, error) {
			return client.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"update metadata of a missing key", func() (any, error) {
			return client.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{KeyId: "ghost", Backend: "software", Name: "n"})
		}, codes.NotFound},
		{"policy requiring MFA", func() (any, error) {
			return client.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{KeyId: "k", Backend: "software", Policy: &pb.KeyPolicy{RequireMfa: true}})
		}, codes.Unimplemented},
		{"policy of a missing key", func() (any, error) {
			return client.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"delete policy of a missing key", func() (any, error) {
			return client.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"rotation policy of a missing key", func() (any, error) {
			return client.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{KeyId: "ghost", Backend: "software", Policy: &pb.RotationPolicy{Enabled: true, IntervalSeconds: 60}})
		}, codes.NotFound},
		{"get rotation policy of a missing key", func() (any, error) {
			return client.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"delete rotation policy of a missing key", func() (any, error) {
			return client.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"algorithms of an unknown backend", func() (any, error) {
			return client.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{Backend: "nope"})
		}, codes.NotFound},
		{"status of an unknown backend", func() (any, error) {
			return client.BackendStatus(ctx, &pb.BackendStatusRequest{Backend: "nope"})
		}, codes.NotFound},
		{"test of an unknown backend", func() (any, error) {
			return client.BackendTest(ctx, &pb.BackendTestRequest{Backend: "nope"})
		}, codes.NotFound},
		{"usage limits on a signing key", func() (any, error) {
			return client.SetKeySafety(ctx, &pb.SetKeySafetyRequest{KeyId: "k", Backend: "software", MaxOperations: 1})
		}, codes.InvalidArgument},
		{"test before the first seal", func() (any, error) {
			return client.BackendTest(ctx, &pb.BackendTestRequest{Backend: "software"})
		}, codes.Unimplemented},
		{"usage limits without a limit", func() (any, error) {
			return client.SetKeySafety(ctx, &pb.SetKeySafetyRequest{KeyId: "k", Backend: "software"})
		}, codes.InvalidArgument},
		{"clear limits of a missing key", func() (any, error) {
			return client.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{KeyId: "ghost", Backend: "software"})
		}, codes.NotFound},
		{"report in an unknown format", func() (any, error) {
			return client.SafetyReport(ctx, &pb.SafetyReportRequest{Format: "xml"})
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

// TestKeyManagementRPCs_TenantBinding checks that a tenant caller never
// reaches a key of the default scope.
func TestKeyManagementRPCs_TenantBinding(t *testing.T) {
	service, client := keyManagementServer(t)
	_, err := client.GenerateKey(context.Background(), &pb.GenerateKeyRequest{KeyId: "k", Backend: "software", KeyType: "signing", Algorithm: "ecdsa"})
	require.NoError(t, err)
	acme := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "u", TenantID: "acme"})

	_, err = service.GetPublicKey(acme, &pb.GetPublicKeyRequest{KeyId: "k", Backend: "software"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = service.GetKeyPolicy(acme, &pb.GetKeyPolicyRequest{KeyId: "k", Backend: "software"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	check, err := service.SafetyCheck(acme, &pb.SafetyCheckRequest{})
	require.NoError(t, err)
	assert.Empty(t, check.GetWarnings())
}

// TestKeyManagementRPCs_NilService checks every handler refuses as
// Unavailable when no service is configured.
func TestKeyManagementRPCs_NilService(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	calls := map[string]func() error{
		"public-key":   func() error { _, err := s.GetPublicKey(ctx, &pb.GetPublicKeyRequest{}); return err },
		"revoke":       func() error { _, err := s.RevokeKey(ctx, &pb.RevokeKeyRequest{}); return err },
		"status":       func() error { _, err := s.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{}); return err },
		"get-meta":     func() error { _, err := s.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{}); return err },
		"update-meta":  func() error { _, err := s.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{}); return err },
		"set-policy":   func() error { _, err := s.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{}); return err },
		"get-policy":   func() error { _, err := s.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{}); return err },
		"del-policy":   func() error { _, err := s.DeleteKeyPolicy(ctx, &pb.DeleteKeyPolicyRequest{}); return err },
		"set-rotation": func() error { _, err := s.SetKeyRotationPolicy(ctx, &pb.SetKeyRotationPolicyRequest{}); return err },
		"get-rotation": func() error { _, err := s.GetKeyRotationPolicy(ctx, &pb.GetKeyRotationPolicyRequest{}); return err },
		"del-rotation": func() error {
			_, err := s.DeleteKeyRotationPolicy(ctx, &pb.DeleteKeyRotationPolicyRequest{})
			return err
		},
		"algorithms":   func() error { _, err := s.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{}); return err },
		"backend":      func() error { _, err := s.BackendStatus(ctx, &pb.BackendStatusRequest{}); return err },
		"backend-test": func() error { _, err := s.BackendTest(ctx, &pb.BackendTestRequest{}); return err },
		"set-safety":   func() error { _, err := s.SetKeySafety(ctx, &pb.SetKeySafetyRequest{}); return err },
		"clear-safety": func() error { _, err := s.ClearKeySafety(ctx, &pb.ClearKeySafetyRequest{}); return err },
		"check":        func() error { _, err := s.SafetyCheck(ctx, &pb.SafetyCheckRequest{}); return err },
		"report":       func() error { _, err := s.SafetyReport(ctx, &pb.SafetyReportRequest{}); return err },
	}
	for name, call := range calls {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}
