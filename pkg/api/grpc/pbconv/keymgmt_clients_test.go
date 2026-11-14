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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func TestKeyManagementEnums(t *testing.T) {
	for status := range keyStatusToProto {
		assert.Equal(t, status, KeyStatusFromProto(KeyStatusToProto(status)), status)
	}
	for alg := range keyAlgorithmToProto {
		assert.Equal(t, alg, KeyAlgorithmFromProto(KeyAlgorithmToProto(alg)), alg)
	}
	usages := make([]transport.KeyUsage, 0, len(keyUsageToProto))
	for u := range keyUsageToProto {
		usages = append(usages, u)
	}
	assert.Equal(t, usages, KeyUsagesFromProto(KeyUsagesToProto(usages)))

	// A value the other side has no enum for converts to the unspecified
	// enum, or to "", which the service refuses.
	assert.Equal(t, pb.KeyStatus(0), KeyStatusToProto("bogus"))
	assert.Equal(t, pb.KeyAlgorithm(0), KeyAlgorithmToProto("bogus"))
	assert.Equal(t, []pb.KeyUsage{0}, KeyUsagesToProto([]transport.KeyUsage{"bogus"}))
	assert.Empty(t, KeyStatusFromProto(pb.KeyStatus(9999)))
	assert.Empty(t, KeyAlgorithmFromProto(pb.KeyAlgorithm(9999)))
	assert.Equal(t, []transport.KeyUsage{""}, KeyUsagesFromProto([]pb.KeyUsage{9999}))

	assert.Nil(t, KeyUsagesToProto(nil))
	assert.Nil(t, KeyUsagesFromProto(nil))

	names := []transport.KeyAlgorithm{transport.KeyAlgorithmAES256GCM, "ML-DSA-65"}
	assert.Equal(t, []string{string(transport.KeyAlgorithmAES256GCM), "ML-DSA-65"}, KeyAlgorithmNamesToProto(names))
	assert.Equal(t, names, KeyAlgorithmNamesFromProto(KeyAlgorithmNamesToProto(names)))
	assert.Empty(t, KeyAlgorithmNamesFromProto(nil))
}

func TestKeyManagementConversions_NilAndTenant(t *testing.T) {
	assert.Nil(t, RotationPolicyToProto(nil))
	assert.Nil(t, RotationPolicyFromProto(nil))
	assert.Nil(t, KeyPolicyToProto(nil))
	assert.Nil(t, KeyPolicyFromProto(nil))
	assert.Nil(t, KeyMetadataToProto(nil))
	assert.Nil(t, KeyMetadataFromProto(nil))
	assert.Empty(t, SafetyWarningsFromProto(nil))

	// Metadata without a rotation policy keeps it absent.
	meta := sampleKeyMetadata()
	meta.RotationPolicy = nil
	assert.Nil(t, KeyMetadataFromProto(KeyMetadataToProto(meta)).RotationPolicy)

	// The tenant never crosses the wire: the server scopes to the caller.
	update := &transport.UpdateKeyMetadataRequest{KeyID: "k1", TenantID: "acme"}
	assert.Empty(t, UpdateKeyMetadataRequestFromProto(UpdateKeyMetadataRequestToProto(update)).TenantID)
	assert.Equal(t, &transport.BackendStatusResponse{}, BackendStatusResponseFromProto(nil))
	assert.Equal(t, &transport.SafetyReportResponse{AllItems: []transport.SafetyWarning{}}, SafetyReportResponseFromProto(nil))
}

func TestKeyManagementClient(t *testing.T) {
	stub := &stubKeystoreClient{resp: map[string]any{
		"GetPublicKey": &pb.GetPublicKeyResponse{
			KeyId: "k1", PublicKey: []byte("pub"), Algorithm: pb.KeyAlgorithm_KEY_ALG_ED25519, Version: 2, Timestamp: 9,
		},
		"RevokeKey":       &pb.RevokeKeyResponse{KeyId: "k1", Status: pb.KeyStatus_KEY_STATUS_COMPROMISED, Timestamp: 9},
		"UpdateKeyStatus": &pb.UpdateKeyStatusResponse{KeyId: "k1", Version: 2, Status: pb.KeyStatus_KEY_STATUS_DISABLED, Timestamp: 9},
		"GetKeyMetadata":  &pb.GetKeyMetadataResponse{Metadata: KeyMetadataToProto(sampleKeyMetadata()), Timestamp: 9},
		"GetKeyPolicy":    &pb.GetKeyPolicyResponse{Policy: KeyPolicyToProto(sampleKeyPolicy()), Timestamp: 9},
		"GetKeyRotationPolicy": &pb.GetKeyRotationPolicyResponse{
			KeyId: "k1", Policy: RotationPolicyToProto(sampleRotationPolicy()), Timestamp: 9,
		},
		"GetSupportedAlgorithms": &pb.GetSupportedAlgorithmsResponse{Algorithms: []string{"AES-256-GCM"}},
		"BackendStatus":          &pb.BackendStatusResponse{BackendType: "tpm2", Status: "ready"},
		"BackendTest":            &pb.BackendTestResponse{Success: true, DurationMs: 12, Message: "ok", Timestamp: 9},
		"SafetyCheck":            &pb.SafetyCheckResponse{Warnings: SafetyWarningsToProto(sampleSafetyWarnings()), Timestamp: 9},
		"SafetyReport":           &pb.SafetyReportResponse{TotalKeys: 10},
	}}
	c := KeyManagementClient{Client: stub}
	ctx := context.Background()

	pub, err := c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{KeyID: "k1", Version: 2, Backend: "pkcs8"})
	require.NoError(t, err)
	assert.Equal(t, &transport.GetPublicKeyResponse{
		KeyID: "k1", PublicKey: []byte("pub"), Algorithm: transport.KeyAlgorithmEd25519, Version: 2, Timestamp: 9,
	}, pub)

	revoked, err := c.RevokeKey(ctx, &transport.RevokeKeyRequest{KeyID: "k1", Reason: "leak"})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusCompromised, revoked.Status)
	assert.Equal(t, "leak", stub.got[len(stub.got)-1].(*pb.RevokeKeyRequest).GetReason())

	updated, err := c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{KeyID: "k1", Version: 2, Status: transport.KeyStatusDisabled})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusDisabled, updated.Status)
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_DISABLED, stub.got[len(stub.got)-1].(*pb.UpdateKeyStatusRequest).GetStatus())

	meta, err := c.GetKeyMetadata(ctx, &transport.KeyManagementRequest{KeyID: "k1"})
	require.NoError(t, err)
	assert.Equal(t, sampleKeyMetadata(), meta.Metadata)

	policy, err := c.GetKeyPolicy(ctx, &transport.KeyManagementRequest{KeyID: "k1"})
	require.NoError(t, err)
	assert.Equal(t, sampleKeyPolicy(), policy.Policy)

	_, err = c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{KeyID: "k1", Policy: sampleKeyPolicy()})
	require.NoError(t, err)
	assert.Equal(t, sampleKeyPolicy(), KeyPolicyFromProto(stub.got[len(stub.got)-1].(*pb.SetKeyPolicyRequest).GetPolicy()))

	rotation, err := c.GetKeyRotationPolicy(ctx, &transport.KeyManagementRequest{KeyID: "k1"})
	require.NoError(t, err)
	assert.Equal(t, sampleRotationPolicy(), rotation.Policy)

	algorithms, err := c.GetSupportedAlgorithms(ctx, &transport.BackendRequest{Backend: "pkcs8"})
	require.NoError(t, err)
	assert.Equal(t, []transport.KeyAlgorithm{transport.KeyAlgorithmAES256GCM}, algorithms.Algorithms)

	backend, err := c.BackendStatus(ctx, &transport.BackendRequest{Backend: "tpm2"})
	require.NoError(t, err)
	assert.Equal(t, "ready", backend.Status)

	tested, err := c.BackendTest(ctx, &transport.BackendRequest{Backend: "tpm2"})
	require.NoError(t, err)
	assert.Equal(t, &transport.BackendTestResponse{Success: true, DurationMS: 12, Message: "ok", Timestamp: 9}, tested)

	check, err := c.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, sampleSafetyWarnings(), check.Warnings)

	report, err := c.SafetyReport(ctx, &transport.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Equal(t, int32(10), report.TotalKeys)

	keyReq := &transport.KeyManagementRequest{KeyID: "k1"}
	backendReq := &transport.BackendRequest{}
	assertClientCalls(t, stub, []clientCall{
		{"GetPublicKey",
			func(ctx context.Context) error {
				_, err := c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.GetPublicKey(ctx, nil); return err }},
		{"RevokeKey",
			func(ctx context.Context) error { _, err := c.RevokeKey(ctx, &transport.RevokeKeyRequest{}); return err },
			func(ctx context.Context) error { _, err := c.RevokeKey(ctx, nil); return err }},
		{"UpdateKeyStatus",
			func(ctx context.Context) error {
				_, err := c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.UpdateKeyStatus(ctx, nil); return err }},
		{"GetKeyMetadata",
			func(ctx context.Context) error { _, err := c.GetKeyMetadata(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.GetKeyMetadata(ctx, nil); return err }},
		{"UpdateKeyMetadata",
			func(ctx context.Context) error {
				_, err := c.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.UpdateKeyMetadata(ctx, nil); return err }},
		{"SetKeyPolicy",
			func(ctx context.Context) error {
				_, err := c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.SetKeyPolicy(ctx, nil); return err }},
		{"GetKeyPolicy",
			func(ctx context.Context) error { _, err := c.GetKeyPolicy(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.GetKeyPolicy(ctx, nil); return err }},
		{"DeleteKeyPolicy",
			func(ctx context.Context) error { _, err := c.DeleteKeyPolicy(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.DeleteKeyPolicy(ctx, nil); return err }},
		{"SetKeyRotationPolicy",
			func(ctx context.Context) error {
				_, err := c.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{Policy: sampleRotationPolicy()})
				return err
			},
			func(ctx context.Context) error { _, err := c.SetKeyRotationPolicy(ctx, nil); return err }},
		{"GetKeyRotationPolicy",
			func(ctx context.Context) error { _, err := c.GetKeyRotationPolicy(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.GetKeyRotationPolicy(ctx, nil); return err }},
		{"DeleteKeyRotationPolicy",
			func(ctx context.Context) error { _, err := c.DeleteKeyRotationPolicy(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.DeleteKeyRotationPolicy(ctx, nil); return err }},
		{"GetSupportedAlgorithms",
			func(ctx context.Context) error { _, err := c.GetSupportedAlgorithms(ctx, backendReq); return err },
			func(ctx context.Context) error { _, err := c.GetSupportedAlgorithms(ctx, nil); return err }},
		{"BackendStatus",
			func(ctx context.Context) error { _, err := c.BackendStatus(ctx, backendReq); return err },
			func(ctx context.Context) error { _, err := c.BackendStatus(ctx, nil); return err }},
		{"BackendTest",
			func(ctx context.Context) error { _, err := c.BackendTest(ctx, backendReq); return err },
			func(ctx context.Context) error { _, err := c.BackendTest(ctx, nil); return err }},
		{"SetKeySafety",
			func(ctx context.Context) error {
				_, err := c.SetKeySafety(ctx, &transport.SetKeySafetyRequest{KeyID: "k1", MaxOperations: 10})
				return err
			},
			func(ctx context.Context) error { _, err := c.SetKeySafety(ctx, nil); return err }},
		{"ClearKeySafety",
			func(ctx context.Context) error { _, err := c.ClearKeySafety(ctx, keyReq); return err },
			func(ctx context.Context) error { _, err := c.ClearKeySafety(ctx, nil); return err }},
		{"SafetyCheck",
			func(ctx context.Context) error {
				_, err := c.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.SafetyCheck(ctx, nil); return err }},
		{"SafetyReport",
			func(ctx context.Context) error {
				_, err := c.SafetyReport(ctx, &transport.SafetyReportRequest{})
				return err
			},
			func(ctx context.Context) error { _, err := c.SafetyReport(ctx, nil); return err }},
	})
}
