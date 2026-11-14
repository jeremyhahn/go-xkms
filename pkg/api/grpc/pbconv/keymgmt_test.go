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

func (s *cannedServer) GetPublicKey(_ context.Context, in *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	return answer[*pb.GetPublicKeyResponse](s, in)
}

func (s *cannedServer) RevokeKey(_ context.Context, in *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	return answer[*pb.RevokeKeyResponse](s, in)
}

func (s *cannedServer) UpdateKeyStatus(_ context.Context, in *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	return answer[*pb.UpdateKeyStatusResponse](s, in)
}

func (s *cannedServer) GetKeyMetadata(_ context.Context, in *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error) {
	return answer[*pb.GetKeyMetadataResponse](s, in)
}

func (s *cannedServer) UpdateKeyMetadata(_ context.Context, in *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error) {
	return answer[*pb.UpdateKeyMetadataResponse](s, in)
}

func (s *cannedServer) SetKeyPolicy(_ context.Context, in *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error) {
	return answer[*pb.SetKeyPolicyResponse](s, in)
}

func (s *cannedServer) GetKeyPolicy(_ context.Context, in *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error) {
	return answer[*pb.GetKeyPolicyResponse](s, in)
}

func (s *cannedServer) DeleteKeyPolicy(_ context.Context, in *pb.DeleteKeyPolicyRequest) (*pb.DeleteKeyPolicyResponse, error) {
	return answer[*pb.DeleteKeyPolicyResponse](s, in)
}

func (s *cannedServer) SetKeyRotationPolicy(_ context.Context, in *pb.SetKeyRotationPolicyRequest) (*pb.SetKeyRotationPolicyResponse, error) {
	return answer[*pb.SetKeyRotationPolicyResponse](s, in)
}

func (s *cannedServer) GetKeyRotationPolicy(_ context.Context, in *pb.GetKeyRotationPolicyRequest) (*pb.GetKeyRotationPolicyResponse, error) {
	return answer[*pb.GetKeyRotationPolicyResponse](s, in)
}

func (s *cannedServer) DeleteKeyRotationPolicy(_ context.Context, in *pb.DeleteKeyRotationPolicyRequest) (*pb.DeleteKeyRotationPolicyResponse, error) {
	return answer[*pb.DeleteKeyRotationPolicyResponse](s, in)
}

func (s *cannedServer) GetSupportedAlgorithms(_ context.Context, in *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error) {
	return answer[*pb.GetSupportedAlgorithmsResponse](s, in)
}

func (s *cannedServer) BackendStatus(_ context.Context, in *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error) {
	return answer[*pb.BackendStatusResponse](s, in)
}

func (s *cannedServer) BackendTest(_ context.Context, in *pb.BackendTestRequest) (*pb.BackendTestResponse, error) {
	return answer[*pb.BackendTestResponse](s, in)
}

func (s *cannedServer) SetKeySafety(_ context.Context, in *pb.SetKeySafetyRequest) (*pb.SetKeySafetyResponse, error) {
	return answer[*pb.SetKeySafetyResponse](s, in)
}

func (s *cannedServer) ClearKeySafety(_ context.Context, in *pb.ClearKeySafetyRequest) (*pb.ClearKeySafetyResponse, error) {
	return answer[*pb.ClearKeySafetyResponse](s, in)
}

func (s *cannedServer) SafetyCheck(_ context.Context, in *pb.SafetyCheckRequest) (*pb.SafetyCheckResponse, error) {
	return answer[*pb.SafetyCheckResponse](s, in)
}

func (s *cannedServer) SafetyReport(_ context.Context, in *pb.SafetyReportRequest) (*pb.SafetyReportResponse, error) {
	return answer[*pb.SafetyReportResponse](s, in)
}

func sampleRotationPolicy() *transport.RotationPolicy {
	return &transport.RotationPolicy{Enabled: true, IntervalSeconds: 86400, NextRotation: 1700000000, RetainVersions: 3, AutoRotate: true}
}

func sampleRotationPolicyPB() *pb.RotationPolicy {
	return &pb.RotationPolicy{Enabled: true, IntervalSeconds: 86400, NextRotation: 1700000000, RetainVersions: 3, AutoRotate: true}
}

func sampleKeyPolicy() *transport.KeyPolicy {
	return &transport.KeyPolicy{
		KeyID:             "k1",
		Version:           2,
		AllowedOperations: []transport.KeyUsage{transport.KeyUsageSign, transport.KeyUsageVerify},
		AllowedPrincipals: []string{"alice"},
		DeniedPrincipals:  []string{"mallory"},
		ExpiresAt:         1800000000,
		RotationRequired:  true,
		MaxUsageCount:     1000,
		RequireMFA:        true,
		UpdatedAt:         1700000000,
	}
}

func sampleKeyPolicyPB() *pb.KeyPolicy {
	return &pb.KeyPolicy{
		KeyId:             "k1",
		Version:           2,
		AllowedOperations: []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN, pb.KeyUsage_KEY_USAGE_VERIFY},
		AllowedPrincipals: []string{"alice"},
		DeniedPrincipals:  []string{"mallory"},
		ExpiresAt:         1800000000,
		RotationRequired:  true,
		MaxUsageCount:     1000,
		RequireMfa:        true,
		UpdatedAt:         1700000000,
	}
}

func sampleKeyMetadata() *transport.KeyMetadata {
	return &transport.KeyMetadata{
		KeyID:              "k1",
		Name:               "signing",
		Description:        "release signing key",
		Algorithm:          transport.KeyAlgorithmECDSAP384,
		Status:             transport.KeyStatusEnabled,
		Usage:              []transport.KeyUsage{transport.KeyUsageSign},
		Version:            2,
		Exportable:         true,
		DeletionProtection: true,
		CreatedAt:          1600000000,
		UpdatedAt:          1700000000,
		LastUsedAt:         1750000000,
		RotationPolicy:     sampleRotationPolicy(),
		Tags:               map[string]string{"team": "release"},
		Owner:              "alice",
	}
}

func sampleKeyMetadataPB() *pb.KeyMetadata {
	return &pb.KeyMetadata{
		KeyId:              "k1",
		Name:               "signing",
		Description:        "release signing key",
		Algorithm:          pb.KeyAlgorithm_KEY_ALG_ECDSA_P384,
		Status:             pb.KeyStatus_KEY_STATUS_ENABLED,
		Usage:              []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN},
		Version:            2,
		Exportable:         true,
		DeletionProtection: true,
		CreatedAt:          1600000000,
		UpdatedAt:          1700000000,
		LastUsedAt:         1750000000,
		RotationPolicy:     sampleRotationPolicyPB(),
		Tags:               map[string]string{"team": "release"},
		Owner:              "alice",
	}
}

func sampleSafetyWarnings() []transport.SafetyWarning {
	return []transport.SafetyWarning{{
		Type: "key", Path: "k1", UsagePercent: 92.5, Status: "critical",
		OperationsUsed: 925, BytesUsed: 4096, MaxOperations: 1000, MaxBytes: 8192,
	}}
}

func sampleSafetyWarningsPB() []*pb.SafetyWarning {
	return []*pb.SafetyWarning{{
		Type: "key", Path: "k1", UsagePercent: 92.5, Status: "critical",
		OperationsUsed: 925, BytesUsed: 4096, MaxOperations: 1000, MaxBytes: 8192,
	}}
}

// TestKeyEnums_RoundTrip asserts every mapped status, algorithm and usage
// survives the trip to its wire enum and back, and that no two transport
// values share a wire enum (invert would silently drop one).
func TestKeyEnums_RoundTrip(t *testing.T) {
	require.Len(t, keyStatusFromProto, len(keyStatusToProto))
	for s := range keyStatusToProto {
		assert.NotEqual(t, pb.KeyStatus(0), KeyStatusToProto(s), s)
		assert.Equal(t, s, KeyStatusFromProto(KeyStatusToProto(s)))
	}
	require.Len(t, keyAlgorithmFromProto, len(keyAlgorithmToProto))
	for a := range keyAlgorithmToProto {
		assert.NotEqual(t, pb.KeyAlgorithm(0), KeyAlgorithmToProto(a), a)
		assert.Equal(t, a, KeyAlgorithmFromProto(KeyAlgorithmToProto(a)))
	}
	require.Len(t, keyUsageFromProto, len(keyUsageToProto))
	usages := make([]transport.KeyUsage, 0, len(keyUsageToProto))
	for u := range keyUsageToProto {
		usages = append(usages, u)
	}
	assert.Equal(t, usages, KeyUsagesFromProto(KeyUsagesToProto(usages)))
}

// TestKeyEnums_Unknown pins that a value outside the maps converts to the
// zero value (the wire's UNSPECIFIED, the transport's empty string) rather
// than to some other valid value.
func TestKeyEnums_Unknown(t *testing.T) {
	assert.Equal(t, pb.KeyStatus(0), KeyStatusToProto("bogus"))
	assert.Equal(t, transport.KeyStatus(""), KeyStatusFromProto(pb.KeyStatus(9999)))
	assert.Equal(t, pb.KeyAlgorithm(0), KeyAlgorithmToProto("bogus"))
	assert.Equal(t, transport.KeyAlgorithm(""), KeyAlgorithmFromProto(pb.KeyAlgorithm(9999)))
	assert.Equal(t, []pb.KeyUsage{0}, KeyUsagesToProto([]transport.KeyUsage{"bogus"}))
	assert.Equal(t, []transport.KeyUsage{""}, KeyUsagesFromProto([]pb.KeyUsage{9999}))
}

// TestKeyMgmt_Nil pins that absent values stay absent, and that an empty
// usage list stays empty rather than becoming nil.
func TestKeyMgmt_Nil(t *testing.T) {
	assert.Nil(t, KeyUsagesToProto(nil))
	assert.Nil(t, KeyUsagesFromProto(nil))
	assert.Equal(t, []pb.KeyUsage{}, KeyUsagesToProto([]transport.KeyUsage{}))
	assert.Equal(t, []transport.KeyUsage{}, KeyUsagesFromProto([]pb.KeyUsage{}))
	assert.Nil(t, RotationPolicyToProto(nil))
	assert.Nil(t, RotationPolicyFromProto(nil))
	assert.Nil(t, KeyPolicyToProto(nil))
	assert.Nil(t, KeyPolicyFromProto(nil))
	assert.Nil(t, KeyMetadataToProto(nil))
	assert.Nil(t, KeyMetadataFromProto(nil))
}

func TestKeyManagementConversions_RoundTrip(t *testing.T) {
	assert.Equal(t, sampleKeyMetadataPB(), KeyMetadataToProto(sampleKeyMetadata()))
	assert.Equal(t, sampleKeyMetadata(), KeyMetadataFromProto(KeyMetadataToProto(sampleKeyMetadata())))
	assert.Equal(t, sampleKeyPolicy(), KeyPolicyFromProto(KeyPolicyToProto(sampleKeyPolicy())))
	assert.Equal(t, sampleSafetyWarnings(), SafetyWarningsFromProto(SafetyWarningsToProto(sampleSafetyWarnings())))

	algorithms := []transport.KeyAlgorithm{transport.KeyAlgorithmAES256GCM, transport.KeyAlgorithmEd25519}
	assert.Equal(t, algorithms, KeyAlgorithmNamesFromProto(KeyAlgorithmNamesToProto(algorithms)))

	update := &transport.UpdateKeyMetadataRequest{
		Backend: "software", KeyID: "k1", Name: "n", Description: "d",
		Tags: map[string]string{"a": "b"}, RemoveTags: []string{"c"}, TenantID: "tenant-a",
	}
	untenanted := *update
	untenanted.TenantID = ""
	assert.Equal(t, &untenanted, UpdateKeyMetadataRequestFromProto(UpdateKeyMetadataRequestToProto(update)))

	status := &transport.BackendStatusResponse{
		BackendType: "tpm2", Status: "ok", Device: "/dev/tpmrm0", Region: "local", KeyID: "srk",
		PCRBanks: []string{"sha256"}, PCRRegisters: []int32{0, 7}, Capabilities: map[string]bool{"seal": true}, Timestamp: 1700000000,
	}
	assert.Equal(t, status, BackendStatusResponseFromProto(BackendStatusResponseToProto(status)))

	report := &transport.SafetyReportResponse{
		AllItems: sampleSafetyWarnings(), TotalKeys: 4, TotalDEKs: 9,
		KeysAtWarning: 1, KeysAtCritical: 2, DEKsAtWarning: 3, DEKsAtCritical: 4, Timestamp: 1700000000,
	}
	assert.Equal(t, report, SafetyReportResponseFromProto(SafetyReportResponseToProto(report)))
}

func TestKeyManagementClient_CarriesEveryRequest(t *testing.T) {
	keyReq := &transport.KeyManagementRequest{Backend: "software", KeyID: "k1", TenantID: "tenant-a"}
	backendReq := &transport.BackendRequest{Backend: "tpm2", TenantID: "tenant-a"}
	deleted := &transport.KeyManagementResponse{KeyID: "k1", Timestamp: 1700000000}
	rotation := &transport.KeyRotationPolicyResponse{KeyID: "k1", Policy: sampleRotationPolicy(), Timestamp: 1700000000}

	runClientCases(t, func(c pb.KeystoreServiceClient) KeyManagementClient { return KeyManagementClient{Client: c} }, []clientCase[KeyManagementClient]{
		{
			name: "GetPublicKey",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k1", Version: 2, TenantID: "tenant-a"})
			},
			wantReq: &pb.GetPublicKeyRequest{KeyId: "k1", Version: 2, Backend: "software"},
			reply:   &pb.GetPublicKeyResponse{KeyId: "k1", PublicKey: []byte("pub"), Algorithm: pb.KeyAlgorithm_KEY_ALG_ED25519, Version: 2, Timestamp: 1700000000},
			want:    &transport.GetPublicKeyResponse{KeyID: "k1", PublicKey: []byte("pub"), Algorithm: transport.KeyAlgorithmEd25519, Version: 2, Timestamp: 1700000000},
		},
		{
			name: "RevokeKey",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "k1", Reason: "compromised"})
			},
			wantReq: &pb.RevokeKeyRequest{KeyId: "k1", Reason: "compromised", Backend: "software"},
			reply:   &pb.RevokeKeyResponse{KeyId: "k1", Status: pb.KeyStatus_KEY_STATUS_COMPROMISED, Timestamp: 1700000000},
			want:    &transport.RevokeKeyResponse{KeyID: "k1", Status: transport.KeyStatusCompromised, Timestamp: 1700000000},
		},
		{
			name: "UpdateKeyStatus",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "k1", Version: 2, Status: transport.KeyStatusDisabled})
			},
			wantReq: &pb.UpdateKeyStatusRequest{KeyId: "k1", Version: 2, Status: pb.KeyStatus_KEY_STATUS_DISABLED, Backend: "software"},
			reply:   &pb.UpdateKeyStatusResponse{KeyId: "k1", Version: 2, Status: pb.KeyStatus_KEY_STATUS_DISABLED, Timestamp: 1700000000},
			want:    &transport.UpdateKeyStatusResponse{KeyID: "k1", Version: 2, Status: transport.KeyStatusDisabled, Timestamp: 1700000000},
		},
		{
			name: "GetKeyMetadata",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.GetKeyMetadata(ctx, keyReq)
			},
			wantReq: &pb.GetKeyMetadataRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.GetKeyMetadataResponse{Metadata: sampleKeyMetadataPB(), Timestamp: 1700000000},
			want:    &transport.KeyMetadataResponse{Metadata: sampleKeyMetadata(), Timestamp: 1700000000},
		},
		{
			name: "UpdateKeyMetadata",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "k1", Name: "n",
					Description: "d", Tags: map[string]string{"a": "b"}, RemoveTags: []string{"c"}})
			},
			wantReq: &pb.UpdateKeyMetadataRequest{KeyId: "k1", Name: "n", Description: "d",
				Tags: map[string]string{"a": "b"}, RemoveTags: []string{"c"}, Backend: "software"},
			reply: &pb.UpdateKeyMetadataResponse{Metadata: sampleKeyMetadataPB(), Timestamp: 1700000000},
			want:  &transport.KeyMetadataResponse{Metadata: sampleKeyMetadata(), Timestamp: 1700000000},
		},
		{
			name: "SetKeyPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "k1", Policy: sampleKeyPolicy()})
			},
			wantReq: &pb.SetKeyPolicyRequest{KeyId: "k1", Policy: sampleKeyPolicyPB(), Backend: "software"},
			reply:   &pb.SetKeyPolicyResponse{KeyId: "k1", PolicyVersion: 3, Timestamp: 1700000000},
			want:    &transport.SetKeyPolicyResponse{KeyID: "k1", PolicyVersion: 3, Timestamp: 1700000000},
		},
		{
			name: "GetKeyPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.GetKeyPolicy(ctx, keyReq)
			},
			wantReq: &pb.GetKeyPolicyRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.GetKeyPolicyResponse{Policy: sampleKeyPolicyPB(), Timestamp: 1700000000},
			want:    &transport.GetKeyPolicyResponse{Policy: sampleKeyPolicy(), Timestamp: 1700000000},
		},
		{
			name: "DeleteKeyPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.DeleteKeyPolicy(ctx, keyReq)
			},
			wantReq: &pb.DeleteKeyPolicyRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.DeleteKeyPolicyResponse{KeyId: "k1", Timestamp: 1700000000},
			want:    deleted,
		},
		{
			name: "SetKeyRotationPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "k1", Policy: sampleRotationPolicy()})
			},
			wantReq: &pb.SetKeyRotationPolicyRequest{KeyId: "k1", Policy: sampleRotationPolicyPB(), Backend: "software"},
			reply:   &pb.SetKeyRotationPolicyResponse{KeyId: "k1", Policy: sampleRotationPolicyPB(), Timestamp: 1700000000},
			want:    rotation,
		},
		{
			name: "GetKeyRotationPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.GetKeyRotationPolicy(ctx, keyReq)
			},
			wantReq: &pb.GetKeyRotationPolicyRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.GetKeyRotationPolicyResponse{KeyId: "k1", Policy: sampleRotationPolicyPB(), Timestamp: 1700000000},
			want:    rotation,
		},
		{
			name: "DeleteKeyRotationPolicy",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.DeleteKeyRotationPolicy(ctx, keyReq)
			},
			wantReq: &pb.DeleteKeyRotationPolicyRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.DeleteKeyRotationPolicyResponse{KeyId: "k1", Timestamp: 1700000000},
			want:    deleted,
		},
		{
			name: "GetSupportedAlgorithms",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.GetSupportedAlgorithms(ctx, backendReq)
			},
			wantReq: &pb.GetSupportedAlgorithmsRequest{Backend: "tpm2"},
			reply:   &pb.GetSupportedAlgorithmsResponse{Algorithms: []string{string(transport.KeyAlgorithmRSA2048), string(transport.KeyAlgorithmECDSAP256)}},
			want:    &transport.GetSupportedAlgorithmsResponse{Algorithms: []transport.KeyAlgorithm{transport.KeyAlgorithmRSA2048, transport.KeyAlgorithmECDSAP256}},
		},
		{
			name: "BackendStatus",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.BackendStatus(ctx, backendReq)
			},
			wantReq: &pb.BackendStatusRequest{Backend: "tpm2"},
			reply: &pb.BackendStatusResponse{BackendType: "tpm2", Status: "ok", Device: "/dev/tpmrm0", PcrBanks: []string{"sha256"},
				PcrRegisters: []int32{7}, Capabilities: map[string]bool{"seal": true}, Timestamp: 1700000000},
			want: &transport.BackendStatusResponse{BackendType: "tpm2", Status: "ok", Device: "/dev/tpmrm0", PCRBanks: []string{"sha256"},
				PCRRegisters: []int32{7}, Capabilities: map[string]bool{"seal": true}, Timestamp: 1700000000},
		},
		{
			name: "BackendTest",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.BackendTest(ctx, backendReq)
			},
			wantReq: &pb.BackendTestRequest{Backend: "tpm2"},
			reply:   &pb.BackendTestResponse{Success: true, DurationMs: 42, Message: "sign and verify passed", Timestamp: 1700000000},
			want:    &transport.BackendTestResponse{Success: true, DurationMS: 42, Message: "sign and verify passed", Timestamp: 1700000000},
		},
		{
			name: "SetKeySafety",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "k1", MaxOperations: 1000, MaxBytes: 8192, WarningPercent: 80})
			},
			wantReq: &pb.SetKeySafetyRequest{KeyId: "k1", MaxOperations: 1000, MaxBytes: 8192, WarningPercent: 80, Backend: "software"},
			reply:   &pb.SetKeySafetyResponse{KeyId: "k1", Timestamp: 1700000000},
			want:    deleted,
		},
		{
			name: "ClearKeySafety",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.ClearKeySafety(ctx, keyReq)
			},
			wantReq: &pb.ClearKeySafetyRequest{KeyId: "k1", Backend: "software"},
			reply:   &pb.ClearKeySafetyResponse{KeyId: "k1", Timestamp: 1700000000},
			want:    deleted,
		},
		{
			name: "SafetyCheck",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.SafetyCheck(ctx, &transport.SafetyCheckRequest{TenantID: "tenant-a"})
			},
			wantReq: &pb.SafetyCheckRequest{},
			reply:   &pb.SafetyCheckResponse{Warnings: sampleSafetyWarningsPB(), Timestamp: 1700000000},
			want:    &transport.SafetyCheckResponse{Warnings: sampleSafetyWarnings(), Timestamp: 1700000000},
		},
		{
			name: "SafetyReport",
			call: func(ctx context.Context, c KeyManagementClient) (any, error) {
				return c.SafetyReport(ctx, &transport.SafetyReportRequest{Format: "json"})
			},
			wantReq: &pb.SafetyReportRequest{Format: "json"},
			reply:   &pb.SafetyReportResponse{AllItems: sampleSafetyWarningsPB(), TotalKeys: 4, KeysAtCritical: 1, Timestamp: 1700000000},
			want:    &transport.SafetyReportResponse{AllItems: sampleSafetyWarnings(), TotalKeys: 4, KeysAtCritical: 1, Timestamp: 1700000000},
		},
	})
}

func testRotationPolicy() *transport.RotationPolicy {
	return &transport.RotationPolicy{Enabled: true, IntervalSeconds: 86400, NextRotation: 1700000000, RetainVersions: 3, AutoRotate: true}
}

func testKeyPolicy() *transport.KeyPolicy {
	return &transport.KeyPolicy{
		KeyID:             "k",
		Version:           2,
		AllowedOperations: []transport.KeyUsage{transport.KeyUsageSign, transport.KeyUsageVerify},
		AllowedPrincipals: []string{"alice"},
		DeniedPrincipals:  []string{"mallory"},
		ExpiresAt:         1800000000,
		RotationRequired:  true,
		MaxUsageCount:     1000,
		RequireMFA:        true,
		UpdatedAt:         1700000001,
	}
}

func testKeyMetadata() *transport.KeyMetadata {
	return &transport.KeyMetadata{
		KeyID:              "k",
		Name:               "signing",
		Description:        "release signing key",
		Algorithm:          transport.KeyAlgorithmECDSAP256,
		Status:             transport.KeyStatusEnabled,
		Usage:              []transport.KeyUsage{transport.KeyUsageSign},
		Version:            4,
		Exportable:         true,
		DeletionProtection: true,
		CreatedAt:          1700000000,
		UpdatedAt:          1700000001,
		LastUsedAt:         1700000002,
		RotationPolicy:     testRotationPolicy(),
		Tags:               map[string]string{"env": "prod"},
		Owner:              "alice",
	}
}

func testSafetyWarnings() []transport.SafetyWarning {
	return []transport.SafetyWarning{{
		Type: "key", Path: "software/k", UsagePercent: 85.5, Status: "warning",
		OperationsUsed: 855, BytesUsed: 4096, MaxOperations: 1000, MaxBytes: 8192,
	}}
}

// TestKeyMgmt_RoundTrip asserts every field of every key-management
// conversion survives the trip to the wire and back.
func TestKeyMgmt_RoundTrip(t *testing.T) {
	tests := map[string]struct {
		in   any
		trip func(any) any
	}{
		"rotation-policy": {testRotationPolicy(), func(v any) any {
			return RotationPolicyFromProto(RotationPolicyToProto(v.(*transport.RotationPolicy)))
		}},
		"key-policy": {testKeyPolicy(), func(v any) any {
			return KeyPolicyFromProto(KeyPolicyToProto(v.(*transport.KeyPolicy)))
		}},
		"key-metadata": {testKeyMetadata(), func(v any) any {
			return KeyMetadataFromProto(KeyMetadataToProto(v.(*transport.KeyMetadata)))
		}},
		"algorithm-names": {[]transport.KeyAlgorithm{transport.KeyAlgorithmRSA2048, transport.KeyAlgorithmEd25519}, func(v any) any {
			return KeyAlgorithmNamesFromProto(KeyAlgorithmNamesToProto(v.([]transport.KeyAlgorithm)))
		}},
		"safety-warnings": {testSafetyWarnings(), func(v any) any {
			return SafetyWarningsFromProto(SafetyWarningsToProto(v.([]transport.SafetyWarning)))
		}},
		"update-metadata-request": {&transport.UpdateKeyMetadataRequest{
			Backend: "software", KeyID: "k", Name: "n", Description: "d",
			Tags: map[string]string{"env": "prod"}, RemoveTags: []string{"stale"},
		}, func(v any) any {
			return UpdateKeyMetadataRequestFromProto(UpdateKeyMetadataRequestToProto(v.(*transport.UpdateKeyMetadataRequest)))
		}},
		"backend-status": {&transport.BackendStatusResponse{
			BackendType: "tpm2", Status: "ok", Device: "/dev/tpmrm0", Region: "local", KeyID: "srk",
			PCRBanks: []string{"sha256"}, PCRRegisters: []int32{0, 7}, Capabilities: map[string]bool{"seal": true}, Timestamp: 1700000000,
		}, func(v any) any {
			return BackendStatusResponseFromProto(BackendStatusResponseToProto(v.(*transport.BackendStatusResponse)))
		}},
		"safety-report": {&transport.SafetyReportResponse{
			AllItems: testSafetyWarnings(), TotalKeys: 10, TotalDEKs: 20,
			KeysAtWarning: 1, KeysAtCritical: 2, DEKsAtWarning: 3, DEKsAtCritical: 4, Timestamp: 1700000000,
		}, func(v any) any {
			return SafetyReportResponseFromProto(SafetyReportResponseToProto(v.(*transport.SafetyReportResponse)))
		}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.in, tt.trip(tt.in))
		})
	}
}

// keyMgmtRecorder answers every key-management call with a canned response
// and records the request it was sent.
type keyMgmtRecorder struct {
	pb.KeystoreServiceClient
	sent any
}

const testTimestamp = int64(1700000000)

func (r *keyMgmtRecorder) GetPublicKey(_ context.Context, in *pb.GetPublicKeyRequest, _ ...grpc.CallOption) (*pb.GetPublicKeyResponse, error) {
	r.sent = in
	return &pb.GetPublicKeyResponse{KeyId: in.GetKeyId(), PublicKey: []byte("pub"), Algorithm: pb.KeyAlgorithm_KEY_ALG_ED25519, Version: in.GetVersion(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) RevokeKey(_ context.Context, in *pb.RevokeKeyRequest, _ ...grpc.CallOption) (*pb.RevokeKeyResponse, error) {
	r.sent = in
	return &pb.RevokeKeyResponse{KeyId: in.GetKeyId(), Status: pb.KeyStatus_KEY_STATUS_COMPROMISED, Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) UpdateKeyStatus(_ context.Context, in *pb.UpdateKeyStatusRequest, _ ...grpc.CallOption) (*pb.UpdateKeyStatusResponse, error) {
	r.sent = in
	return &pb.UpdateKeyStatusResponse{KeyId: in.GetKeyId(), Version: in.GetVersion(), Status: in.GetStatus(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) GetKeyMetadata(_ context.Context, in *pb.GetKeyMetadataRequest, _ ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error) {
	r.sent = in
	return &pb.GetKeyMetadataResponse{Metadata: KeyMetadataToProto(testKeyMetadata()), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) UpdateKeyMetadata(_ context.Context, in *pb.UpdateKeyMetadataRequest, _ ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error) {
	r.sent = in
	return &pb.UpdateKeyMetadataResponse{Metadata: KeyMetadataToProto(testKeyMetadata()), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) SetKeyPolicy(_ context.Context, in *pb.SetKeyPolicyRequest, _ ...grpc.CallOption) (*pb.SetKeyPolicyResponse, error) {
	r.sent = in
	return &pb.SetKeyPolicyResponse{KeyId: in.GetKeyId(), PolicyVersion: 3, Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) GetKeyPolicy(_ context.Context, in *pb.GetKeyPolicyRequest, _ ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error) {
	r.sent = in
	return &pb.GetKeyPolicyResponse{Policy: KeyPolicyToProto(testKeyPolicy()), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) DeleteKeyPolicy(_ context.Context, in *pb.DeleteKeyPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteKeyPolicyResponse, error) {
	r.sent = in
	return &pb.DeleteKeyPolicyResponse{KeyId: in.GetKeyId(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) SetKeyRotationPolicy(_ context.Context, in *pb.SetKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.SetKeyRotationPolicyResponse, error) {
	r.sent = in
	return &pb.SetKeyRotationPolicyResponse{KeyId: in.GetKeyId(), Policy: in.GetPolicy(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) GetKeyRotationPolicy(_ context.Context, in *pb.GetKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.GetKeyRotationPolicyResponse, error) {
	r.sent = in
	return &pb.GetKeyRotationPolicyResponse{KeyId: in.GetKeyId(), Policy: RotationPolicyToProto(testRotationPolicy()), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) DeleteKeyRotationPolicy(_ context.Context, in *pb.DeleteKeyRotationPolicyRequest, _ ...grpc.CallOption) (*pb.DeleteKeyRotationPolicyResponse, error) {
	r.sent = in
	return &pb.DeleteKeyRotationPolicyResponse{KeyId: in.GetKeyId(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) GetSupportedAlgorithms(_ context.Context, in *pb.GetSupportedAlgorithmsRequest, _ ...grpc.CallOption) (*pb.GetSupportedAlgorithmsResponse, error) {
	r.sent = in
	return &pb.GetSupportedAlgorithmsResponse{Algorithms: []string{"ed25519", "rsa-2048"}}, nil
}

func (r *keyMgmtRecorder) BackendStatus(_ context.Context, in *pb.BackendStatusRequest, _ ...grpc.CallOption) (*pb.BackendStatusResponse, error) {
	r.sent = in
	return &pb.BackendStatusResponse{BackendType: in.GetBackend(), Status: "ok", Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) BackendTest(_ context.Context, in *pb.BackendTestRequest, _ ...grpc.CallOption) (*pb.BackendTestResponse, error) {
	r.sent = in
	return &pb.BackendTestResponse{Success: true, DurationMs: 12, Message: "ok", Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) SetKeySafety(_ context.Context, in *pb.SetKeySafetyRequest, _ ...grpc.CallOption) (*pb.SetKeySafetyResponse, error) {
	r.sent = in
	return &pb.SetKeySafetyResponse{KeyId: in.GetKeyId(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) ClearKeySafety(_ context.Context, in *pb.ClearKeySafetyRequest, _ ...grpc.CallOption) (*pb.ClearKeySafetyResponse, error) {
	r.sent = in
	return &pb.ClearKeySafetyResponse{KeyId: in.GetKeyId(), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) SafetyCheck(_ context.Context, in *pb.SafetyCheckRequest, _ ...grpc.CallOption) (*pb.SafetyCheckResponse, error) {
	r.sent = in
	return &pb.SafetyCheckResponse{Warnings: SafetyWarningsToProto(testSafetyWarnings()), Timestamp: testTimestamp}, nil
}

func (r *keyMgmtRecorder) SafetyReport(_ context.Context, in *pb.SafetyReportRequest, _ ...grpc.CallOption) (*pb.SafetyReportResponse, error) {
	r.sent = in
	return &pb.SafetyReportResponse{AllItems: SafetyWarningsToProto(testSafetyWarnings()), TotalKeys: 10, Timestamp: testTimestamp}, nil
}

// TestKeyManagementClient_Calls asserts each verb puts its request fields on
// the wire and maps the wire response back field for field.
func TestKeyManagementClient_Calls(t *testing.T) {
	ctx := context.Background()
	rec := &keyMgmtRecorder{}
	c := KeyManagementClient{Client: rec}
	byKey := &transport.KeyManagementRequest{Backend: "software", KeyID: "k"}
	byBackend := &transport.BackendRequest{Backend: "tpm2"}

	pub, err := c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{Backend: "software", KeyID: "k", Version: 2})
	require.NoError(t, err)
	assert.Equal(t, &pb.GetPublicKeyRequest{KeyId: "k", Version: 2, Backend: "software"}, rec.sent)
	assert.Equal(t, &transport.GetPublicKeyResponse{KeyID: "k", PublicKey: []byte("pub"), Algorithm: transport.KeyAlgorithmEd25519, Version: 2, Timestamp: testTimestamp}, pub)

	revoked, err := c.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "k", Reason: "leaked"})
	require.NoError(t, err)
	assert.Equal(t, &pb.RevokeKeyRequest{KeyId: "k", Reason: "leaked", Backend: "software"}, rec.sent)
	assert.Equal(t, &transport.RevokeKeyResponse{KeyID: "k", Status: transport.KeyStatusCompromised, Timestamp: testTimestamp}, revoked)

	status, err := c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "k", Version: 2, Status: transport.KeyStatusDisabled})
	require.NoError(t, err)
	assert.Equal(t, &pb.UpdateKeyStatusRequest{KeyId: "k", Version: 2, Status: pb.KeyStatus_KEY_STATUS_DISABLED, Backend: "software"}, rec.sent)
	assert.Equal(t, &transport.UpdateKeyStatusResponse{KeyID: "k", Version: 2, Status: transport.KeyStatusDisabled, Timestamp: testTimestamp}, status)

	metadata := &transport.KeyMetadataResponse{Metadata: testKeyMetadata(), Timestamp: testTimestamp}
	got, err := c.GetKeyMetadata(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.GetKeyMetadataRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, metadata, got)

	update := &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "k", Name: "renamed"}
	got, err = c.UpdateKeyMetadata(ctx, update)
	require.NoError(t, err)
	assert.Equal(t, update, UpdateKeyMetadataRequestFromProto(rec.sent.(*pb.UpdateKeyMetadataRequest)))
	assert.Equal(t, metadata, got)

	set, err := c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "k", Policy: testKeyPolicy()})
	require.NoError(t, err)
	assert.Equal(t, testKeyPolicy(), KeyPolicyFromProto(rec.sent.(*pb.SetKeyPolicyRequest).GetPolicy()))
	assert.Equal(t, &transport.SetKeyPolicyResponse{KeyID: "k", PolicyVersion: 3, Timestamp: testTimestamp}, set)

	policy, err := c.GetKeyPolicy(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.GetKeyPolicyRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, &transport.GetKeyPolicyResponse{Policy: testKeyPolicy(), Timestamp: testTimestamp}, policy)

	ack := &transport.KeyManagementResponse{KeyID: "k", Timestamp: testTimestamp}
	gotAck, err := c.DeleteKeyPolicy(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.DeleteKeyPolicyRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, ack, gotAck)

	rotation := &transport.KeyRotationPolicyResponse{KeyID: "k", Policy: testRotationPolicy(), Timestamp: testTimestamp}
	gotRotation, err := c.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "k", Policy: testRotationPolicy()})
	require.NoError(t, err)
	assert.Equal(t, "software", rec.sent.(*pb.SetKeyRotationPolicyRequest).GetBackend())
	assert.Equal(t, rotation, gotRotation)

	gotRotation, err = c.GetKeyRotationPolicy(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.GetKeyRotationPolicyRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, rotation, gotRotation)

	gotAck, err = c.DeleteKeyRotationPolicy(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.DeleteKeyRotationPolicyRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, ack, gotAck)

	algorithms, err := c.GetSupportedAlgorithms(ctx, byBackend)
	require.NoError(t, err)
	assert.Equal(t, &pb.GetSupportedAlgorithmsRequest{Backend: "tpm2"}, rec.sent)
	assert.Equal(t, []transport.KeyAlgorithm{"ed25519", "rsa-2048"}, algorithms.Algorithms)

	backend, err := c.BackendStatus(ctx, byBackend)
	require.NoError(t, err)
	assert.Equal(t, &pb.BackendStatusRequest{Backend: "tpm2"}, rec.sent)
	assert.Equal(t, &transport.BackendStatusResponse{BackendType: "tpm2", Status: "ok", Timestamp: testTimestamp}, backend)

	tested, err := c.BackendTest(ctx, byBackend)
	require.NoError(t, err)
	assert.Equal(t, &pb.BackendTestRequest{Backend: "tpm2"}, rec.sent)
	assert.Equal(t, &transport.BackendTestResponse{Success: true, DurationMS: 12, Message: "ok", Timestamp: testTimestamp}, tested)

	gotAck, err = c.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "k", MaxOperations: 1000, MaxBytes: 8192, WarningPercent: 80})
	require.NoError(t, err)
	assert.Equal(t, &pb.SetKeySafetyRequest{KeyId: "k", MaxOperations: 1000, MaxBytes: 8192, WarningPercent: 80, Backend: "software"}, rec.sent)
	assert.Equal(t, ack, gotAck)

	gotAck, err = c.ClearKeySafety(ctx, byKey)
	require.NoError(t, err)
	assert.Equal(t, &pb.ClearKeySafetyRequest{KeyId: "k", Backend: "software"}, rec.sent)
	assert.Equal(t, ack, gotAck)

	check, err := c.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, &transport.SafetyCheckResponse{Warnings: testSafetyWarnings(), Timestamp: testTimestamp}, check)

	report, err := c.SafetyReport(ctx, &transport.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	assert.Equal(t, &pb.SafetyReportRequest{Format: "json"}, rec.sent)
	assert.Equal(t, testSafetyWarnings(), report.AllItems)
	assert.Equal(t, int32(10), report.TotalKeys)
}

func (c failingKeystoreClient) GetPublicKey(context.Context, *pb.GetPublicKeyRequest, ...grpc.CallOption) (*pb.GetPublicKeyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) RevokeKey(context.Context, *pb.RevokeKeyRequest, ...grpc.CallOption) (*pb.RevokeKeyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) UpdateKeyStatus(context.Context, *pb.UpdateKeyStatusRequest, ...grpc.CallOption) (*pb.UpdateKeyStatusResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GetKeyMetadata(context.Context, *pb.GetKeyMetadataRequest, ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) UpdateKeyMetadata(context.Context, *pb.UpdateKeyMetadataRequest, ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) SetKeyPolicy(context.Context, *pb.SetKeyPolicyRequest, ...grpc.CallOption) (*pb.SetKeyPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GetKeyPolicy(context.Context, *pb.GetKeyPolicyRequest, ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) DeleteKeyPolicy(context.Context, *pb.DeleteKeyPolicyRequest, ...grpc.CallOption) (*pb.DeleteKeyPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) SetKeyRotationPolicy(context.Context, *pb.SetKeyRotationPolicyRequest, ...grpc.CallOption) (*pb.SetKeyRotationPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GetKeyRotationPolicy(context.Context, *pb.GetKeyRotationPolicyRequest, ...grpc.CallOption) (*pb.GetKeyRotationPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) DeleteKeyRotationPolicy(context.Context, *pb.DeleteKeyRotationPolicyRequest, ...grpc.CallOption) (*pb.DeleteKeyRotationPolicyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) GetSupportedAlgorithms(context.Context, *pb.GetSupportedAlgorithmsRequest, ...grpc.CallOption) (*pb.GetSupportedAlgorithmsResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) BackendStatus(context.Context, *pb.BackendStatusRequest, ...grpc.CallOption) (*pb.BackendStatusResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) BackendTest(context.Context, *pb.BackendTestRequest, ...grpc.CallOption) (*pb.BackendTestResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) SetKeySafety(context.Context, *pb.SetKeySafetyRequest, ...grpc.CallOption) (*pb.SetKeySafetyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) ClearKeySafety(context.Context, *pb.ClearKeySafetyRequest, ...grpc.CallOption) (*pb.ClearKeySafetyResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) SafetyCheck(context.Context, *pb.SafetyCheckRequest, ...grpc.CallOption) (*pb.SafetyCheckResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) SafetyReport(context.Context, *pb.SafetyReportRequest, ...grpc.CallOption) (*pb.SafetyReportResponse, error) {
	return nil, c.err
}

func TestKeyManagementClient_Errors(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("rpc failed")
	c := KeyManagementClient{Client: failingKeystoreClient{err: rpcErr}}
	byKey := &transport.KeyManagementRequest{KeyID: "k"}
	byBackend := &transport.BackendRequest{Backend: "tpm2"}

	// Each call runs once with a nil request and once with a valid one.
	calls := map[string]func(valid bool) (any, error){
		"public-key": func(valid bool) (any, error) {
			if !valid {
				return c.GetPublicKey(ctx, nil)
			}
			return c.GetPublicKey(ctx, &transport.GetPublicKeyRequest{KeyID: "k"})
		},
		"revoke": func(valid bool) (any, error) {
			if !valid {
				return c.RevokeKey(ctx, nil)
			}
			return c.RevokeKey(ctx, &transport.RevokeKeyRequest{KeyID: "k"})
		},
		"status": func(valid bool) (any, error) {
			if !valid {
				return c.UpdateKeyStatus(ctx, nil)
			}
			return c.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{KeyID: "k"})
		},
		"get-metadata": func(valid bool) (any, error) {
			if !valid {
				return c.GetKeyMetadata(ctx, nil)
			}
			return c.GetKeyMetadata(ctx, byKey)
		},
		"update-metadata": func(valid bool) (any, error) {
			if !valid {
				return c.UpdateKeyMetadata(ctx, nil)
			}
			return c.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{KeyID: "k"})
		},
		"set-policy": func(valid bool) (any, error) {
			if !valid {
				return c.SetKeyPolicy(ctx, nil)
			}
			return c.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{KeyID: "k"})
		},
		"get-policy": func(valid bool) (any, error) {
			if !valid {
				return c.GetKeyPolicy(ctx, nil)
			}
			return c.GetKeyPolicy(ctx, byKey)
		},
		"delete-policy": func(valid bool) (any, error) {
			if !valid {
				return c.DeleteKeyPolicy(ctx, nil)
			}
			return c.DeleteKeyPolicy(ctx, byKey)
		},
		"set-rotation": func(valid bool) (any, error) {
			if !valid {
				return c.SetKeyRotationPolicy(ctx, nil)
			}
			return c.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{KeyID: "k"})
		},
		"get-rotation": func(valid bool) (any, error) {
			if !valid {
				return c.GetKeyRotationPolicy(ctx, nil)
			}
			return c.GetKeyRotationPolicy(ctx, byKey)
		},
		"delete-rotation": func(valid bool) (any, error) {
			if !valid {
				return c.DeleteKeyRotationPolicy(ctx, nil)
			}
			return c.DeleteKeyRotationPolicy(ctx, byKey)
		},
		"algorithms": func(valid bool) (any, error) {
			if !valid {
				return c.GetSupportedAlgorithms(ctx, nil)
			}
			return c.GetSupportedAlgorithms(ctx, byBackend)
		},
		"backend-status": func(valid bool) (any, error) {
			if !valid {
				return c.BackendStatus(ctx, nil)
			}
			return c.BackendStatus(ctx, byBackend)
		},
		"backend-test": func(valid bool) (any, error) {
			if !valid {
				return c.BackendTest(ctx, nil)
			}
			return c.BackendTest(ctx, byBackend)
		},
		"set-safety": func(valid bool) (any, error) {
			if !valid {
				return c.SetKeySafety(ctx, nil)
			}
			return c.SetKeySafety(ctx, &transport.SetKeySafetyRequest{KeyID: "k"})
		},
		"clear-safety": func(valid bool) (any, error) {
			if !valid {
				return c.ClearKeySafety(ctx, nil)
			}
			return c.ClearKeySafety(ctx, byKey)
		},
		"safety-check": func(valid bool) (any, error) {
			if !valid {
				return c.SafetyCheck(ctx, nil)
			}
			return c.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
		},
		"safety-report": func(valid bool) (any, error) {
			if !valid {
				return c.SafetyReport(ctx, nil)
			}
			return c.SafetyReport(ctx, &transport.SafetyReportRequest{})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			out, err := call(false)
			require.ErrorIs(t, err, ErrNilRequest)
			assert.Nil(t, out)
			out, err = call(true)
			require.ErrorIs(t, err, rpcErr)
			assert.Nil(t, out, "no partial result on a transport error")
		})
	}
}
