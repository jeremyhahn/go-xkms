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

func TestKeyManagementConversions_EveryEnumRoundTrips(t *testing.T) {
	// Each map must be one to one: a shared wire value would make invert
	// decode two values to the same one.
	for s := range keyStatusToProto {
		assert.Equal(t, s, KeyStatusFromProto(KeyStatusToProto(s)), "status %q", s)
	}
	assert.Len(t, keyStatusFromProto, len(keyStatusToProto))
	for a := range keyAlgorithmToProto {
		assert.Equal(t, a, KeyAlgorithmFromProto(KeyAlgorithmToProto(a)), "algorithm %q", a)
	}
	assert.Len(t, keyAlgorithmFromProto, len(keyAlgorithmToProto))
	usages := make([]transport.KeyUsage, 0, len(keyUsageToProto))
	for u := range keyUsageToProto {
		usages = append(usages, u)
	}
	assert.Equal(t, usages, KeyUsagesFromProto(KeyUsagesToProto(usages)))
	assert.Len(t, keyUsageFromProto, len(keyUsageToProto))
}

func TestKeyManagementConversions_UnknownValuesBecomeUnspecified(t *testing.T) {
	assert.Equal(t, pb.KeyStatus_KEY_STATUS_UNSPECIFIED, KeyStatusToProto("melted"))
	assert.Equal(t, transport.KeyStatus(""), KeyStatusFromProto(pb.KeyStatus(999)))
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, KeyAlgorithmToProto("rot13"))
	assert.Equal(t, transport.KeyAlgorithm(""), KeyAlgorithmFromProto(pb.KeyAlgorithm(999)))
	assert.Equal(t, []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_UNSPECIFIED}, KeyUsagesToProto([]transport.KeyUsage{"juggle"}))
	assert.Equal(t, []transport.KeyUsage{""}, KeyUsagesFromProto([]pb.KeyUsage{pb.KeyUsage(999)}))
}

func TestKeyManagementConversions_AbsentValuesStayAbsent(t *testing.T) {
	assert.Nil(t, KeyUsagesToProto(nil))
	assert.Nil(t, KeyUsagesFromProto(nil))
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

func TestKeyManagementClient_RefusesNilRequests(t *testing.T) {
	c := KeyManagementClient{}
	ctx := context.Background()
	calls := []error{
		func() error { _, err := c.GetPublicKey(ctx, nil); return err }(),
		func() error { _, err := c.RevokeKey(ctx, nil); return err }(),
		func() error { _, err := c.UpdateKeyStatus(ctx, nil); return err }(),
		func() error { _, err := c.GetKeyMetadata(ctx, nil); return err }(),
		func() error { _, err := c.UpdateKeyMetadata(ctx, nil); return err }(),
		func() error { _, err := c.SetKeyPolicy(ctx, nil); return err }(),
		func() error { _, err := c.GetKeyPolicy(ctx, nil); return err }(),
		func() error { _, err := c.DeleteKeyPolicy(ctx, nil); return err }(),
		func() error { _, err := c.SetKeyRotationPolicy(ctx, nil); return err }(),
		func() error { _, err := c.GetKeyRotationPolicy(ctx, nil); return err }(),
		func() error { _, err := c.DeleteKeyRotationPolicy(ctx, nil); return err }(),
		func() error { _, err := c.GetSupportedAlgorithms(ctx, nil); return err }(),
		func() error { _, err := c.BackendStatus(ctx, nil); return err }(),
		func() error { _, err := c.BackendTest(ctx, nil); return err }(),
		func() error { _, err := c.SetKeySafety(ctx, nil); return err }(),
		func() error { _, err := c.ClearKeySafety(ctx, nil); return err }(),
		func() error { _, err := c.SafetyCheck(ctx, nil); return err }(),
		func() error { _, err := c.SafetyReport(ctx, nil); return err }(),
	}
	for i, err := range calls {
		assert.ErrorIs(t, err, ErrNilRequest, "call %d", i)
	}
}
