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

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// verbCase is one transport method that forwards a request to the RPC of
// its name: sent is the request the server must receive, reply the server's
// answer, want the response the caller must get back, and refusal the status
// code the server refuses this verb with.
type verbCase struct {
	call    func(context.Context, *Transport) (any, error)
	sent    proto.Message
	reply   proto.Message
	want    any
	refusal codes.Code
}

// verb binds a transport method expression to the request it is called with.
func verb[Req, Resp any](method func(*Transport, context.Context, Req) (Resp, error), req Req) func(context.Context, *Transport) (any, error) {
	return func(ctx context.Context, tr *Transport) (any, error) {
		return method(tr, ctx, req)
	}
}

// assertVerbsReachTheServer proves each verb sends exactly its request to
// the RPC of its name and returns the server's answer decoded.
func assertVerbsReachTheServer(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &rpcRecorder{reply: tc.reply}
			got, err := tc.call(context.Background(), rec.connect(t))
			require.NoError(t, err)

			sent := tc.sent.ProtoReflect().New().Interface()
			assert.Equal(t, name, rec.request(t, sent))
			assert.True(t, proto.Equal(tc.sent, sent), "sent %v, want %v", sent, tc.sent)
			assert.Equal(t, tc.want, got)
		})
	}
}

// assertVerbsSurfaceRefusals proves each verb returns the server's status
// code unchanged and no partial result.
func assertVerbsSurfaceRefusals(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &rpcRecorder{err: status.Error(tc.refusal, "refused")}
			got, err := tc.call(context.Background(), rec.connect(t))
			assert.Equal(t, tc.refusal, status.Code(err))
			assert.Nil(t, got)
		})
	}
}

// assertVerbsNeedAConnection proves each verb refuses with ErrNotConnected
// before the transport connects.
func assertVerbsNeedAConnection(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.call(context.Background(), &Transport{})
			assert.ErrorIs(t, err, ErrNotConnected)
			assert.Nil(t, got)
		})
	}
}

// keyManagementVerbs returns a case for every key management verb.
func keyManagementVerbs() map[string]verbCase {
	const backend, keyID = "pkcs11", "orders-key"
	keyReq := &transport.KeyManagementRequest{Backend: backend, KeyID: keyID}
	backendReq := &transport.BackendRequest{Backend: backend}

	metadata := &pb.GetKeyMetadataResponse{Timestamp: 1700000001}
	updatedMetadata := &pb.UpdateKeyMetadataResponse{Timestamp: 1700000002}
	policy := &pb.GetKeyPolicyResponse{Timestamp: 1700000003}
	rotation := &pb.GetKeyRotationPolicyResponse{KeyId: keyID, Timestamp: 1700000004}
	setRotation := &pb.SetKeyRotationPolicyResponse{KeyId: keyID, Timestamp: 1700000005}
	algorithms := &pb.GetSupportedAlgorithmsResponse{Algorithms: []string{string(transport.KeyAlgorithmAES256GCM)}}
	backendStatus := &pb.BackendStatusResponse{BackendType: backend, Status: "healthy"}
	safetyCheck := &pb.SafetyCheckResponse{Timestamp: 1700000006}
	safetyReport := &pb.SafetyReportResponse{TotalKeys: 3, KeysAtWarning: 1, Timestamp: 1700000007}
	updateMetadata := &transport.UpdateKeyMetadataRequest{Backend: backend, KeyID: keyID}

	return map[string]verbCase{
		"GetPublicKey": {
			call:    verb((*Transport).GetPublicKey, &transport.GetPublicKeyRequest{Backend: backend, KeyID: keyID, Version: 3}),
			sent:    &pb.GetPublicKeyRequest{KeyId: keyID, Version: 3, Backend: backend},
			reply:   &pb.GetPublicKeyResponse{KeyId: keyID, PublicKey: []byte{0x30, 0x59}, Version: 3},
			want:    &transport.GetPublicKeyResponse{KeyID: keyID, PublicKey: []byte{0x30, 0x59}, Algorithm: pbconv.KeyAlgorithmFromProto(0), Version: 3},
			refusal: codes.NotFound,
		},
		"RevokeKey": {
			call:    verb((*Transport).RevokeKey, &transport.RevokeKeyRequest{Backend: backend, KeyID: keyID, Reason: "compromised"}),
			sent:    &pb.RevokeKeyRequest{KeyId: keyID, Reason: "compromised", Backend: backend},
			reply:   &pb.RevokeKeyResponse{KeyId: keyID, Status: pbconv.KeyStatusToProto(transport.KeyStatusCompromised), Timestamp: 1700000000},
			want:    &transport.RevokeKeyResponse{KeyID: keyID, Status: transport.KeyStatusCompromised, Timestamp: 1700000000},
			refusal: codes.PermissionDenied,
		},
		"UpdateKeyStatus": {
			call:    verb((*Transport).UpdateKeyStatus, &transport.UpdateKeyStatusRequest{Backend: backend, KeyID: keyID, Version: 2, Status: transport.KeyStatusDisabled}),
			sent:    &pb.UpdateKeyStatusRequest{KeyId: keyID, Version: 2, Status: pbconv.KeyStatusToProto(transport.KeyStatusDisabled), Backend: backend},
			reply:   &pb.UpdateKeyStatusResponse{KeyId: keyID, Version: 2, Status: pbconv.KeyStatusToProto(transport.KeyStatusDisabled), Timestamp: 1700000000},
			want:    &transport.UpdateKeyStatusResponse{KeyID: keyID, Version: 2, Status: transport.KeyStatusDisabled, Timestamp: 1700000000},
			refusal: codes.FailedPrecondition,
		},
		"GetKeyMetadata": {
			call:    verb((*Transport).GetKeyMetadata, keyReq),
			sent:    &pb.GetKeyMetadataRequest{KeyId: keyID, Backend: backend},
			reply:   metadata,
			want:    &transport.KeyMetadataResponse{Metadata: pbconv.KeyMetadataFromProto(metadata.GetMetadata()), Timestamp: 1700000001},
			refusal: codes.NotFound,
		},
		"UpdateKeyMetadata": {
			call:    verb((*Transport).UpdateKeyMetadata, updateMetadata),
			sent:    pbconv.UpdateKeyMetadataRequestToProto(updateMetadata),
			reply:   updatedMetadata,
			want:    &transport.KeyMetadataResponse{Metadata: pbconv.KeyMetadataFromProto(updatedMetadata.GetMetadata()), Timestamp: 1700000002},
			refusal: codes.InvalidArgument,
		},
		"SetKeyPolicy": {
			call:    verb((*Transport).SetKeyPolicy, &transport.SetKeyPolicyRequest{Backend: backend, KeyID: keyID}),
			sent:    &pb.SetKeyPolicyRequest{KeyId: keyID, Policy: pbconv.KeyPolicyToProto(nil), Backend: backend},
			reply:   &pb.SetKeyPolicyResponse{KeyId: keyID, PolicyVersion: 4, Timestamp: 1700000000},
			want:    &transport.SetKeyPolicyResponse{KeyID: keyID, PolicyVersion: 4, Timestamp: 1700000000},
			refusal: codes.InvalidArgument,
		},
		"GetKeyPolicy": {
			call:    verb((*Transport).GetKeyPolicy, keyReq),
			sent:    &pb.GetKeyPolicyRequest{KeyId: keyID, Backend: backend},
			reply:   policy,
			want:    &transport.GetKeyPolicyResponse{Policy: pbconv.KeyPolicyFromProto(policy.GetPolicy()), Timestamp: 1700000003},
			refusal: codes.NotFound,
		},
		"DeleteKeyPolicy": {
			call:    verb((*Transport).DeleteKeyPolicy, keyReq),
			sent:    &pb.DeleteKeyPolicyRequest{KeyId: keyID, Backend: backend},
			reply:   &pb.DeleteKeyPolicyResponse{KeyId: keyID, Timestamp: 1700000000},
			want:    &transport.KeyManagementResponse{KeyID: keyID, Timestamp: 1700000000},
			refusal: codes.NotFound,
		},
		"SetKeyRotationPolicy": {
			call:    verb((*Transport).SetKeyRotationPolicy, &transport.SetKeyRotationPolicyRequest{Backend: backend, KeyID: keyID}),
			sent:    &pb.SetKeyRotationPolicyRequest{KeyId: keyID, Policy: pbconv.RotationPolicyToProto(nil), Backend: backend},
			reply:   setRotation,
			want:    &transport.KeyRotationPolicyResponse{KeyID: keyID, Policy: pbconv.RotationPolicyFromProto(setRotation.GetPolicy()), Timestamp: 1700000005},
			refusal: codes.InvalidArgument,
		},
		"GetKeyRotationPolicy": {
			call:    verb((*Transport).GetKeyRotationPolicy, keyReq),
			sent:    &pb.GetKeyRotationPolicyRequest{KeyId: keyID, Backend: backend},
			reply:   rotation,
			want:    &transport.KeyRotationPolicyResponse{KeyID: keyID, Policy: pbconv.RotationPolicyFromProto(rotation.GetPolicy()), Timestamp: 1700000004},
			refusal: codes.NotFound,
		},
		"DeleteKeyRotationPolicy": {
			call:    verb((*Transport).DeleteKeyRotationPolicy, keyReq),
			sent:    &pb.DeleteKeyRotationPolicyRequest{KeyId: keyID, Backend: backend},
			reply:   &pb.DeleteKeyRotationPolicyResponse{KeyId: keyID, Timestamp: 1700000000},
			want:    &transport.KeyManagementResponse{KeyID: keyID, Timestamp: 1700000000},
			refusal: codes.NotFound,
		},
		"GetSupportedAlgorithms": {
			call:    verb((*Transport).GetSupportedAlgorithms, backendReq),
			sent:    &pb.GetSupportedAlgorithmsRequest{Backend: backend},
			reply:   algorithms,
			want:    &transport.GetSupportedAlgorithmsResponse{Algorithms: []transport.KeyAlgorithm{transport.KeyAlgorithmAES256GCM}},
			refusal: codes.Unavailable,
		},
		"BackendStatus": {
			call:    verb((*Transport).BackendStatus, backendReq),
			sent:    &pb.BackendStatusRequest{Backend: backend},
			reply:   backendStatus,
			want:    pbconv.BackendStatusResponseFromProto(backendStatus),
			refusal: codes.Unavailable,
		},
		"BackendTest": {
			call:    verb((*Transport).BackendTest, backendReq),
			sent:    &pb.BackendTestRequest{Backend: backend},
			reply:   &pb.BackendTestResponse{Success: true, DurationMs: 12, Message: "seal round trip ok", Timestamp: 1700000000},
			want:    &transport.BackendTestResponse{Success: true, DurationMS: 12, Message: "seal round trip ok", Timestamp: 1700000000},
			refusal: codes.Internal,
		},
		"SetKeySafety": {
			call:    verb((*Transport).SetKeySafety, &transport.SetKeySafetyRequest{Backend: backend, KeyID: keyID, MaxOperations: 1 << 32, MaxBytes: 1 << 36, WarningPercent: 80}),
			sent:    &pb.SetKeySafetyRequest{KeyId: keyID, MaxOperations: 1 << 32, MaxBytes: 1 << 36, WarningPercent: 80, Backend: backend},
			reply:   &pb.SetKeySafetyResponse{KeyId: keyID, Timestamp: 1700000000},
			want:    &transport.KeyManagementResponse{KeyID: keyID, Timestamp: 1700000000},
			refusal: codes.InvalidArgument,
		},
		"ClearKeySafety": {
			call:    verb((*Transport).ClearKeySafety, keyReq),
			sent:    &pb.ClearKeySafetyRequest{KeyId: keyID, Backend: backend},
			reply:   &pb.ClearKeySafetyResponse{KeyId: keyID, Timestamp: 1700000000},
			want:    &transport.KeyManagementResponse{KeyID: keyID, Timestamp: 1700000000},
			refusal: codes.NotFound,
		},
		"SafetyCheck": {
			call:    verb((*Transport).SafetyCheck, &transport.SafetyCheckRequest{}),
			sent:    &pb.SafetyCheckRequest{},
			reply:   safetyCheck,
			want:    &transport.SafetyCheckResponse{Warnings: pbconv.SafetyWarningsFromProto(safetyCheck.GetWarnings()), Timestamp: 1700000006},
			refusal: codes.Unavailable,
		},
		"SafetyReport": {
			call:    verb((*Transport).SafetyReport, &transport.SafetyReportRequest{Format: "json"}),
			sent:    &pb.SafetyReportRequest{Format: "json"},
			reply:   safetyReport,
			want:    pbconv.SafetyReportResponseFromProto(safetyReport),
			refusal: codes.Unauthenticated,
		},
	}
}

// TestKeyManagementVerbs_ReachTheServer proves every key management verb
// sends its request to the RPC of its name and decodes the server's answer.
func TestKeyManagementVerbs_ReachTheServer(t *testing.T) {
	assertVerbsReachTheServer(t, keyManagementVerbs())
}

// TestKeyManagementVerbs_SurfaceServerRefusals proves every key management
// verb returns the server's status code and no partial result.
func TestKeyManagementVerbs_SurfaceServerRefusals(t *testing.T) {
	assertVerbsSurfaceRefusals(t, keyManagementVerbs())
}

// TestKeyManagementVerbs_NotConnected proves every key management verb
// refuses with ErrNotConnected before the transport connects.
func TestKeyManagementVerbs_NotConnected(t *testing.T) {
	assertVerbsNeedAConnection(t, keyManagementVerbs())
}
