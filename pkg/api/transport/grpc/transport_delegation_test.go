// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// refusedToken makes the mock invite and LAK handlers refuse the request.
const refusedToken = "refused"

var inviteExpiry = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func errRefused() error { return status.Error(codes.PermissionDenied, "refused") }

// GetInvite echoes the request back in the invite metadata.
func (s *mockKeystoreServer) GetInvite(_ context.Context, req *pb.GetInviteRequest) (*pb.GetInviteResponse, error) {
	if req.GetToken() == refusedToken {
		return nil, errRefused()
	}
	return &pb.GetInviteResponse{
		Email:       req.GetTenantId() + "@example.com",
		DisplayName: req.GetToken(),
		ExpiresAt:   timestamppb.New(inviteExpiry),
		Methods:     []string{"webauthn", "piv"},
	}, nil
}

// BeginInviteRegistration echoes the request back in the ceremony.
func (s *mockKeystoreServer) BeginInviteRegistration(_ context.Context, req *pb.BeginInviteRegistrationRequest) (*pb.BeginInviteRegistrationResponse, error) {
	if req.GetToken() == refusedToken {
		return nil, errRefused()
	}
	return &pb.BeginInviteRegistrationResponse{SessionId: req.GetTenantId() + "/" + req.GetToken(), OptionsJson: `{"publicKey":{}}`}, nil
}

// FinishInviteRegistration activates user 42 when every field arrived.
func (s *mockKeystoreServer) FinishInviteRegistration(_ context.Context, req *pb.FinishInviteRegistrationRequest) (*pb.FinishInviteRegistrationResponse, error) {
	if req.GetToken() == refusedToken {
		return nil, errRefused()
	}
	if req.GetTenantId() == "" || req.GetSessionId() == "" || req.GetAttestationJson() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing field")
	}
	return &pb.FinishInviteRegistrationResponse{UserId: 42}, nil
}

// ActivateInvitePIV activates user 43 when every field arrived.
func (s *mockKeystoreServer) ActivateInvitePIV(_ context.Context, req *pb.ActivateInvitePIVRequest) (*pb.ActivateInvitePIVResponse, error) {
	if req.GetToken() == refusedToken {
		return nil, errRefused()
	}
	if req.GetTenantId() == "" || req.GetCertPem() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing field")
	}
	return &pb.ActivateInvitePIVResponse{UserId: 43}, nil
}

// IssueLAKCertificate refuses unless every evidence field arrived, and
// answers with a certificate built from them.
func (s *mockKeystoreServer) IssueLAKCertificate(_ context.Context, req *pb.IssueLAKCertificateRequest) (*pb.IssueLAKCertificateResponse, error) {
	if req.GetTpmManufacturer() == refusedToken {
		return nil, errRefused()
	}
	if req.GetTpmModel() == "" || req.GetTpmFirmwareVersion() == "" || len(req.GetIakCertificateDer()) == 0 ||
		len(req.GetCertifyInfo()) == 0 || len(req.GetSignature()) == 0 || len(req.GetLakPublicArea()) == 0 ||
		len(req.GetNonce()) == 0 || req.GetSignatureAlgorithm() != int32(x509.SHA256WithRSA) {
		return nil, status.Error(codes.InvalidArgument, "missing evidence")
	}
	return &pb.IssueLAKCertificateResponse{
		CertificateDer: req.GetLakPublicArea(),
		CertificatePem: []byte("PEM:" + req.GetTpmManufacturer()),
		SerialNumber:   "01",
	}, nil
}

// TestInvite_RoundTrip proves each invite verb sends every request field to
// the server and decodes every field of its answer.
func TestInvite_RoundTrip(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	invite, err := tr.GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "tok"})
	require.NoError(t, err)
	assert.Equal(t, &transport.GetInviteResponse{
		Email:       "acme@example.com",
		DisplayName: "tok",
		ExpiresAt:   inviteExpiry,
		Methods:     []string{"webauthn", "piv"},
	}, invite)

	begun, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
	require.NoError(t, err)
	assert.Equal(t, &transport.BeginInviteRegistrationResponse{SessionID: "acme/tok", OptionsJSON: `{"publicKey":{}}`}, begun)

	finished, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
		TenantID: "acme", Token: "tok", SessionID: begun.SessionID, AttestationJSON: "{}",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(42), finished.UserID)

	activated, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok", CertPEM: "PEM"})
	require.NoError(t, err)
	assert.Equal(t, uint64(43), activated.UserID)
}

// TestIssueLAKCertificate_RoundTrip proves every evidence field reaches the
// server and every certificate field comes back.
func TestIssueLAKCertificate_RoundTrip(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.IssueLAKCertificate(context.Background(), &transport.IssueLAKCertificateRequest{
		TPMManufacturer:    "IFX",
		TPMModel:           "SLB9670",
		TPMFirmwareVersion: "7.85",
		IAKCertificateDER:  []byte{0x30},
		CertifyInfo:        []byte{0x01},
		Signature:          []byte{0x02},
		SignatureAlgorithm: int(x509.SHA256WithRSA),
		LAKPublicArea:      []byte{0x03},
		Nonce:              []byte{0x04},
	})
	require.NoError(t, err)
	assert.Equal(t, &transport.IssueLAKCertificateResponse{
		CertificateDER: []byte{0x03},
		CertificatePEM: []byte("PEM:IFX"),
		SerialNumber:   "01",
	}, resp)
}

// TestIssueLAKCertificate_Refused proves a server refusal comes back wrapped,
// with its status code intact and no partial result.
func TestIssueLAKCertificate_Refused(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	resp, err := tr.IssueLAKCertificate(context.Background(), &transport.IssueLAKCertificateRequest{TPMManufacturer: refusedToken})
	assert.Nil(t, resp)
	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped), "error %v is not *errs.Wrapped", err)
	assert.Equal(t, codes.PermissionDenied, status.Code(wrapped.Err))
}

// delegatedCalls names every verb this test file pins, each called with a
// request the server refuses: the invite verbs and LAK issuance carry the
// refused token, and the key-management, crypto-utility and trust-root verbs
// reach a server that does not implement them.
func delegatedCalls(ctx context.Context, tr *Transport) map[string]func() (any, error) {
	return map[string]func() (any, error){
		"GetInvite": func() (any, error) {
			return tr.GetInvite(ctx, &transport.GetInviteRequest{Token: refusedToken})
		},
		"BeginInviteRegistration": func() (any, error) {
			return tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{Token: refusedToken})
		},
		"FinishInviteRegistration": func() (any, error) {
			return tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{Token: refusedToken})
		},
		"ActivateInvitePIV": func() (any, error) {
			return tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{Token: refusedToken})
		},
		"IssueLAKCertificate": func() (any, error) {
			return tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{TPMManufacturer: refusedToken})
		},

		"Rewrap":       func() (any, error) { return tr.Rewrap(ctx, &transport.RewrapRequest{}) },
		"EncryptBatch": func() (any, error) { return tr.EncryptBatch(ctx, &transport.EncryptBatchRequest{}) },
		"DecryptBatch": func() (any, error) { return tr.DecryptBatch(ctx, &transport.DecryptBatchRequest{}) },
		"GenerateDataKey": func() (any, error) {
			return tr.GenerateDataKey(ctx, &transport.GenerateDataKeyRequest{})
		},
		"GenerateWrappedDataKey": func() (any, error) {
			return tr.GenerateWrappedDataKey(ctx, &transport.GenerateDataKeyRequest{})
		},
		"GenerateHMAC":   func() (any, error) { return tr.GenerateHMAC(ctx, &transport.GenerateHMACRequest{}) },
		"VerifyHMAC":     func() (any, error) { return tr.VerifyHMAC(ctx, &transport.VerifyHMACRequest{}) },
		"GenerateRandom": func() (any, error) { return tr.GenerateRandom(ctx, &transport.GenerateRandomRequest{}) },
		"Hash":           func() (any, error) { return tr.Hash(ctx, &transport.HashRequest{}) },

		"GetPublicKey":    func() (any, error) { return tr.GetPublicKey(ctx, &transport.GetPublicKeyRequest{}) },
		"RevokeKey":       func() (any, error) { return tr.RevokeKey(ctx, &transport.RevokeKeyRequest{}) },
		"UpdateKeyStatus": func() (any, error) { return tr.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{}) },
		"GetKeyMetadata":  func() (any, error) { return tr.GetKeyMetadata(ctx, &transport.KeyManagementRequest{}) },
		"UpdateKeyMetadata": func() (any, error) {
			return tr.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{})
		},
		"SetKeyPolicy":    func() (any, error) { return tr.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{}) },
		"GetKeyPolicy":    func() (any, error) { return tr.GetKeyPolicy(ctx, &transport.KeyManagementRequest{}) },
		"DeleteKeyPolicy": func() (any, error) { return tr.DeleteKeyPolicy(ctx, &transport.KeyManagementRequest{}) },
		"SetKeyRotationPolicy": func() (any, error) {
			return tr.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{})
		},
		"GetKeyRotationPolicy": func() (any, error) {
			return tr.GetKeyRotationPolicy(ctx, &transport.KeyManagementRequest{})
		},
		"DeleteKeyRotationPolicy": func() (any, error) {
			return tr.DeleteKeyRotationPolicy(ctx, &transport.KeyManagementRequest{})
		},
		"GetSupportedAlgorithms": func() (any, error) {
			return tr.GetSupportedAlgorithms(ctx, &transport.BackendRequest{})
		},
		"BackendStatus":  func() (any, error) { return tr.BackendStatus(ctx, &transport.BackendRequest{}) },
		"BackendTest":    func() (any, error) { return tr.BackendTest(ctx, &transport.BackendRequest{}) },
		"SetKeySafety":   func() (any, error) { return tr.SetKeySafety(ctx, &transport.SetKeySafetyRequest{}) },
		"ClearKeySafety": func() (any, error) { return tr.ClearKeySafety(ctx, &transport.KeyManagementRequest{}) },
		"SafetyCheck":    func() (any, error) { return tr.SafetyCheck(ctx, &transport.SafetyCheckRequest{}) },
		"SafetyReport":   func() (any, error) { return tr.SafetyReport(ctx, &transport.SafetyReportRequest{}) },

		"TrustRootList": func() (any, error) { return tr.TrustRootList(ctx, &transport.TrustRootListRequest{}) },
		"TrustRootGet":  func() (any, error) { return tr.TrustRootGet(ctx, &transport.TrustRootRequest{}) },
		"TrustRootImport": func() (any, error) {
			return tr.TrustRootImport(ctx, &transport.TrustRootImportRequest{})
		},
		"TrustRootQuarantine": func() (any, error) {
			return tr.TrustRootQuarantine(ctx, &transport.TrustRootRequest{})
		},
		"TrustRootRemove": func() (any, error) { return nil, tr.TrustRootRemove(ctx, &transport.TrustRootRequest{}) },
	}
}

// TestDelegatedVerbs_ServerRefusal proves each verb reaches the server and
// returns its refusal with the status code intact and no partial result.
func TestDelegatedVerbs_ServerRefusal(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	for name, call := range delegatedCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			resp, err := call()
			assert.Nil(t, resp)
			require.Error(t, err)
			assert.Contains(t, []codes.Code{codes.PermissionDenied, codes.Unimplemented}, status.Code(err),
				"error %v lost its status code", err)
		})
	}
}

// TestDelegatedVerbs_NotConnected proves each verb refuses before the
// transport is connected, without a result.
func TestDelegatedVerbs_NotConnected(t *testing.T) {
	for name, call := range delegatedCalls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) {
			resp, err := call()
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, ErrNotConnected)
		})
	}
}
