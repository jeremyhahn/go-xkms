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

package unix

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers Unix transport client methods (go-xkms #705, batch A)
// that shipped without a NotConnected / Connected / ServerError triple: per-
// share and audit queries, tenant entitlement/quota updates, algorithm
// discovery and the PKCS11State remote-storage bridge. Each mock/error
// handler proves the request fields the client sends survive the round trip.

// --- mockKeystoreServer additions (happy path, field echo) ---

func (s *mockKeystoreServer) GetShare(_ context.Context, req *pb.GetShareRequest) (*pb.ShareInfo, error) {
	return &pb.ShareInfo{
		ServerUrl: req.GetServerUrl(), GroupId: req.GetGroupId(), ShareIndex: req.GetShareIndex(),
		GroupName: "recovery", Purpose: "shamir-recovery", TenantId: "tenant-a",
		SubmittedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func (s *mockKeystoreServer) DeleteShare(_ context.Context, _ *pb.DeleteShareRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *mockKeystoreServer) QueryAudit(_ context.Context, req *pb.QueryAuditRequest) (*pb.QueryAuditResponse, error) {
	attrs, _ := structpb.NewStruct(map[string]any{"ip": "127.0.0.1"})
	return &pb.QueryAuditResponse{
		Events: []*pb.AuditEvent{{
			Timestamp: timestamppb.New(time.Unix(1700000000, 0)),
			Actor:     req.GetActor(), TenantId: req.GetTenantId(), Resource: req.GetResource(),
			Action: req.GetAction(), Outcome: req.GetOutcome(), Attributes: attrs,
			ClientIp: "10.0.0.1", RequestId: "req-1", PrevHash: "abc123",
		}},
		Next: "cursor-2", Total: 1,
	}, nil
}

func (s *mockKeystoreServer) TenantBarrierStatus(_ context.Context, req *pb.TenantBarrierStatusRequest) (*pb.TenantBarrierStatusResponse, error) {
	return &pb.TenantBarrierStatusResponse{
		TenantId: req.GetTenantId(), Sealed: false, Initialized: true, Strategy: "shamir",
		HardwareBacked: true, ShamirThreshold: 3, ShamirTotal: 5,
	}, nil
}

func (s *mockKeystoreServer) UpdateTenantEntitlements(_ context.Context, req *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	return &pb.UpdateTenantEntitlementsResponse{Tenant: &pb.TenantInfo{
		Id: req.GetTenantId(), Entitlements: req.GetEntitlements(),
	}}, nil
}

func (s *mockKeystoreServer) UpdateTenantQuotas(_ context.Context, req *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	return &pb.UpdateTenantQuotasResponse{Tenant: &pb.TenantInfo{
		Id: req.GetTenantId(), Quotas: req.GetQuotas(),
	}}, nil
}

func (s *mockKeystoreServer) Algorithms(_ context.Context, _ *pb.AlgorithmsRequest) (*pb.AlgorithmsResponse, error) {
	return &pb.AlgorithmsResponse{
		Signing: []*pb.AlgorithmInfo{
			{Algorithm: "ECDSA", Curves: []string{"P-256"}, KeySizes: []int32{256}, Backends: []string{"software"}},
		},
		KeyEncapsulation: []*pb.AlgorithmInfo{
			{Algorithm: "ML-KEM", KeySizes: []int32{768}, PostQuantum: true},
		},
	}, nil
}

func (s *mockKeystoreServer) PKCS11StatePut(_ context.Context, _ *pb.PKCS11StatePutRequest) (*pb.PKCS11StatePutResponse, error) {
	return &pb.PKCS11StatePutResponse{}, nil
}

func (s *mockKeystoreServer) PKCS11StatePutIfAbsent(_ context.Context, _ *pb.PKCS11StatePutIfAbsentRequest) (*pb.PKCS11StatePutIfAbsentResponse, error) {
	return &pb.PKCS11StatePutIfAbsentResponse{Stored: true}, nil
}

func (s *mockKeystoreServer) PKCS11StateCAS(_ context.Context, req *pb.PKCS11StateCASRequest) (*pb.PKCS11StateCASResponse, error) {
	return &pb.PKCS11StateCASResponse{Swapped: true, Current: req.GetNew()}, nil
}

func (s *mockKeystoreServer) PKCS11StateGet(_ context.Context, req *pb.PKCS11StateGetRequest) (*pb.PKCS11StateGetResponse, error) {
	if req.GetKey() == "missing" {
		return &pb.PKCS11StateGetResponse{Found: false}, nil
	}
	return &pb.PKCS11StateGetResponse{Value: []byte("state-value"), Found: true}, nil
}

func (s *mockKeystoreServer) PKCS11StateDelete(_ context.Context, _ *pb.PKCS11StateDeleteRequest) (*pb.PKCS11StateDeleteResponse, error) {
	return &pb.PKCS11StateDeleteResponse{}, nil
}

func (s *mockKeystoreServer) PKCS11StateList(_ context.Context, req *pb.PKCS11StateListRequest) (*pb.PKCS11StateListResponse, error) {
	return &pb.PKCS11StateListResponse{Keys: []string{req.GetPrefix() + "/a", req.GetPrefix() + "/b"}}, nil
}

// --- errServer additions (uniform Internal status) ---

func (s *errServer) GetShare(context.Context, *pb.GetShareRequest) (*pb.ShareInfo, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) DeleteShare(context.Context, *pb.DeleteShareRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) QueryAudit(context.Context, *pb.QueryAuditRequest) (*pb.QueryAuditResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) TenantBarrierStatus(context.Context, *pb.TenantBarrierStatusRequest) (*pb.TenantBarrierStatusResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) UpdateTenantEntitlements(context.Context, *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) UpdateTenantQuotas(context.Context, *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) Algorithms(context.Context, *pb.AlgorithmsRequest) (*pb.AlgorithmsResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StatePut(context.Context, *pb.PKCS11StatePutRequest) (*pb.PKCS11StatePutResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StatePutIfAbsent(context.Context, *pb.PKCS11StatePutIfAbsentRequest) (*pb.PKCS11StatePutIfAbsentResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StateCAS(context.Context, *pb.PKCS11StateCASRequest) (*pb.PKCS11StateCASResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StateGet(context.Context, *pb.PKCS11StateGetRequest) (*pb.PKCS11StateGetResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StateDelete(context.Context, *pb.PKCS11StateDeleteRequest) (*pb.PKCS11StateDeleteResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}
func (s *errServer) PKCS11StateList(context.Context, *pb.PKCS11StateListRequest) (*pb.PKCS11StateListResponse, error) {
	return nil, status.Error(codes.Internal, "fail")
}

// --- NotConnected ---

func TestGetShare_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetShare(context.Background(), "https://a", "g1", 0)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteShare_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeleteShare(context.Background(), "https://a", "g1", 0)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestQueryAudit_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).QueryAudit(context.Background(), &transport.AuditFilter{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestQueryAudit_NilFilter(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	_, err := tr.QueryAudit(context.Background(), nil)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
}

func TestTenantBarrierStatus_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).TenantBarrierStatus(context.Background(), "tenant-a")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantEntitlements_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantQuotas_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestAlgorithms_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).Algorithms(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierEnableEncryption_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePut_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePutIfAbsent_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateCAS_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateGet_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateDelete_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateList_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Connected: the wire contract round trip ---

func TestGetShare_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.GetShare(context.Background(), "https://a.example", "group-1", 2)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", resp.ServerURL)
	assert.Equal(t, "group-1", resp.GroupID)
	assert.Equal(t, 2, resp.ShareIndex)
}

func TestDeleteShare_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DeleteShare(context.Background(), "https://a.example", "group-1", 2))
}

func TestQueryAudit_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	page, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{
		Actor: "alice", Resource: "key", Action: "sign", Outcome: "success",
		From: time.Now().Add(-time.Hour), To: time.Now(), Limit: 10, Cursor: "c1",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, page.Total)
	assert.Equal(t, "cursor-2", page.Next)
	require.Len(t, page.Events, 1)
	assert.Equal(t, "alice", page.Events[0].Actor)
	assert.Equal(t, "sign", page.Events[0].Action)
	assert.Equal(t, "127.0.0.1", page.Events[0].Attributes["ip"])
}

func TestTenantBarrierStatus_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.TenantBarrierStatus(context.Background(), "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", resp.TenantID)
	assert.True(t, resp.Initialized)
	assert.Equal(t, 3, resp.ShamirThreshold)
	assert.Equal(t, 5, resp.ShamirTotal)
}

func TestUpdateTenantEntitlements_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "tenant-a",
		Entitlements: transport.TenantEntitlements{
			AllowedIsolationModes: []string{"dedicated"}, AllowDedicatedRaft: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Entitlements)
	assert.True(t, resp.Tenant.Entitlements.AllowDedicatedRaft)
}

func TestUpdateTenantQuotas_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: "tenant-a",
		Quotas:   transport.TenantQuotas{MaxKeys: 100, MaxUsers: 10},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Quotas)
	assert.Equal(t, int64(100), resp.Tenant.Quotas.MaxKeys)
}

func TestAlgorithms_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Signing, 1)
	assert.Equal(t, "ECDSA", resp.Signing[0].Algorithm)
	assert.Equal(t, []int{256}, resp.Signing[0].KeySizes)
	require.Len(t, resp.KeyEncapsulation, 1)
	assert.True(t, resp.KeyEncapsulation[0].PostQuantum)
}

func TestBarrierEnableEncryption_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{
		Strategy: "shamir", Mechanism: "in-place", Availability: "online", ShamirThreshold: 3, ShamirTotal: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "started", resp.Status)
	assert.Equal(t, "system", resp.Scope)
}

func TestPKCS11StatePut_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Value: []byte("v"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPKCS11StatePutIfAbsent_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Value: []byte("v"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Stored)
}

func TestPKCS11StateCAS_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Expected: []byte("old"), New: []byte("new"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Swapped)
	assert.Equal(t, []byte("new"), resp.Current)
}

func TestPKCS11StateGet_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k",
	})
	require.NoError(t, err)
	assert.True(t, resp.Found)
	assert.Equal(t, []byte("state-value"), resp.Value)

	resp, err = tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "missing",
	})
	require.NoError(t, err)
	assert.False(t, resp.Found)
}

func TestPKCS11StateDelete_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPKCS11StateList_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{
		TenantID: "tenant-a", Token: "tok0", Prefix: "ns",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns/a", "ns/b"}, resp.Keys)
}

// --- ServerError ---

func TestGetShare_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.GetShare(context.Background(), "u", "g", 0)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDeleteShare_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	err := tr.DeleteShare(context.Background(), "u", "g", 0)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestQueryAudit_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestTenantBarrierStatus_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.TenantBarrierStatus(context.Background(), "tenant-a")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestUpdateTenantEntitlements_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestUpdateTenantQuotas_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestAlgorithms_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.Algorithms(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestBarrierEnableEncryption_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StatePut_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StatePutIfAbsent_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateCAS_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateGet_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateDelete_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateList_ServerError(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
