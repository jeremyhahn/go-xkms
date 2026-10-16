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
	"math"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// samplePolicy is a TPM policy with every field set.
func samplePolicy() *transport.TPMPolicy {
	return &transport.TPMPolicy{
		Name:        "boot",
		TenantID:    "acme",
		Description: "firmware and Secure Boot",
		Branches: []transport.TPMPolicyBranch{
			{Conditions: []transport.TPMPolicyCondition{
				{Type: "pcr", Bank: "sha256", PCRs: []uint{0, 7}, PCRValues: map[uint]string{0: "aa", 7: "bb"}, PCRDigest: "cc"},
				{Type: "locality", Localities: []uint{0, 3}},
			}, Approved: true, Reference: &transport.TPMPolicyReference{ID: "boot-image-v2", Profile: "p", Signer: "s", Digest: []byte{0xab}}},
			{Conditions: []transport.TPMPolicyCondition{{Type: "auth_value"}}, Approved: true},
		},
		Index:               0x01500010,
		Approved:            true,
		Epoch:               4,
		AuthorityGeneration: 2,
		AutoUnseal:          true,
		CreatedAt:           "2026-09-29T00:00:00Z",
		UpdatedAt:           "2026-09-29T01:00:00Z",
	}
}

// TestConversions_RoundTrip proves every TPM policy message survives the
// trip to proto and back unchanged.
func TestConversions_RoundTrip(t *testing.T) {
	p := samplePolicy()
	assert.Equal(t, p, TPMPolicyFromProto(TPMPolicyToProto(p)))

	create := &transport.TPMPolicyCreateRequest{
		TenantID: "acme", Name: "boot", Description: "d", AutoUnseal: true, OwnerAuth: []byte("owner"),
		Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})},
	}
	assert.Equal(t, create, TPMPolicyCreateRequestFromProto(TPMPolicyCreateRequestToProto(create)))

	named := &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"}
	assert.Equal(t, named, TPMPolicyRequestFromProto(TPMPolicyRequestToProto(named)))

	capture := &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot"}
	assert.Equal(t, capture, TPMPolicyUpdateRequestFromProto(TPMPolicyUpdateRequestToProto(capture)))
	branch := 1
	update := &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot", Branch: &branch, ReferenceValues: []byte{0xd2, 0x84}}
	assert.Equal(t, update, TPMPolicyUpdateRequestFromProto(TPMPolicyUpdateRequestToProto(update)))

	list := &transport.TPMPolicyListResponse{Policies: []transport.TPMPolicy{*p}}
	assert.Equal(t, list, TPMPolicyListResponseFromProto(TPMPolicyListResponseToProto(list)))

	del := &transport.TPMPolicyDeleteRequest{TenantID: "acme", Name: "boot", OwnerAuth: []byte("owner")}
	assert.Equal(t, del, TPMPolicyDeleteRequestFromProto(TPMPolicyDeleteRequestToProto(del)))

	verify := &transport.TPMPolicyVerifyResponse{Name: "boot", Match: false, Approved: true, Branches: []transport.TPMPolicyBranchVerification{
		{Match: false, Mismatched: []uint{7}, Approved: true, Reference: &transport.TPMPolicyReference{ID: "boot-image-v2", Profile: "p", Signer: "s", Digest: []byte{0xab}}},
		{Match: true, Approved: true},
	}}
	assert.Equal(t, verify, TPMPolicyVerifyResponseFromProto(TPMPolicyVerifyResponseToProto(verify)))

	objects := &transport.TPMPolicyObjectsResponse{Name: "boot", Objects: []string{"key/a"}}
	assert.Equal(t, objects, TPMPolicyObjectsResponseFromProto(TPMPolicyObjectsResponseToProto(objects)))

	described := &transport.TPMPolicyDescriptionRequest{TenantID: "acme", Name: "boot", Description: "firmware"}
	assert.Equal(t, described, TPMPolicyDescriptionRequestFromProto(TPMPolicyDescriptionRequestToProto(described)))

	auto := &transport.TPMPolicyAutoUnsealRequest{TenantID: "acme", Name: "boot", Enabled: true}
	assert.Equal(t, auto, TPMPolicyAutoUnsealRequestFromProto(TPMPolicyAutoUnsealRequestToProto(auto)))

	objReq := &transport.TPMObjectPolicyRequest{TenantID: "acme", KeyID: "signer", Kind: "sealed"}
	assert.Equal(t, objReq, TPMObjectPolicyRequestFromProto(TPMObjectPolicyRequestToProto(objReq)))

	objResp := &transport.TPMObjectPolicyResponse{ObjectID: "key/signer", Kind: "key", Policy: "boot", AuthPolicy: "ab", CreatedAt: "now"}
	assert.Equal(t, objResp, TPMObjectPolicyResponseFromProto(TPMObjectPolicyResponseToProto(objResp)))

	rotated := &transport.TPMAuthorityRotateResponse{TenantID: "acme", Generation: 3, AuthorityName: "000b", Epoch: 5}
	assert.Equal(t, rotated, TPMAuthorityRotateResponseFromProto(TPMAuthorityRotateResponseToProto(rotated)))

	mode := &transport.TenantTPMModeResponse{TenantID: "acme", Mode: "vtpm"}
	assert.Equal(t, mode, TenantTPMModeResponseFromProto(TenantTPMModeResponseToProto(mode)))

	setMode := &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none", OwnerAuth: []byte("owner")}
	assert.Equal(t, setMode, SetTenantTPMModeRequestFromProto(SetTenantTPMModeRequestToProto(setMode)))

	vtpm := &transport.TenantVTPMStatusResponse{TenantID: "acme", Running: true, PID: 42, Socket: "/run/x.sock", Restarts: 1}
	assert.Equal(t, vtpm, TenantVTPMStatusResponseFromProto(TenantVTPMStatusResponseToProto(vtpm)))
}

// TestTPMPolicyUpdateRequestToProto_BranchOutOfRange proves a branch index
// int32 cannot carry is sent as -1, which names no branch, rather than as a
// truncated index naming another one.
func TestTPMPolicyUpdateRequestToProto_BranchOutOfRange(t *testing.T) {
	for _, branch := range []int{-2, math.MaxInt32 + 1} {
		got := TPMPolicyUpdateRequestToProto(&transport.TPMPolicyUpdateRequest{Name: "boot", Branch: &branch})
		require.NotNil(t, got.Branch)
		assert.Equal(t, int32(-1), got.GetBranch(), "branch %d", branch)
	}
}

// TestConversions_EmptyObjectsAreNotNil proves an empty object list decodes
// as [] rather than null.
func TestConversions_EmptyObjectsAreNotNil(t *testing.T) {
	got := TPMPolicyObjectsResponseFromProto(&pb.TPMPolicyObjectsResponse{Name: "boot"})
	assert.NotNil(t, got.Objects)
	assert.Empty(t, got.Objects)
	assert.Nil(t, uintsToProto(nil))
	assert.Nil(t, uintsFromProto(nil))
	assert.Nil(t, pcrValuesToProto(nil))
	assert.Nil(t, pcrValuesFromProto(nil))
}

// recordingServer answers every TPM policy RPC with a response derived from
// its request, and records the last request of each.
type recordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	last map[string]any
}

func (s *recordingServer) record(name string, req any) { s.last[name] = req }

func (s *recordingServer) TPMPolicyCreate(_ context.Context, r *pb.TPMPolicyCreateRequest) (*pb.TPMPolicy, error) {
	s.record("create", r)
	return &pb.TPMPolicy{Name: r.GetName(), TenantId: r.GetTenantId(), Description: r.GetDescription(), Branches: r.GetBranches()}, nil
}
func (s *recordingServer) TPMPolicyGet(_ context.Context, r *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	s.record("get", r)
	return &pb.TPMPolicy{Name: r.GetName(), TenantId: r.GetTenantId()}, nil
}
func (s *recordingServer) TPMPolicyList(_ context.Context, r *pb.TPMPolicyListRequest) (*pb.TPMPolicyListResponse, error) {
	s.record("list", r)
	return &pb.TPMPolicyListResponse{Policies: []*pb.TPMPolicy{{Name: "boot", TenantId: r.GetTenantId()}}}, nil
}
func (s *recordingServer) TPMPolicyUpdate(_ context.Context, r *pb.TPMPolicyUpdateRequest) (*pb.TPMPolicy, error) {
	s.record("update", r)
	return &pb.TPMPolicy{Name: r.GetName(), Epoch: 2}, nil
}
func (s *recordingServer) TPMPolicyRevoke(_ context.Context, r *pb.TPMPolicyRequest) (*pb.TPMPolicy, error) {
	s.record("revoke", r)
	return &pb.TPMPolicy{Name: r.GetName(), Approved: false}, nil
}
func (s *recordingServer) TPMPolicyVerify(_ context.Context, r *pb.TPMPolicyRequest) (*pb.TPMPolicyVerifyResponse, error) {
	s.record("verify", r)
	return &pb.TPMPolicyVerifyResponse{Name: r.GetName(), Match: true, Approved: true}, nil
}
func (s *recordingServer) TPMPolicyDelete(_ context.Context, r *pb.TPMPolicyDeleteRequest) (*pb.TPMPolicyDeleteResponse, error) {
	s.record("delete", r)
	return nil, status.Error(codes.FailedPrecondition, "policy \"boot\" is assigned to 1 object(s): key/a")
}
func (s *recordingServer) TPMPolicyObjects(_ context.Context, r *pb.TPMPolicyRequest) (*pb.TPMPolicyObjectsResponse, error) {
	s.record("objects", r)
	return &pb.TPMPolicyObjectsResponse{Name: r.GetName(), Objects: []string{"key/a"}}, nil
}
func (s *recordingServer) TPMPolicySetAutoUnseal(_ context.Context, r *pb.TPMPolicyAutoUnsealRequest) (*pb.TPMPolicy, error) {
	s.record("auto", r)
	return &pb.TPMPolicy{Name: r.GetName(), AutoUnseal: r.GetEnabled()}, nil
}
func (s *recordingServer) TPMPolicySetDescription(_ context.Context, r *pb.TPMPolicyDescriptionRequest) (*pb.TPMPolicy, error) {
	s.record("description", r)
	return &pb.TPMPolicy{Name: r.GetName(), Description: r.GetDescription()}, nil
}
func (s *recordingServer) TPMObjectPolicy(_ context.Context, r *pb.TPMObjectPolicyRequest) (*pb.TPMObjectPolicyResponse, error) {
	s.record("object", r)
	return &pb.TPMObjectPolicyResponse{ObjectId: r.GetKind() + "/" + r.GetKeyId(), Policy: "boot"}, nil
}
func (s *recordingServer) TPMPolicyRotateAuthority(_ context.Context, r *pb.TPMAuthorityRotateRequest) (*pb.TPMAuthorityRotateResponse, error) {
	s.record("rotate", r)
	return &pb.TPMAuthorityRotateResponse{TenantId: r.GetTenantId(), Generation: 2}, nil
}
func (s *recordingServer) GetTenantTPMMode(_ context.Context, r *pb.TenantTPMModeRequest) (*pb.TenantTPMModeResponse, error) {
	s.record("getMode", r)
	return &pb.TenantTPMModeResponse{TenantId: r.GetTenantId(), Mode: "shared"}, nil
}
func (s *recordingServer) SetTenantTPMMode(_ context.Context, r *pb.SetTenantTPMModeRequest) (*pb.TenantTPMModeResponse, error) {
	s.record("setMode", r)
	return &pb.TenantTPMModeResponse{TenantId: r.GetTenantId(), Mode: r.GetMode()}, nil
}
func (s *recordingServer) TenantVTPMStatus(_ context.Context, r *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	s.record("status", r)
	return &pb.TenantVTPMStatusResponse{TenantId: r.GetTenantId()}, nil
}
func (s *recordingServer) TenantVTPMStart(_ context.Context, r *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	s.record("start", r)
	return &pb.TenantVTPMStatusResponse{TenantId: r.GetTenantId(), Running: true, Pid: 7}, nil
}
func (s *recordingServer) TenantVTPMStop(_ context.Context, r *pb.TenantVTPMRequest) (*pb.TenantVTPMStatusResponse, error) {
	s.record("stop", r)
	return &pb.TenantVTPMStatusResponse{TenantId: r.GetTenantId()}, nil
}

// newRecordingClient serves a recordingServer over an in-memory connection
// and returns a TPMPolicyClient over it.
func newRecordingClient(t *testing.T) (TPMPolicyClient, *recordingServer) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	rec := &recordingServer{last: map[string]any{}}
	pb.RegisterKeystoreServiceServer(srv, rec)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		srv.Stop()
		require.NoError(t, <-served)
	})
	return TPMPolicyClient{Client: pb.NewKeystoreServiceClient(conn)}, rec
}

// TestTPMPolicyClient_CarriesEveryRequest proves each client method sends
// its request's fields and decodes the server's answer.
func TestTPMPolicyClient_CarriesEveryRequest(t *testing.T) {
	c, rec := newRecordingClient(t)
	ctx := context.Background()

	branches := []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}
	p, err := c.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{TenantID: "acme", Name: "boot", Description: "d", Branches: branches, OwnerAuth: []byte("o")})
	require.NoError(t, err)
	assert.Equal(t, branches, p.Branches)
	assert.Equal(t, "d", p.Description)
	assert.Equal(t, []byte("o"), rec.last["create"].(*pb.TPMPolicyCreateRequest).GetOwnerAuth())

	p, err = c.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "acme", p.TenantID)

	list, err := c.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{TenantID: "acme"})
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, "acme", list.Policies[0].TenantID)

	branch := 1
	p, err = c.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: &branch, ReferenceValues: []byte{0xd2, 0x84}})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), p.Epoch)
	sent := rec.last["update"].(*pb.TPMPolicyUpdateRequest)
	assert.Equal(t, int32(1), sent.GetBranch())
	assert.Equal(t, []byte{0xd2, 0x84}, sent.GetReferenceValues())

	p, err = c.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, p.Approved)

	v, err := c.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.True(t, v.Match)

	err = c.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot", OwnerAuth: []byte("o")})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "the server's status reaches the caller unchanged")
	assert.Equal(t, []byte("o"), rec.last["delete"].(*pb.TPMPolicyDeleteRequest).GetOwnerAuth())

	objects, err := c.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/a"}, objects.Objects)

	p, err = c.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "boot", Enabled: true})
	require.NoError(t, err)
	assert.True(t, p.AutoUnseal)

	p, err = c.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: "firmware"})
	require.NoError(t, err)
	assert.Equal(t, "firmware", p.Description)

	obj, err := c.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "signer", Kind: "key"})
	require.NoError(t, err)
	assert.Equal(t, "key/signer", obj.ObjectID)

	rot, err := c.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), rot.Generation)

	mode, err := c.GetTenantTPMMode(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "shared", mode.Mode)

	mode, err = c.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
	require.NoError(t, err)
	assert.Equal(t, "none", mode.Mode)

	st, err := c.TenantVTPMStart(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, 7, st.PID)
	st, err = c.TenantVTPMStatus(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", st.TenantID)
	st, err = c.TenantVTPMStop(ctx, "acme")
	require.NoError(t, err)
	assert.False(t, st.Running)
}

// TestTPMPolicyClient_RefusesNilRequests proves every request-taking method
// refuses a nil request without calling the server.
func TestTPMPolicyClient_RefusesNilRequests(t *testing.T) {
	c := TPMPolicyClient{}
	ctx := context.Background()
	calls := []error{
		func() error { _, err := c.TPMPolicyCreate(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyGet(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyList(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyUpdate(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyRevoke(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyVerify(ctx, nil); return err }(),
		c.TPMPolicyDelete(ctx, nil),
		func() error { _, err := c.TPMPolicyObjects(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicySetAutoUnseal(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicySetDescription(ctx, nil); return err }(),
		func() error { _, err := c.TPMObjectPolicy(ctx, nil); return err }(),
		func() error { _, err := c.TPMPolicyRotateAuthority(ctx, nil); return err }(),
		func() error { _, err := c.SetTenantTPMMode(ctx, nil); return err }(),
	}
	for i, err := range calls {
		assert.ErrorIs(t, err, ErrNilRequest, "call %d", i)
	}
}

// TestTPMPolicyClient_ServerErrorsPassThrough proves an RPC failure of every
// kind of method reaches the caller as the server's status.
func TestTPMPolicyClient_ServerErrorsPassThrough(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, &pb.UnimplementedKeystoreServiceServer{})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, conn.Close())
		srv.Stop()
		require.NoError(t, <-served)
	}()
	c := TPMPolicyClient{Client: pb.NewKeystoreServiceClient(conn)}
	ctx := context.Background()

	_, err = c.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: "boot"})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.TenantVTPMStatus(ctx, "acme")
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.GetTenantTPMMode(ctx, "acme")
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
