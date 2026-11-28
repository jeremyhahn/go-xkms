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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_ReachesTheServer proves a connected transport serves the TPM
// policy API over its gRPC connection: the request's tenant and name reach
// the server and its policy is decoded. The conversions themselves are
// tested once, in pkg/api/grpc/pbconv.
func TestTPMPolicy_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()

	p, err := tr.TPMPolicyGet(context.Background(), &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}, p.Branches)
	assert.True(t, p.Approved)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before
// the transport is connected.
func TestTPMPolicy_NotConnected(t *testing.T) {
	for name, call := range tpmpolicytest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}

// parityCoRIM stands in for a signed CoRIM: the transport carries it as
// opaque bytes.
var parityCoRIM = []byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58}

// parityReference is the reference a verify reports for branch "next".
var parityReference = transport.TPMPolicyReference{
	ID: "corim-next", Profile: "tag:go-xkms,2026:tpm", Signer: "release", Digest: []byte{0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c},
}

// TPMPolicyUpdate echoes the update request as the updated policy: the
// branch carries the request's branch name and its reference digest the
// request's reference values, so a client test sees both arrive and come
// back.
func (s *mockKeystoreServer) TPMPolicyUpdate(_ context.Context, req *pb.TPMPolicyUpdateRequest) (*pb.TPMPolicy, error) {
	branch := &pb.TPMPolicyBranch{Name: req.GetBranch(), Approved: true, Conditions: []*pb.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", Pcrs: []uint32{7}}}}
	if len(req.GetReferenceValues()) > 0 {
		branch.Reference = &pb.TPMPolicyReference{Id: parityReference.ID, Digest: req.GetReferenceValues()}
	}
	return &pb.TPMPolicy{Name: req.GetName(), TenantId: req.GetTenantId(), Branches: []*pb.TPMPolicyBranch{branch}, Approved: true}, nil
}

// TPMPolicyVerify reports parityReference for branch "next".
func (s *mockKeystoreServer) TPMPolicyVerify(_ context.Context, req *pb.TPMPolicyRequest) (*pb.TPMPolicyVerifyResponse, error) {
	ref := &pb.TPMPolicyReference{Id: parityReference.ID, Profile: parityReference.Profile, Signer: parityReference.Signer, Digest: parityReference.Digest}
	return &pb.TPMPolicyVerifyResponse{Name: req.GetName(), Match: true, Approved: true, Branches: []*pb.TPMPolicyBranchVerification{
		{Name: "next", Match: true, Approved: true, Reference: ref},
	}}, nil
}

// TestTPMPolicy_BranchAndReferenceParity proves the branch name, the
// reference values and the verify reference cross the Unix-socket
// transport unchanged in both directions.
func TestTPMPolicy_BranchAndReferenceParity(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()
	branch := transport.TPMPolicyPCRBranch("sha256", []uint{7})
	branch.Name, branch.Approved = "next", true

	t.Run("update with branch", func(t *testing.T) {
		p, err := tr.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot", Branch: "next"})
		require.NoError(t, err)
		assert.Equal(t, &transport.TPMPolicy{Name: "boot", TenantID: "acme", Branches: []transport.TPMPolicyBranch{branch}, Approved: true}, p)
	})

	t.Run("update with branch and reference values", func(t *testing.T) {
		p, err := tr.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot", Branch: "next", ReferenceValues: parityCoRIM})
		require.NoError(t, err)
		want := branch
		want.Reference = &transport.TPMPolicyReference{ID: parityReference.ID, Digest: parityCoRIM}
		assert.Equal(t, &transport.TPMPolicy{Name: "boot", TenantID: "acme", Branches: []transport.TPMPolicyBranch{want}, Approved: true}, p)
	})

	t.Run("verify reports the reference", func(t *testing.T) {
		v, err := tr.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
		require.NoError(t, err)
		ref := parityReference
		assert.Equal(t, &transport.TPMPolicyVerifyResponse{Name: "boot", Match: true, Approved: true, Branches: []transport.TPMPolicyBranchVerification{
			{Name: "next", Match: true, Approved: true, Reference: &ref},
		}}, v)
	})
}
