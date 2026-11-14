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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_CallsTheTool proves the TPM policy methods call their MCP
// tools with the request as parameters and decode the result: the request's
// tenant and name reach the server, and a tenant-ID method sends tenant_id.
func TestTPMPolicy_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	ctx := context.Background()

	p, err := tr.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}, p.Branches)
	assert.True(t, p.Approved)

	st, err := tr.TenantVTPMStatus(ctx, "globex")
	require.NoError(t, err)
	assert.Equal(t, "globex", st.TenantID)
	assert.True(t, st.Running)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before it
// is connected.
func TestTPMPolicy_NotConnected(t *testing.T) {
	for name, call := range tpmpolicytest.Calls(context.Background(), &Transport{}) {
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

// parityPolicy echoes an update request as the policy the server returns:
// the updated branch carries the request's branch name, and its reference
// digest is the request's reference values, so the caller sees both come
// back unchanged.
func parityPolicy(req *transport.TPMPolicyUpdateRequest) transport.TPMPolicy {
	branch := transport.TPMPolicyPCRBranch("sha256", []uint{7})
	branch.Name, branch.Approved = req.Branch, true
	if len(req.ReferenceValues) > 0 {
		branch.Reference = &transport.TPMPolicyReference{ID: parityReference.ID, Digest: req.ReferenceValues}
	}
	return transport.TPMPolicy{Name: req.Name, TenantID: req.TenantID, Branches: []transport.TPMPolicyBranch{branch}, Approved: true}
}

// parityVerify is the verify response that reports parityReference.
func parityVerify(name string) transport.TPMPolicyVerifyResponse {
	ref := parityReference
	return transport.TPMPolicyVerifyResponse{Name: name, Match: true, Approved: true, Branches: []transport.TPMPolicyBranchVerification{
		{Name: "next", Match: true, Approved: true, Reference: &ref},
	}}
}

// TestTPMPolicy_BranchAndReferenceParity proves the branch name, the
// reference values and the verify reference cross the MCP transport
// unchanged in both directions.
func TestTPMPolicy_BranchAndReferenceParity(t *testing.T) {
	updates := make(chan transport.TPMPolicyUpdateRequest, 4)
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		var result any
		switch req.Method {
		case "health":
			result = map[string]string{"status": "ok", "version": "1.0.0"}
		case "tpm.policy.update":
			var params transport.TPMPolicyUpdateRequest
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return jsonrpcResponse{ErrorText: err.Error()}
			}
			updates <- params
			result = parityPolicy(&params)
		case "tpm.policy.verify":
			var params transport.TPMPolicyRequest
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return jsonrpcResponse{ErrorText: err.Error()}
			}
			result = parityVerify(params.Name)
		default:
			return jsonrpcResponse{ErrorText: "unexpected method " + req.Method}
		}
		d, err := json.Marshal(result)
		if err != nil {
			return jsonrpcResponse{ErrorText: err.Error()}
		}
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	ctx := context.Background()

	t.Run("update with branch", func(t *testing.T) {
		req := &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot", Branch: "next"}
		p, err := tr.TPMPolicyUpdate(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, *req, <-updates)
		require.Len(t, p.Branches, 1)
		assert.Equal(t, "next", p.Branches[0].Name)
		assert.Nil(t, p.Branches[0].Reference)
	})

	t.Run("update with branch and reference values", func(t *testing.T) {
		req := &transport.TPMPolicyUpdateRequest{TenantID: "acme", Name: "boot", Branch: "next", ReferenceValues: parityCoRIM}
		p, err := tr.TPMPolicyUpdate(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, *req, <-updates)
		want := parityPolicy(req)
		assert.Equal(t, &want, p)
	})

	t.Run("verify reports the reference", func(t *testing.T) {
		v, err := tr.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
		require.NoError(t, err)
		want := parityVerify("boot")
		assert.Equal(t, &want, v)
	})
}
