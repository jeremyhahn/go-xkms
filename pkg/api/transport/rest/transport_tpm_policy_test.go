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

package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// TestTPMPolicy_ReachesTheServer proves a connected transport serves the TPM
// policy API over the REST routes: the policy name travels in the path and
// the tenant in the query, and the server's policy is decoded. The routes
// and bodies of every method are tested once, in pkg/api/rest/wire.
func TestTPMPolicy_ReachesTheServer(t *testing.T) {
	srv := newFullMockServer(t)
	defer srv.Close()
	tr := connectFullMock(t, srv)

	p, err := tr.TPMPolicyGet(context.Background(), &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, "boot", p.Name)
	assert.Equal(t, "acme", p.TenantID)
	assert.Equal(t, []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}, p.Branches)
}

// TestTPMPolicy_NotConnected proves every TPM policy method refuses before
// the transport is connected.
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

// parityHandler serves policy "boot"'s update and verify routes the way the
// server does: the name from the path, the tenant from the body or the
// query. It records each update request it decodes on updates.
func parityHandler(updates chan<- transport.TPMPolicyUpdateRequest) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch {
		case r.URL.Path == "/health":
			result = map[string]string{"status": "healthy", "version": "1.0.0"}
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tpm/policies/boot/update":
			var req transport.TPMPolicyUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req.Name = "boot"
			if req.TenantID == "" {
				req.TenantID = r.URL.Query().Get("tenant_id")
			}
			updates <- req
			result = parityPolicy(&req)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tpm/policies/boot/verify":
			result = parityVerify("boot")
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
}

// TestTPMPolicy_BranchAndReferenceParity proves the branch name, the
// reference values and the verify reference cross the REST transport
// unchanged in both directions.
func TestTPMPolicy_BranchAndReferenceParity(t *testing.T) {
	updates := make(chan transport.TPMPolicyUpdateRequest, 4)
	srv := httptest.NewServer(parityHandler(updates))
	defer srv.Close()
	tr := connectFullMock(t, srv)
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
