// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// wireCase is one Transport verb together with the server tool it must
// reach and the params it must send there.
type wireCase struct {
	name   string
	method string
	params any
	call   func(ctx context.Context, tr *Transport) error
}

// tenantParams is the params object every tenant-scoped verb sends.
var tenantParams = map[string]string{"tenant_id": "acme"}

// errOf drops a verb's result so every case shares one call signature.
func errOf[T any](_ T, err error) error { return err }

// wireCases lists the verbs whose routing and error propagation are pinned
// here; each entry names the exact server tool the server registers.
func wireCases() []wireCase {
	keyVersion := &transport.KeyVersionRequest{Backend: "software", KeyID: "signer", Version: 2}
	allVersions := &transport.AllKeyVersionsRequest{Backend: "software", KeyID: "signer"}
	policy := &transport.TPMPolicyRequest{Name: "boot", TenantID: "acme"}
	branch := 1
	update := &transport.TPMPolicyUpdateRequest{Name: "boot", TenantID: "acme", Branch: &branch, ReferenceValues: []byte{0xd2, 0x84}}
	oidcRef := &transport.OIDCCredentialRef{Owner: "alice"}
	return []wireCase{
		{"Algorithms", "xkms.algorithms", nil, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.Algorithms(ctx))
		}},
		{"GetInvite", "invite.get", &transport.GetInviteRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.GetInvite(ctx, &transport.GetInviteRequest{}))
		}},
		{"ActivateInvitePIV", "invite.pivActivate", &transport.ActivateInvitePIVRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{}))
		}},
		{"IssueLAKCertificate", "xkms.ca.tcg.issue-lak", &transport.IssueLAKCertificateRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.IssueLAKCertificate(ctx, &transport.IssueLAKCertificateRequest{}))
		}},
		{"ListPIVSlots", "xkms.listPIVSlots", &transport.ListPIVSlotsRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{}))
		}},
		{"EnableKeyVersion", "xkms.enableKeyVersion", keyVersion, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.EnableKeyVersion(ctx, keyVersion))
		}},
		{"DisableKeyVersion", "xkms.disableKeyVersion", keyVersion, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.DisableKeyVersion(ctx, keyVersion))
		}},
		{"RetireKeyVersion", "xkms.retireKeyVersion", keyVersion, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.RetireKeyVersion(ctx, keyVersion))
		}},
		{"EnableAllKeyVersions", "xkms.enableAllKeyVersions", allVersions, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.EnableAllKeyVersions(ctx, allVersions))
		}},
		{"DisableAllKeyVersions", "xkms.disableAllKeyVersions", allVersions, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.DisableAllKeyVersions(ctx, allVersions))
		}},
		{"TPMPolicyCreate", "tpm.policy.create", &transport.TPMPolicyCreateRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{}))
		}},
		{"TPMPolicyGet", "tpm.policy.get", policy, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyGet(ctx, policy))
		}},
		{"TPMPolicyList", "tpm.policy.list", &transport.TPMPolicyListRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{}))
		}},
		{"TPMPolicyUpdate", "tpm.policy.update", update, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyUpdate(ctx, update))
		}},
		{"TPMPolicyRevoke", "tpm.policy.revoke", policy, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyRevoke(ctx, policy))
		}},
		{"TPMPolicyVerify", "tpm.policy.verify", policy, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyVerify(ctx, policy))
		}},
		{"TPMPolicyDelete", "tpm.policy.delete", &transport.TPMPolicyDeleteRequest{}, func(ctx context.Context, tr *Transport) error {
			return tr.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{})
		}},
		{"TPMPolicyObjects", "tpm.policy.objects", policy, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyObjects(ctx, policy))
		}},
		{"TPMPolicySetAutoUnseal", "tpm.policy.autoUnseal", &transport.TPMPolicyAutoUnsealRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{}))
		}},
		{"TPMPolicySetDescription", "tpm.policy.setDescription", &transport.TPMPolicyDescriptionRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{}))
		}},
		{"TPMObjectPolicy", "tpm.object.policy", &transport.TPMObjectPolicyRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{}))
		}},
		{"TPMPolicyRotateAuthority", "tpm.authority.rotate", &transport.TPMAuthorityRotateRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{}))
		}},
		{"GetTenantTPMMode", "xkms.getTenantTPMMode", tenantParams, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.GetTenantTPMMode(ctx, "acme"))
		}},
		{"SetTenantTPMMode", "xkms.setTenantTPMMode", &transport.SetTenantTPMModeRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{}))
		}},
		{"TenantVTPMStatus", "xkms.tenantVTPMStatus", tenantParams, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TenantVTPMStatus(ctx, "acme"))
		}},
		{"TenantVTPMStart", "xkms.tenantVTPMStart", tenantParams, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TenantVTPMStart(ctx, "acme"))
		}},
		{"TenantVTPMStop", "xkms.tenantVTPMStop", tenantParams, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.TenantVTPMStop(ctx, "acme"))
		}},
		{"UpdateTenantEntitlements", "xkms.updateTenantEntitlements", &transport.UpdateTenantEntitlementsRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{}))
		}},
		{"UpdateTenantQuotas", "xkms.updateTenantQuotas", &transport.UpdateTenantQuotasRequest{}, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{}))
		}},
		{"OIDCCredentialGet", "oidc.credential.get", oidcRef, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.OIDCCredentialGet(ctx, oidcRef))
		}},
		{"OIDCCredentialGetAccessToken", "oidc.credential.token", oidcRef, func(ctx context.Context, tr *Transport) error {
			return errOf(tr.OIDCCredentialGetAccessToken(ctx, oidcRef))
		}},
	}
}

// TestWire_VerbsReachTheirTool pins each verb's tool name and params: a
// verb sent to the wrong tool, or with a reshaped payload, fails against a
// real server even though the client compiles.
func TestWire_VerbsReachTheirTool(t *testing.T) {
	var (
		mu       sync.Mutex
		received []jsonrpcRequest
	)
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "health" {
			mu.Lock()
			received = append(received, req)
			mu.Unlock()
		}
		return jsonrpcResponse{Result: json.RawMessage(`{}`)}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	for _, tc := range wireCases() {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			received = nil
			mu.Unlock()

			require.NoError(t, tc.call(context.Background(), tr))

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, received, 1)
			assert.Equal(t, tc.method, received[0].Method)
			if tc.params == nil {
				return
			}
			want, err := json.Marshal(tc.params)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(received[0].Params))
		})
	}
}

// TestWire_VerbsSurfaceToolErrors checks every verb hands the server's
// classified error back as an *RPCError instead of a zero-valued result.
func TestWire_VerbsSurfaceToolErrors(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: json.RawMessage(`{"status":"ok"}`)}
		}
		return jsonrpcResponse{ErrorText: "no such object", Envelope: qrdbsdk.MCPCodeNotFound}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	for _, tc := range wireCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(context.Background(), tr)
			var rpcErr *RPCError
			require.True(t, errors.As(err, &rpcErr), "got %v", err)
			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, rpcErr.Code)
			assert.Equal(t, "no such object", rpcErr.Message)
		})
	}
}

// TestConnect_HealthFailureClosesSession checks a server that accepts the
// session but fails its health check leaves the transport disconnected and
// reports ErrConnectionFailed.
func TestConnect_HealthFailureClosesSession(t *testing.T) {
	addr, cleanup := startMockServer(t, func(jsonrpcRequest) jsonrpcResponse {
		return jsonrpcResponse{ErrorText: "starting up", Envelope: qrdbsdk.MCPCodeUnavailable}
	})
	defer cleanup()

	tr, err := New(transport.WithAddress(addr))
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.ErrorIs(t, err, ErrConnectionFailed)
	assert.Contains(t, err.Error(), "starting up")
	assert.False(t, tr.IsConnected())
}

// TestInviteRegistration_ExcludedByDesign checks the invite WebAuthn
// ceremony is refused on MCP, like the other identity ceremonies.
func TestInviteRegistration_ExcludedByDesign(t *testing.T) {
	tr := &Transport{}
	_, err := tr.BeginInviteRegistration(context.Background(), &transport.BeginInviteRegistrationRequest{})
	assert.ErrorIs(t, err, ErrIdentityCeremonyExcluded)
	_, err = tr.FinishInviteRegistration(context.Background(), &transport.FinishInviteRegistrationRequest{})
	assert.ErrorIs(t, err, ErrIdentityCeremonyExcluded)
}
