// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// errRequestFailed stands in for a transport failure.
var errRequestFailed = errors.New("test: request failed")

// recorded is one request a recordingRequester received.
type recorded struct {
	method, path string
	body         map[string]any
}

// recordingRequester records every request and answers it with response.
type recordingRequester struct {
	requests []recorded
	response string
	err      error
}

func (r *recordingRequester) do(_ context.Context, method, path string, body any) ([]byte, error) {
	rec := recorded{method: method, path: path}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &rec.body); err != nil {
			return nil, err
		}
	}
	r.requests = append(r.requests, rec)
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.response), nil
}

// last returns the last recorded request.
func (r *recordingRequester) last() recorded { return r.requests[len(r.requests)-1] }

// TestTPMPolicyClient_Routes proves every method sends its request to the
// route the server registers: the method, the path (with the policy name,
// key ID or tenant escaped into it), the query and the body.
func TestTPMPolicyClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := TPMPolicyClient{Do: rec.do}
	ctx := context.Background()

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"create", func() error {
			_, err := c.TPMPolicyCreate(ctx, &transport.TPMPolicyCreateRequest{TenantID: "acme", Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{7})}})
			return err
		}, http.MethodPost, "/api/v1/tpm/policies", map[string]any{"tenant_id": "acme", "name": "boot", "branches": []any{map[string]any{
			"conditions": []any{map[string]any{"type": "pcr", "bank": "sha256", "pcrs": []any{7.0}}}, "approved": false,
		}}}},
		{"get", func() error {
			_, err := c.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "a b"})
			return err
		},
			http.MethodGet, "/api/v1/tpm/policies/a%20b?tenant_id=acme", nil},
		{"list", func() error { _, err := c.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{}); return err },
			http.MethodGet, "/api/v1/tpm/policies", nil},
		{"update", func() error {
			_, err := c.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot"})
			return err
		},
			http.MethodPost, "/api/v1/tpm/policies/boot/update", map[string]any{"name": "boot"}},
		{"branch update", func() error {
			branch := 1
			_, err := c.TPMPolicyUpdate(ctx, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: &branch, ReferenceValues: []byte{0xd2, 0x84}})
			return err
		}, http.MethodPost, "/api/v1/tpm/policies/boot/update", map[string]any{"name": "boot", "branch": 1.0, "reference_values": "0oQ="}},
		{"revoke", func() error { _, err := c.TPMPolicyRevoke(ctx, &transport.TPMPolicyRequest{Name: "boot"}); return err },
			http.MethodPost, "/api/v1/tpm/policies/boot/revoke", map[string]any{"name": "boot"}},
		{"verify", func() error { _, err := c.TPMPolicyVerify(ctx, &transport.TPMPolicyRequest{Name: "boot"}); return err },
			http.MethodPost, "/api/v1/tpm/policies/boot/verify", map[string]any{"name": "boot"}},
		{"delete", func() error {
			return c.TPMPolicyDelete(ctx, &transport.TPMPolicyDeleteRequest{Name: "boot", OwnerAuth: []byte("o")})
		}, http.MethodDelete, "/api/v1/tpm/policies/boot", map[string]any{"name": "boot", "owner_auth": "bw=="}},
		{"objects", func() error {
			_, err := c.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{TenantID: "acme", Name: "boot"})
			return err
		}, http.MethodGet, "/api/v1/tpm/policies/boot/objects?tenant_id=acme", nil},
		{"auto-unseal", func() error {
			_, err := c.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: "boot", Enabled: true})
			return err
		}, http.MethodPost, "/api/v1/tpm/policies/boot/auto-unseal", map[string]any{"name": "boot", "enabled": true}},
		{"description", func() error {
			_, err := c.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: "boot", Description: "firmware"})
			return err
		}, http.MethodPost, "/api/v1/tpm/policies/boot/description", map[string]any{"name": "boot", "description": "firmware"}},
		{"object policy", func() error {
			_, err := c.TPMObjectPolicy(ctx, &transport.TPMObjectPolicyRequest{KeyID: "signer", Kind: "sealed"})
			return err
		}, http.MethodGet, "/api/v1/keys/signer/tpm-policy?kind=sealed", nil},
		{"rotate", func() error {
			_, err := c.TPMPolicyRotateAuthority(ctx, &transport.TPMAuthorityRotateRequest{TenantID: "acme"})
			return err
		}, http.MethodPost, "/api/v1/tpm/authority/rotate", map[string]any{"tenant_id": "acme"}},
		{"get mode", func() error { _, err := c.GetTenantTPMMode(ctx, "acme"); return err },
			http.MethodGet, "/api/v1/tenants/acme/tpm", nil},
		{"set mode", func() error {
			_, err := c.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
			return err
		}, http.MethodPut, "/api/v1/tenants/acme/tpm", map[string]any{"tenant_id": "acme", "mode": "none"}},
		{"vtpm status", func() error { _, err := c.TenantVTPMStatus(ctx, "acme"); return err },
			http.MethodGet, "/api/v1/tenants/acme/tpm/vtpm", nil},
		{"vtpm start", func() error { _, err := c.TenantVTPMStart(ctx, "acme"); return err },
			http.MethodPost, "/api/v1/tenants/acme/tpm/vtpm/start", nil},
		{"vtpm stop", func() error { _, err := c.TenantVTPMStop(ctx, "acme"); return err },
			http.MethodPost, "/api/v1/tenants/acme/tpm/vtpm/stop", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
			assert.Equal(t, tt.body, got.body)
		})
	}
}

// TestTPMPolicyClient_DecodesResponses proves the server's JSON answer is
// decoded into the method's transport type.
func TestTPMPolicyClient_DecodesResponses(t *testing.T) {
	rec := &recordingRequester{response: `{"name":"boot","tenant_id":"acme","description":"d","branches":[{"conditions":[{"type":"pcr","bank":"sha256","pcrs":[7]}],"approved":true}],"approved":true}`}
	c := TPMPolicyClient{Do: rec.do}
	p, err := c.TPMPolicyGet(context.Background(), &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, &transport.TPMPolicy{
		Name: "boot", TenantID: "acme", Description: "d", Approved: true,
		Branches: []transport.TPMPolicyBranch{{Conditions: []transport.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", PCRs: []uint{7}}}, Approved: true}},
	}, p)

	rec.response = `{"policies":[{"name":"boot"}]}`
	list, err := c.TPMPolicyList(context.Background(), &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
}

// TestTPMPolicyClient_Failures proves a request failure passes through, an
// undecodable answer is a *DecodeError naming the path, and a nil request is
// refused without a request.
func TestTPMPolicyClient_Failures(t *testing.T) {
	failing := TPMPolicyClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	_, err := failing.TPMPolicyVerify(context.Background(), &transport.TPMPolicyRequest{Name: "boot"})
	require.ErrorIs(t, err, errRequestFailed)
	require.ErrorIs(t, failing.TPMPolicyDelete(context.Background(), &transport.TPMPolicyDeleteRequest{Name: "boot"}), errRequestFailed)

	garbled := TPMPolicyClient{Do: (&recordingRequester{response: "not json"}).do}
	_, err = garbled.TenantVTPMStatus(context.Background(), "acme")
	var decodeErr *DecodeError
	require.ErrorAs(t, err, &decodeErr)
	assert.Equal(t, "/api/v1/tenants/acme/tpm/vtpm", decodeErr.Path)
	assert.Contains(t, decodeErr.Error(), decodeErr.Path)
	assert.NotNil(t, decodeErr.Unwrap())

	rec := &recordingRequester{}
	c := TPMPolicyClient{Do: rec.do}
	ctx := context.Background()
	nilCalls := []error{
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
	for i, err := range nilCalls {
		assert.ErrorIs(t, err, ErrNilRequest, "call %d", i)
	}
	assert.Empty(t, rec.requests, "a nil request sends nothing")
}
