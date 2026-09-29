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

//go:build frost

package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Cross-tenant isolation for the FROST routes (go-xkms#1231).
//
// Tenant A, authenticated, names a FROST key that belongs to tenant B. Every
// FROST route that takes a key ID must answer exactly as it does for a key no
// tenant holds -- the same status and the same body -- and must leave B's key
// untouched. A listing shows only the caller's keys, an import cannot replace
// another tenant's share, and a key ID is unique only within a tenant.
// ===========================================================================

const (
	frostTenantA = "tenant-a"
	frostTenantB = "tenant-b"
	frostKeyA    = "a-frost"
	frostKeyB    = "b-frost"
)

// frostTenantCall issues one FROST handler call as tenantID and returns the
// recorded response. keyID, when set, is bound as the {id} route parameter.
func frostTenantCall(t *testing.T, handler http.HandlerFunc, method, target, keyID, tenantID string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	req := tenantIdentityRequest(t, method, target, body, tenantID)
	if keyID != "" {
		req = withURLParam(req, "id", keyID)
	}
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// frostGenerateAs creates a participant-mode FROST key keyID for tenantID.
func frostGenerateAs(t *testing.T, h *HandlerContext, tenantID, keyID string) FrostGenerateKeyResponse {
	t.Helper()
	w := frostTenantCall(t, h.FrostGenerateKeyHandler, http.MethodPost, "/api/v1/frost/keys", "", tenantID,
		FrostGenerateKeyRequest{KeyID: keyID, Threshold: 2, Total: 3, ParticipantID: 1})
	require.Equal(t, http.StatusCreated, w.Code, "generating %s for %s: %s", keyID, tenantID, w.Body.String())
	var resp FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// frostCrossTenantContext registers an in-memory FROST backend and creates
// one key for each holder tenant (tenant A and tenant B when none are named).
func frostCrossTenantContext(t *testing.T, holders ...string) *HandlerContext {
	t.Helper()
	setupFrostService(t)
	h := newTestHandlerContext()

	keyOf := map[string]string{frostTenantA: frostKeyA, frostTenantB: frostKeyB}
	if len(holders) == 0 {
		holders = []string{frostTenantA, frostTenantB}
	}
	for _, tenant := range holders {
		frostGenerateAs(t, h, tenant, keyOf[tenant])
	}
	return h
}

// frostListAs lists the FROST keys tenantID can see.
func frostListAs(t *testing.T, h *HandlerContext, tenantID string) FrostListKeysResponse {
	t.Helper()
	w := frostTenantCall(t, h.FrostListKeysHandler, http.MethodGet, "/api/v1/frost/keys", "", tenantID, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp FrostListKeysResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// frostGetAs reads keyID as tenantID and returns the decoded key info.
func frostGetAs(t *testing.T, h *HandlerContext, tenantID, keyID string) FrostKeyInfo {
	t.Helper()
	w := frostTenantCall(t, h.FrostGetKeyHandler, http.MethodGet, "/api/v1/frost/keys/"+keyID, keyID, tenantID, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var info FrostKeyInfo
	require.NoError(t, json.NewDecoder(w.Body).Decode(&info))
	return info
}

// requireFrostKeyBIntact proves tenant B still holds its key.
func requireFrostKeyBIntact(t *testing.T, h *HandlerContext) {
	t.Helper()
	listed := frostListAs(t, h, frostTenantB)
	require.Len(t, listed.Keys, 1, "tenant B lost its FROST key to tenant A")
	require.Equal(t, frostKeyB, listed.Keys[0].KeyID)
}

// frostHex32 is 32 bytes of hex, long enough to stand in for any scalar or
// element a FROST round request carries.
var frostHex32 = strings.Repeat("01", 32)

// frostKeyRoute is one FROST handler that addresses a key by ID.
type frostKeyRoute struct {
	name    string
	method  string
	handler func(*HandlerContext) http.HandlerFunc
	target  func(keyID string) string
	byParam bool
	body    func(keyID string) interface{}
}

func frostKeyRoutes() []frostKeyRoute {
	commitments := []FrostCommitment{
		{ParticipantID: 1, HidingCommitment: frostHex32, BindingCommitment: frostHex32},
		{ParticipantID: 2, HidingCommitment: frostHex32, BindingCommitment: frostHex32},
	}
	return []frostKeyRoute{
		{
			name: "get", method: http.MethodGet, byParam: true,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostGetKeyHandler },
			target:  func(id string) string { return "/api/v1/frost/keys/" + id },
		},
		{
			name: "delete", method: http.MethodDelete, byParam: true,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostDeleteKeyHandler },
			target:  func(id string) string { return "/api/v1/frost/keys/" + id },
		},
		{
			name: "nonces", method: http.MethodPost, byParam: true,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostGenerateNoncesHandler },
			target:  func(id string) string { return "/api/v1/frost/keys/" + id + "/nonces" },
		},
		{
			name: "sign", method: http.MethodPost, byParam: true,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostSignRoundHandler },
			target:  func(id string) string { return "/api/v1/frost/keys/" + id + "/sign" },
			body: func(id string) interface{} {
				return FrostSignRoundRequest{
					KeyID: id, Message: "deadbeef", SessionID: "session",
					HidingNonce: frostHex32, BindingNonce: frostHex32,
					HidingCommitment: frostHex32, BindingCommitment: frostHex32,
					Commitments: commitments,
				}
			},
		},
		{
			name: "aggregate", method: http.MethodPost,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostAggregateHandler },
			target:  func(string) string { return "/api/v1/frost/aggregate" },
			body: func(id string) interface{} {
				return FrostAggregateRequest{
					KeyID: id, Message: "deadbeef", Commitments: commitments,
					Shares: []FrostSignatureShare{
						{ParticipantID: 1, Share: frostHex32},
						{ParticipantID: 2, Share: frostHex32},
					},
				}
			},
		},
		{
			name: "verify", method: http.MethodPost,
			handler: func(h *HandlerContext) http.HandlerFunc { return h.FrostVerifyHandler },
			target:  func(string) string { return "/api/v1/frost/verify" },
			body: func(id string) interface{} {
				return FrostVerifyRequest{KeyID: id, Message: "deadbeef", Signature: frostHex32 + frostHex32}
			},
		},
	}
}

// call issues the route as tenantID naming keyID.
func (r frostKeyRoute) call(t *testing.T, h *HandlerContext, tenantID, keyID string) *httptest.ResponseRecorder {
	t.Helper()
	var body interface{}
	if r.body != nil {
		body = r.body(keyID)
	}
	param := ""
	if r.byParam {
		param = keyID
	}
	return frostTenantCall(t, r.handler(h), r.method, r.target(keyID), param, tenantID, body)
}

// TestFrostHandlers_CrossTenantRefusalEqualsGenuineMiss is the go-xkms#1231
// regression for REST. For each FROST route that names a key, tenant A naming
// tenant B's key must get exactly the response -- status and body -- tenant A
// gets for the same key ID in a deployment where no tenant holds it, and
// tenant B's key must survive the attempt.
func TestFrostHandlers_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for _, route := range frostKeyRoutes() {
		t.Run(route.name, func(t *testing.T) {
			h := frostCrossTenantContext(t, frostTenantA)
			miss := route.call(t, h, frostTenantA, frostKeyB)
			require.Equal(t, http.StatusNotFound, miss.Code,
				"a genuinely missing FROST key must be 404: %s", miss.Body.String())

			h = frostCrossTenantContext(t)
			cross := route.call(t, h, frostTenantA, frostKeyB)
			assert.Equal(t, miss.Code, cross.Code,
				"tenant A reached tenant B's FROST key: %s", cross.Body.String())
			assert.Equal(t, miss.Body.String(), cross.Body.String(),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")

			requireFrostKeyBIntact(t, h)
		})
	}
}

// TestFrostHandlers_CrossTenantSigningRoundsRefused drives the exploit end to
// end: tenant A asks for Round 1 nonces over tenant B's share, then asks for a
// Round 2 signature share with them. Neither round may run.
func TestFrostHandlers_CrossTenantSigningRoundsRefused(t *testing.T) {
	h := frostCrossTenantContext(t)

	nonces := frostTenantCall(t, h.FrostGenerateNoncesHandler, http.MethodPost,
		"/api/v1/frost/keys/"+frostKeyB+"/nonces", frostKeyB, frostTenantA, nil)
	require.Equal(t, http.StatusNotFound, nonces.Code,
		"tenant A drew Round 1 nonces from tenant B's share: %s", nonces.Body.String())

	// Tenant B's own nonces, which tenant A must not be able to spend.
	own := frostTenantCall(t, h.FrostGenerateNoncesHandler, http.MethodPost,
		"/api/v1/frost/keys/"+frostKeyB+"/nonces", frostKeyB, frostTenantB, nil)
	require.Equal(t, http.StatusOK, own.Code, own.Body.String())
	var n FrostGenerateNoncesResponse
	require.NoError(t, json.NewDecoder(own.Body).Decode(&n))

	sign := frostTenantCall(t, h.FrostSignRoundHandler, http.MethodPost,
		"/api/v1/frost/keys/"+frostKeyB+"/sign", frostKeyB, frostTenantA, FrostSignRoundRequest{
			KeyID: frostKeyB, Message: "deadbeef", SessionID: n.SessionID,
			HidingNonce: n.HidingNonce, BindingNonce: n.BindingNonce,
			HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment,
			Commitments: []FrostCommitment{
				{ParticipantID: n.ParticipantID, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
				{ParticipantID: n.ParticipantID + 1, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
			},
		})
	require.Equal(t, http.StatusNotFound, sign.Code,
		"tenant A produced a signature share with tenant B's key share: %s", sign.Body.String())
}

// TestFrostListKeysHandler_ShowsOnlyCallersKeys proves a tenant's listing, and
// its total, count only that tenant's FROST keys.
func TestFrostListKeysHandler_ShowsOnlyCallersKeys(t *testing.T) {
	h := frostCrossTenantContext(t)

	listed := frostListAs(t, h, frostTenantA)
	require.Len(t, listed.Keys, 1, "tenant A saw another tenant's FROST keys: %+v", listed.Keys)
	assert.Equal(t, frostKeyA, listed.Keys[0].KeyID)
	assert.Equal(t, 1, listed.Total)
}

// TestFrostImportKeyHandler_CannotReplaceAnotherTenantsShare proves an import
// naming another tenant's key ID lands in the importer's own tenant and leaves
// the other tenant's share in place.
func TestFrostImportKeyHandler_CannotReplaceAnotherTenantsShare(t *testing.T) {
	h := frostCrossTenantContext(t)
	before := frostGetAs(t, h, frostTenantB, frostKeyB)

	dealt := frostTenantCall(t, h.FrostGenerateKeyHandler, http.MethodPost, "/api/v1/frost/keys", "", frostTenantA,
		FrostGenerateKeyRequest{KeyID: frostKeyB, Threshold: 2, Total: 3, DealerMode: true})
	require.Equal(t, http.StatusCreated, dealt.Code, dealt.Body.String())
	var gen FrostGenerateKeyResponse
	require.NoError(t, json.NewDecoder(dealt.Body).Decode(&gen))

	imported := frostTenantCall(t, h.FrostImportKeyHandler, http.MethodPost, "/api/v1/frost/keys/import", "", frostTenantA,
		FrostImportKeyRequest{Package: gen.Packages[0]})
	require.Equal(t, http.StatusCreated, imported.Code, imported.Body.String())

	after := frostGetAs(t, h, frostTenantB, frostKeyB)
	assert.Equal(t, before.GroupPublicKey, after.GroupPublicKey,
		"tenant A's import replaced tenant B's key share")
	assert.Equal(t, gen.GroupPublicKey, frostGetAs(t, h, frostTenantA, frostKeyB).GroupPublicKey,
		"tenant A's import must land in tenant A")
}

// TestFrostGenerateKeyHandler_KeyIDsAreTenantLocal proves a key ID is unique
// only within a tenant: tenant A can create a key under the ID tenant B uses,
// and the refusal a duplicate would get does not reveal that B holds it.
func TestFrostGenerateKeyHandler_KeyIDsAreTenantLocal(t *testing.T) {
	h := frostCrossTenantContext(t)

	created := frostGenerateAs(t, h, frostTenantA, frostKeyB)
	assert.Equal(t, frostKeyB, created.KeyID)
	requireFrostKeyBIntact(t, h)
	assert.Len(t, frostListAs(t, h, frostTenantA).Keys, 2)
}
