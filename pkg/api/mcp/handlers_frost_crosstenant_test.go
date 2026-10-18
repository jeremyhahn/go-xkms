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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ===========================================================================
// Cross-tenant isolation for the frost.* MCP methods (go-xkms#1231).
//
// Tenant A, authenticated, names a FROST key that belongs to tenant B. Every
// frost.* method that takes a key ID must answer exactly as it does for a key
// no tenant holds -- the same JSON-RPC code and the same message -- and must
// leave B's key untouched. A listing shows only the caller's keys and an
// import cannot replace another tenant's share.
// ===========================================================================

const (
	frostTenantA = "tenant-a"
	frostTenantB = "tenant-b"
	frostKeyA    = "a-frost"
	frostKeyB    = "b-frost"
)

// frostTenantCtx returns a context authenticated as tenantID.
func frostTenantCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "svc", TenantID: tenantID})
}

// frostCrossTenantServer registers an in-memory FROST backend and creates one
// participant-mode key for each holder tenant (A and B when none are named).
func frostCrossTenantServer(t *testing.T, holders ...string) *Server {
	t.Helper()
	server := newFrostMCPServer(t)

	keyOf := map[string]string{frostTenantA: frostKeyA, frostTenantB: frostKeyB}
	if len(holders) == 0 {
		holders = []string{frostTenantA, frostTenantB}
	}
	for _, tenant := range holders {
		_, err := server.handleFrostGenerateKey(frostTenantCtx(tenant), frostReq(t, "frost.generateKey",
			FrostGenerateKeyParams{KeyID: keyOf[tenant], Threshold: 2, Total: 3, ParticipantID: 1}))
		require.NoError(t, err, "generating %s for %s", keyOf[tenant], tenant)
	}
	return server
}

// frostListAs lists the FROST keys tenantID can see.
func frostListAs(t *testing.T, server *Server, tenantID string) FrostListKeysResult {
	t.Helper()
	res, err := server.handleFrostListKeys(frostTenantCtx(tenantID), frostReq(t, "frost.listKeys", struct{}{}))
	require.NoError(t, err)
	listed, ok := res.(FrostListKeysResult)
	require.True(t, ok, "unexpected result type %T", res)
	return listed
}

// frostGetAs reads keyID as tenantID.
func frostGetAs(t *testing.T, server *Server, tenantID, keyID string) FrostKeyInfo {
	t.Helper()
	res, err := server.handleFrostGetKey(frostTenantCtx(tenantID), frostReq(t, "frost.getKey", FrostGetKeyParams{KeyID: keyID}))
	require.NoError(t, err)
	info, ok := res.(FrostKeyInfo)
	require.True(t, ok, "unexpected result type %T", res)
	return info
}

// requireFrostKeyBIntact proves tenant B still holds its key.
func requireFrostKeyBIntact(t *testing.T, server *Server) {
	t.Helper()
	listed := frostListAs(t, server, frostTenantB)
	require.Len(t, listed.Keys, 1, "tenant B lost its FROST key to tenant A")
	require.Equal(t, frostKeyB, listed.Keys[0].KeyID)
}

// frostHex32 is 32 bytes of hex standing in for any scalar or element a FROST
// round request carries.
var frostHex32 = strings.Repeat("01", 32)

// frostKeyMethod is one frost.* method that addresses a key by ID.
type frostKeyMethod struct {
	method string
	params func(keyID string) interface{}
}

func frostKeyMethods() []frostKeyMethod {
	commitments := []FrostCommitment{
		{ParticipantID: 1, HidingCommitment: frostHex32, BindingCommitment: frostHex32},
		{ParticipantID: 2, HidingCommitment: frostHex32, BindingCommitment: frostHex32},
	}
	return []frostKeyMethod{
		{"frost.getKey", func(id string) interface{} { return FrostGetKeyParams{KeyID: id} }},
		{"frost.deleteKey", func(id string) interface{} { return FrostDeleteKeyParams{KeyID: id} }},
		{"frost.generateNonces", func(id string) interface{} { return FrostGenerateNoncesParams{KeyID: id} }},
		{"frost.signRound", func(id string) interface{} {
			return FrostSignRoundParams{
				KeyID: id, Message: "deadbeef", SessionID: "session",
				HidingNonce: frostHex32, BindingNonce: frostHex32,
				HidingCommitment: frostHex32, BindingCommitment: frostHex32,
				Commitments: commitments,
			}
		}},
		{"frost.aggregate", func(id string) interface{} {
			return FrostAggregateParams{
				KeyID: id, Message: "deadbeef", Commitments: commitments,
				Shares: []FrostSignatureShare{{ParticipantID: 1, Share: frostHex32}, {ParticipantID: 2, Share: frostHex32}},
			}
		}},
		{"frost.verify", func(id string) interface{} {
			return FrostVerifyParams{KeyID: id, Message: "deadbeef", Signature: frostHex32 + frostHex32}
		}},
	}
}

// frostWireOutcome is what a JSON-RPC caller sees for one call: the result, or
// the error code and message.
type frostWireOutcome struct {
	Code    int
	Message string
	Result  string
}

// call dispatches the method as tenantID naming keyID and renders the outcome
// the way the wire does.
func (m frostKeyMethod) call(t *testing.T, server *Server, tenantID, keyID string) frostWireOutcome {
	t.Helper()
	entry, registered := rpcMethods[m.method]
	require.True(t, registered, "%s must be registered", m.method)
	result, err := entry.handler(server, frostTenantCtx(tenantID), frostReq(t, m.method, m.params(keyID)))
	if err != nil {
		code, message := ClientError(err)
		return frostWireOutcome{Code: code, Message: message}
	}
	raw, marshalErr := json.Marshal(result)
	require.NoError(t, marshalErr)
	return frostWireOutcome{Result: string(raw)}
}

// TestFrostMethods_CrossTenantRefusalEqualsGenuineMiss is the go-xkms#1231
// regression for MCP. For each frost.* method that names a key, tenant A
// naming tenant B's key must get exactly the error tenant A gets for the same
// key ID in a deployment where no tenant holds it, and B's key must survive.
func TestFrostMethods_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for _, m := range frostKeyMethods() {
		t.Run(m.method, func(t *testing.T) {
			server := frostCrossTenantServer(t, frostTenantA)
			miss := m.call(t, server, frostTenantA, frostKeyB)
			require.Equal(t, sdkssh.JSONRPCCodeNotFound, miss.Code,
				"a genuinely missing FROST key must be Not found: %+v", miss)

			server = frostCrossTenantServer(t)
			cross := m.call(t, server, frostTenantA, frostKeyB)
			assert.Equal(t, miss, cross, "a cross-tenant refusal must be indistinguishable from a genuine miss")

			requireFrostKeyBIntact(t, server)
		})
	}
}

// TestFrostMethods_CrossTenantSigningRoundsRefused drives the exploit end to
// end: tenant A may neither draw nonces from tenant B's share nor spend tenant
// B's nonces on a signature share.
func TestFrostMethods_CrossTenantSigningRoundsRefused(t *testing.T) {
	server := frostCrossTenantServer(t)

	_, err := server.handleFrostGenerateNonces(frostTenantCtx(frostTenantA),
		frostReq(t, "frost.generateNonces", FrostGenerateNoncesParams{KeyID: frostKeyB}))
	require.Error(t, err, "tenant A drew nonces from tenant B's share")
	assertKeyOpCode(t, err, sdkssh.JSONRPCCodeNotFound)

	res, err := server.handleFrostGenerateNonces(frostTenantCtx(frostTenantB),
		frostReq(t, "frost.generateNonces", FrostGenerateNoncesParams{KeyID: frostKeyB}))
	require.NoError(t, err)
	n, ok := res.(FrostGenerateNoncesResult)
	require.True(t, ok)

	_, err = server.handleFrostSignRound(frostTenantCtx(frostTenantA), frostReq(t, "frost.signRound", FrostSignRoundParams{
		KeyID: frostKeyB, Message: "deadbeef", SessionID: n.SessionID,
		HidingNonce: n.HidingNonce, BindingNonce: n.BindingNonce,
		HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment,
		Commitments: []FrostCommitment{
			{ParticipantID: n.ParticipantID, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
			{ParticipantID: n.ParticipantID + 1, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
		},
	}))
	require.Error(t, err, "tenant A produced a signature share with tenant B's key share")
	assertKeyOpCode(t, err, sdkssh.JSONRPCCodeNotFound)
}

// TestFrostListKeys_ShowsOnlyCallersKeys proves a tenant's listing counts only
// that tenant's FROST keys.
func TestFrostListKeys_ShowsOnlyCallersKeys(t *testing.T) {
	server := frostCrossTenantServer(t)

	listed := frostListAs(t, server, frostTenantA)
	require.Len(t, listed.Keys, 1, "tenant A saw another tenant's FROST keys: %+v", listed.Keys)
	assert.Equal(t, frostKeyA, listed.Keys[0].KeyID)
	assert.Equal(t, 1, listed.Total)
}

// TestFrostImportKey_CannotReplaceAnotherTenantsShare proves an import naming
// another tenant's key ID lands in the importer's tenant.
func TestFrostImportKey_CannotReplaceAnotherTenantsShare(t *testing.T) {
	server := frostCrossTenantServer(t)
	before := frostGetAs(t, server, frostTenantB, frostKeyB)

	res, err := server.handleFrostGenerateKey(frostTenantCtx(frostTenantA), frostReq(t, "frost.generateKey",
		FrostGenerateKeyParams{KeyID: frostKeyB, Threshold: 2, Total: 3, DealerMode: true}))
	require.NoError(t, err)
	dealt, ok := res.(FrostGenerateKeyResult)
	require.True(t, ok)

	_, err = server.handleFrostImportKey(frostTenantCtx(frostTenantA), frostReq(t, "frost.importKey",
		FrostImportKeyParams{Package: dealt.Packages[0]}))
	require.NoError(t, err)

	after := frostGetAs(t, server, frostTenantB, frostKeyB)
	assert.Equal(t, before.GroupPublicKey, after.GroupPublicKey, "tenant A's import replaced tenant B's key share")
	assert.Equal(t, dealt.GroupPublicKey, frostGetAs(t, server, frostTenantA, frostKeyB).GroupPublicKey,
		"tenant A's import must land in tenant A")
}
