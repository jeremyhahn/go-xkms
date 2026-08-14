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

package initgate

import (
	"strings"
	"testing"

	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTableCoversEveryOp asserts every canonical operation has a table entry
// with at least one transport name, and that Ops carries no duplicates.
func TestTableCoversEveryOp(t *testing.T) {
	seen := make(map[Op]struct{}, len(Ops))
	for _, op := range Ops {
		_, dup := seen[op]
		require.Falsef(t, dup, "operation %q listed twice in Ops", op)
		seen[op] = struct{}{}

		names, ok := Table[op]
		require.Truef(t, ok, "operation %q missing from Table", op)
		assert.Falsef(t, names.HTTP == "" && names.MCP == "" && names.GRPC == "",
			"operation %q has no transport surface at all", op)
	}
	assert.Len(t, Table, len(Ops), "Table must not carry entries absent from Ops")
}

// TestHTTPPublicPaths_ExactHistoricalSet locks the derived HTTP allowlist to
// the exact five paths the REST and QUIC transports have always exempted.
// Any addition or removal here is a security-posture change and must be a
// deliberate table edit, reviewed as such.
func TestHTTPPublicPaths_ExactHistoricalSet(t *testing.T) {
	want := map[string]bool{
		"/api/v1/init/status":               true,
		"/api/v1/init/claim-cert/begin":     true,
		"/api/v1/init/claim-cert/complete":  true,
		"/api/v1/init/claim-share/begin":    true,
		"/api/v1/init/claim-share/complete": true,
	}
	assert.Equal(t, want, HTTPPublicPaths())
}

// TestMCPPublicMethods_ExactHistoricalSet locks the derived MCP allowlist to
// the exact five methods the MCP transport has always exempted.
func TestMCPPublicMethods_ExactHistoricalSet(t *testing.T) {
	want := map[string]struct{}{
		"init.getStatus":          {},
		"init.claimCertBegin":     {},
		"init.claimCertComplete":  {},
		"init.claimShareBegin":    {},
		"init.claimShareComplete": {},
	}
	assert.Equal(t, want, MCPPublicMethods())
}

// TestGRPCPublicMethods_Empty pins the fact that no init ceremony RPC exists
// on the gRPC (and therefore unix) transport. If this test fails, an init
// ceremony RPC was added to the table: wire the pre-operational gate into
// the gRPC interceptor chain and the unix server before shipping it.
func TestGRPCPublicMethods_Empty(t *testing.T) {
	assert.Empty(t, GRPCPublicMethods(),
		"KeystoreService declares no init ceremony RPC; adding one requires wiring the initgate on gRPC and unix")
}

// TestExclusions_SignCSRNeverExempt asserts sign-csr is excluded from every
// derivation on every transport: it requires the SO PIN and belongs to an
// already-enrolled operator.
func TestExclusions_SignCSRNeverExempt(t *testing.T) {
	require.True(t, Excluded(OpSignCSR))

	names := Table[OpSignCSR]
	_, inHTTP := HTTPPublicPaths()[names.HTTP]
	assert.False(t, inHTTP, "sign-csr HTTP path must not be exempt")
	_, inMCP := MCPPublicMethods()[names.MCP]
	assert.False(t, inMCP, "sign-csr MCP method must not be exempt")

	// Every excluded operation must still name its wire surface so the
	// parity tests can account for the complete mounted ceremony routes.
	for op, reason := range Exclusions {
		_, ok := Table[op]
		assert.Truef(t, ok, "excluded operation %q (%s) missing from Table", op, reason)
	}
}

// TestDerivations_ExactMatchOnly guards against prefix-match
// reintroduction: no derived entry may end in "/" (the prefix-match
// convention) and no derived HTTP path may be a proper prefix of another
// mounted ceremony route. "/api/v1/init" as a prefix would also exempt
// hypothetical routes such as "/api/v1/initialize", and it silently
// re-admits any route a later change mounts beneath it.
func TestDerivations_ExactMatchOnly(t *testing.T) {
	for p := range HTTPPublicPaths() {
		assert.Falsef(t, strings.HasSuffix(p, "/"),
			"HTTP allowlist entry %q ends in '/': prefix matching is forbidden", p)
	}
	for m := range MCPPublicMethods() {
		assert.Falsef(t, strings.HasSuffix(m, "."),
			"MCP allowlist entry %q ends in '.': prefix matching is forbidden", m)
	}

	// No exempt path may cover another table route by prefix extension.
	paths := HTTPPublicPaths()
	for exempt := range paths {
		for _, op := range Ops {
			route := Table[op].HTTP
			if route == "" || route == exempt {
				continue
			}
			assert.Falsef(t, strings.HasPrefix(route, exempt+"/"),
				"exempt path %q is a parent of mounted route %q; exact-match integrity broken", exempt, route)
		}
	}
}

// TestPreOperational_FailsClosed asserts the state gate admits exactly the
// two pre-operational states and fails closed on everything else, including
// the empty string and state names a future go-qrdb release might add.
func TestPreOperational_FailsClosed(t *testing.T) {
	assert.True(t, PreOperational(initialize.StateAwaitingInit))
	assert.True(t, PreOperational(initialize.StateEnrolling))

	assert.False(t, PreOperational(initialize.StateOperational),
		"operational must never qualify: serving the claim surface unauthenticated on an initialized daemon is a live vulnerability")
	assert.False(t, PreOperational(initialize.CeremonyState("")))
	assert.False(t, PreOperational(initialize.CeremonyState("some-future-state")))
}

// TestPreOperationalName_MirrorsPreOperational asserts the wire-string
// predicate is byte-for-byte consistent with the typed predicate.
func TestPreOperationalName_MirrorsPreOperational(t *testing.T) {
	for _, state := range []initialize.CeremonyState{
		initialize.StateAwaitingInit,
		initialize.StateEnrolling,
		initialize.StateOperational,
		initialize.CeremonyState(""),
		initialize.CeremonyState("some-future-state"),
	} {
		assert.Equalf(t, PreOperational(state), PreOperationalName(string(state)),
			"typed and wire-string predicates diverge for state %q", state)
	}
}
