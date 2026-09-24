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
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
)

// knownServerGaps is the exact, documented set of JSON-RPC methods this
// client sends that the real MCP server (pkg/api/mcp) deliberately does not
// implement yet. Every entry here must cite the tracked gap so this table
// cannot silently grow into a place where a genuine go-xkms#762-style
// regression hides:
//
//   - PIN management (docs/pin-management/api.md: "MCP carries none of the
//     PIN surface", eight rows marked "MISSING — docs/13").
//   - Custodian groups (docs/share-custody/api.md, seven rows marked
//     "MISSING — docs/13").
//   - Tenant administration (docs/multi-tenancy/api.md: "MCP carries none
//     of the tenant surface", nine rows marked "MISSING — docs/13").
//   - Symmetric key derivation (docs/key-management/api.md: "Derive (KDF)"
//     row marked "MISSING — docs/13" on every transport but gRPC/Unix and
//     Embedded).
//   - user.* (go-xkms#758 adds this family; this client does not call it
//     yet under either an "xkms." or "user." name except the two stale
//     entries below, which #758 owns).
//
// A method belongs here only if it is untested by construction (no server
// handler exists under any name) -- not because a rename is inconvenient.
// go-xkms#762's own fix (the password.* rename, and adding
// password.setAccessMode / xkms.getBackend) is proof this list shrinks over
// time rather than growing to hide new mismatches.
var knownServerGaps = map[string]string{
	"xkms.setSOPIN":                 "docs/pin-management/api.md",
	"xkms.changeSOPIN":              "docs/pin-management/api.md",
	"xkms.verifySOPIN":              "docs/pin-management/api.md",
	"xkms.setUserPIN":               "docs/pin-management/api.md",
	"xkms.changeUserPIN":            "docs/pin-management/api.md",
	"xkms.verifyUserPIN":            "docs/pin-management/api.md",
	"xkms.getLockoutStatus":         "docs/pin-management/api.md",
	"xkms.resetLockout":             "docs/pin-management/api.md",
	"xkms.createCustodianGroup":     "docs/share-custody/api.md",
	"xkms.listCustodianGroups":      "docs/share-custody/api.md",
	"xkms.getCustodianGroup":        "docs/share-custody/api.md",
	"xkms.deleteCustodianGroup":     "docs/share-custody/api.md",
	"xkms.addCustodianMember":       "docs/share-custody/api.md",
	"xkms.removeCustodianMember":    "docs/share-custody/api.md",
	"xkms.distributeShares":         "docs/share-custody/api.md",
	"xkms.createTenant":             "docs/multi-tenancy/api.md",
	"xkms.getTenant":                "docs/multi-tenancy/api.md",
	"xkms.deleteTenant":             "docs/multi-tenancy/api.md",
	"xkms.tenantBarrierStatus":      "docs/multi-tenancy/api.md",
	"xkms.tenantBarrierInit":        "docs/multi-tenancy/api.md",
	"xkms.updateTenantEntitlements": "docs/multi-tenancy/api.md",
	"xkms.updateTenantQuotas":       "docs/multi-tenancy/api.md",
	"xkms.deriveKey":                "docs/key-management/api.md",
	"xkms.getUser":                  "go-xkms#758 (user.* family, not yet merged)",
	"xkms.listUsers":                "go-xkms#758 (user.* family, not yet merged)",
}

// literalMethodNames parses filename (a source file in this package) and
// returns every string literal that names a JSON-RPC method: the second
// argument of every t.rpcCall(ctx, "...", ...) call, plus every map value
// keyed by a REST-style path (methodMapping's entries and dynamicPatterns'
// {suffix, method: "..."} entries). It walks the AST rather than
// hand-duplicating a method list so a new rpcCall site is caught by
// construction -- the same reason go-xkms#762 asked for this test.
func literalMethodNames(t *testing.T, filename string) map[string]struct{} {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	require.NoError(t, err, "parsing %s", filename)

	methods := make(map[string]struct{})

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "rpcCall" || len(node.Args) < 2 {
				return true
			}
			lit, ok := node.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			methods[mustUnquote(t, lit.Value)] = struct{}{}

		case *ast.KeyValueExpr:
			// methodMapping entries: "/path": "method".
			if _, isPathKey := node.Key.(*ast.BasicLit); isPathKey {
				if lit, ok := node.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					methods[mustUnquote(t, lit.Value)] = struct{}{}
				}
				return true
			}
			// dynamicPatterns entries: {suffix: "...", method: "..."}.
			if ident, ok := node.Key.(*ast.Ident); ok && ident.Name == "method" {
				if lit, ok := node.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					methods[mustUnquote(t, lit.Value)] = struct{}{}
				}
			}
		}
		return true
	})

	return methods
}

// mustUnquote strips the Go string-literal quoting go/ast preserves on
// BasicLit.Value.
func mustUnquote(t *testing.T, raw string) string {
	t.Helper()
	require.True(t, len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"',
		"unexpected literal form %q", raw)
	return raw[1 : len(raw)-1]
}

// isRESTPath distinguishes a methodMapping/dynamicPatterns key ("/api/v1/...")
// from a JSON-RPC method name so literalMethodNames' generic KeyValueExpr
// branch above only ever reports the method-name side of the pair.
func isRESTPath(s string) bool {
	return len(s) > 0 && s[0] == '/'
}

// TestClientMethods_HaveServerHandlers is the regression guard for
// go-xkms#762: every JSON-RPC method this client can send must be a method
// the real MCP server (pkg/api/mcp) dispatches, or must be named in
// knownServerGaps with a citation to the tracked gap. It is what would have
// caught the "xkms.passwordAdd" vs "password.add" mismatch, and the missing
// "xkms.getBackend" / "password.setAccessMode" handlers, before they shipped.
func TestClientMethods_HaveServerHandlers(t *testing.T) {
	clientMethods := literalMethodNames(t, "transport.go")
	require.NotEmpty(t, clientMethods)

	dispatchable := make(map[string]struct{})
	for _, spec := range xkmsmcp.ModuleMethods() {
		dispatchable[spec.Method] = struct{}{}
	}
	require.NotEmpty(t, dispatchable)

	var unrouted []string
	for method := range clientMethods {
		if isRESTPath(method) {
			continue
		}
		if _, dispatched := dispatchable[method]; dispatched {
			continue
		}
		if _, known := knownServerGaps[method]; known {
			continue
		}
		unrouted = append(unrouted, method)
	}
	sort.Strings(unrouted)
	assert.Empty(t, unrouted,
		"client sends JSON-RPC methods the server does not dispatch and that "+
			"are not in knownServerGaps: %v", unrouted)

	// The inverse: every knownServerGaps entry must still be a method the
	// client actually sends and the server still does not implement. An
	// entry that stops being true here is stale bookkeeping -- either the
	// server gained the handler (delete the row) or the client stopped
	// calling it (delete the row).
	for method, gap := range knownServerGaps {
		_, calledByClient := clientMethods[method]
		assert.True(t, calledByClient, "knownServerGaps[%q] (%s) is no longer called by the client", method, gap)
		_, dispatched := dispatchable[method]
		assert.False(t, dispatched, "knownServerGaps[%q] (%s) is now dispatchable; remove it from the gap list", method, gap)
	}
}
