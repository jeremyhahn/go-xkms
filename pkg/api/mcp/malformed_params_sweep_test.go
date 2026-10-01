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
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// paramsOptionalMethods is the exact, documented set of JSON-RPC methods
// whose handler never decodes req.Params -- either the method carries no
// parameters at all, or every field it might read is genuinely optional and
// left unparsed when absent -- so malformed JSON cannot produce a decode
// failure for them.
//
// TestEveryHandler_MalformedParamsAreInvalidParams below iterates every
// entry of rpcMethodHandlers; a handler that starts decoding params without
// removing itself from this table is expected to reject malformed JSON with
// ErrCodeInvalidParams, and the test fails loudly if it does not. This
// mirrors method_parity_test.go's knownServerGaps: a table a reviewer can
// see shrink or grow, not a default branch a new handler quietly falls into
// (go-xkms#774).
var paramsOptionalMethods = map[string]string{
	"health":                     "no parameters",
	"xkms.algorithms":            "no parameters",
	"user.list":                  "no parameters",
	"xkms.listShares":            "no parameters",
	"init.getStatus":             "no parameters",
	"credentials.strategy":       "no parameters",
	"password.lock":              "no parameters (tenant comes from the caller's identity)",
	"password.status":            "no parameters (tenant comes from the caller's identity)",
	"password.vault.status":      "no parameters (the vault is the caller's)",
	"bootstrap.showKeys":         "no parameters",
	"sealStore.list":             "no parameters",
	"sealStore.status":           "no parameters",
	"policy.list":                "no parameters",
	"barrier.seal":               "no parameters",
	"barrier.status":             "no parameters",
	"barrier.deleteRecoveryKeys": "no parameters",
	"barrier.hasRecoveryKeys":    "no parameters",
	"xkms.getLockoutStatus":      "no parameters",
	"xkms.listCustodianGroups":   "no parameters",
	"xkms.listTenants":           "no parameters",
	"xkms.listBackups":           "no parameters",
}

// methodContext supplies a per-method context override for the handful of
// handlers whose own precondition runs -- and fails on that precondition,
// not on decoding -- before decodeParams ever sees req.Params against a bare
// context.Background() caller.
//
// init.claimShareBegin and init.claimShareComplete authenticate the officer
// from a verified mTLS peer certificate (callerCertThumbprint,
// handlers_init_credentials.go) before decoding, by design (the officer has
// no account yet; the certificate is the only credential). Without this
// override a malformed-params call against them would fail on
// ErrClientCertRequired, which is a real and already-tested gate
// (TestMCPInitCeremony_ShareClaimThumbprintNotFromWire, init_public_test.go)
// but not the one this test exists to prove.
//
// password.unlock rejects a cross-tenant (system-scoped) caller before
// decoding (auth.IsCrossTenant, handlers_password.go), so it needs a
// tenant-scoped identity to reach decodeParams at all.
var methodContext = map[string]func(t *testing.T) context.Context{
	"init.claimShareBegin":    mcpCtxWithPeerCert,
	"init.claimShareComplete": mcpCtxWithPeerCert,
	"password.unlock": func(t *testing.T) context.Context {
		return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user1", TenantID: "tenant-a"})
	},
}

// newMalformedParamsTestServer builds a *Server with every optional
// sub-system wired (password store, barrier, SSH), so a handler under test
// reaches its own decodeParams call instead of short-circuiting on a "not
// configured" guard that would otherwise mask what this test checks.
func newMalformedParamsTestServer(t *testing.T) *Server {
	t.Helper()

	server := createTestServer(t)

	_, _, manager := passwordTestRegistry(t)
	server.xkmsService.SetPasswordStoreManager(manager)

	barrier, _, _ := createTestBarrier(t)
	server.xkmsService.SetBarrier(barrier)

	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	sshClient, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: backend})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sshClient.Close() })
	server.sshClient = sshClient

	return server
}

// TestEveryHandler_MalformedParamsAreInvalidParams drives every entry of
// rpcMethodHandlers -- the package's full JSON-RPC method surface, the same
// table InvokeMethod dispatches through and ModuleMethods() advertises as
// MCP tools -- with unparsable JSON params, and asserts each one rejects it
// as a *KeyOpError carrying ErrCodeInvalidParams (-32602), the code
// InvokeMethod/mcpToolHandler renders as wire.CodeInvalidArgument (go-
// xkms#774, #814). A handler that returns a different error, or an
// unclassified one that would reach the caller as wire.CodeInternal
// instead, fails this test by name.
func TestEveryHandler_MalformedParamsAreInvalidParams(t *testing.T) {
	server := newMalformedParamsTestServer(t)
	defer cleanupXKMS()

	// Truncated JSON: always a decode failure regardless of the destination
	// struct's shape, so this one payload exercises every handler's params
	// type uniformly.
	malformed := json.RawMessage(`{"not": "valid json"`)

	methods := make([]string, 0, len(rpcMethodHandlers))
	for method := range rpcMethodHandlers {
		methods = append(methods, method)
	}
	sort.Strings(methods)

	for _, method := range methods {
		method := method
		handler := rpcMethodHandlers[method]

		t.Run(method, func(t *testing.T) {
			if reason, skip := paramsOptionalMethods[method]; skip {
				t.Skip("no parameters to malform: " + reason)
			}

			ctx := context.Background()
			if withCtx, ok := methodContext[method]; ok {
				ctx = withCtx(t)
			}

			req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: malformed, ID: 1}
			_, err := handler(server, ctx, req)
			require.Errorf(t, err, "%s: malformed params must be rejected", method)

			var keyErr *KeyOpError
			require.ErrorAsf(t, err, &keyErr,
				"%s: error must be a *KeyOpError so InvokeMethod/mcpToolHandler can classify it (got %T: %v)",
				method, err, err)
			assert.Equalf(t, ErrCodeInvalidParams, keyErr.Code,
				"%s: malformed params must report Invalid params (-32602), got code %d (%v)",
				method, keyErr.Code, err)
		})
	}
}
