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
)

// assertKeyOpCode requires that err is a *KeyOpError carrying want, so a
// handler test pins the exact wire-level code its caller sees (not merely
// that some error occurred). It is the shared assertion the per-family
// wire-code tests (go-xkms#930) use across handlers_share_test.go,
// handlers_audit_test.go, handlers_algorithms_test.go and utils_test.go.
func assertKeyOpCode(t *testing.T, err error, want int) {
	t.Helper()

	var keyErr *KeyOpError
	require.ErrorAsf(t, err, &keyErr, "error must be a *KeyOpError (got %T: %v)", err, err)
	assert.Equal(t, want, keyErr.Code)
}

// TestEveryRegisteredHandler_ReturnsKeyOpErrorOrNil is the guard go-xkms#930
// asks for: it fails if any registered MCP handler can return an error that
// is not a *KeyOpError, since pkg/apimodule/module_mcp.go's mcpToolHandler
// (and every other InvokeMethod caller) can only recover a wire-level code
// from that type -- anything else reaches the caller as an
// indistinguishable "xkms: internal error".
//
// Mechanism: a runtime sweep over rpcMethodHandlers -- the same table
// InvokeMethod dispatches through and ModuleMethods() advertises as MCP
// tools, and the same table TestEveryHandler_MalformedParamsAreInvalidParams
// already sweeps for the decode-failure gate -- driving each handler with a
// valid, empty JSON object ({}). That payload decodes successfully (unlike
// the malformed-params sweep's truncated JSON), so it reaches each
// handler's OWN request validation and, for a handler with no required
// fields, the service-layer call beneath it. The test server is built with
// every optional subsystem it is safe to leave wired (password store,
// barrier, SSH) so a handler that depends on one of those does not panic on
// a nil dereference the fixture would otherwise mask; everything else
// (shares, audit, custodian groups, CA, WebAuthn, PIV, FROST backends,
// tenant service) is deliberately left nil, so a handler that reaches its
// own subsystem's "not configured" guard exercises the exact path this
// issue's bug class lived in.
//
// This mechanism was chosen over a go/ast static check for two reasons.
// First, it proves exactly what module_mcp.go itself observes: it calls
// the same handler function through the same errors.As(&KeyOpError{}) the
// dispatcher uses, so it can never diverge from real dispatch behaviour the
// way a lexical pattern match over source text could (a static check has to
// re-derive, by inspecting call graphs across interface boundaries, that
// every "safe" mapper function -- mapKeyOpError, mapShareError,
// certOperationError, and so on -- itself only ever returns nil or
// *KeyOpError; a runtime call proves it directly). Second, it is exactly
// the architecture this package already committed to for the sibling gate
// (TestEveryHandler_MalformedParamsAreInvalidParams, go-xkms#774): a table
// a reviewer watches shrink or grow, not a parallel analysis tool with its
// own blind spots.
//
// This complements, and does not replace, the malformed-params sweep: that
// one proves decodeParams's own failure is always classified; this one
// proves every handler's OWN validation and unconfigured-subsystem guards
// are too. Together they cover every return statement a handler can reach
// with syntactically valid JSON-RPC params.
func TestEveryRegisteredHandler_ReturnsKeyOpErrorOrNil(t *testing.T) {
	server := newMalformedParamsTestServer(t)
	defer cleanupXKMS()

	// A valid, empty JSON object: decodeParams accepts it for every params
	// struct in this package (every field is left at its zero value), so
	// this one payload drives every handler past decoding and into its own
	// validation and service-layer calls uniformly.
	empty := json.RawMessage(`{}`)

	methods := make([]string, 0, len(rpcMethodHandlers))
	for method := range rpcMethodHandlers {
		methods = append(methods, method)
	}
	sort.Strings(methods)

	for _, method := range methods {
		method := method
		handler := rpcMethodHandlers[method]

		t.Run(method, func(t *testing.T) {
			ctx := context.Background()
			if withCtx, ok := methodContext[method]; ok {
				ctx = withCtx(t)
			}

			req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: empty, ID: 1}
			_, err := handler(server, ctx, req)
			if err == nil {
				// A handler with no required fields against a configured
				// subsystem (xkms.algorithms, xkms.listBackends, ...)
				// legitimately succeeds against {}; nothing to classify.
				return
			}

			var keyErr *KeyOpError
			require.ErrorAsf(t, err, &keyErr,
				"%s: every handler failure must be a *KeyOpError so InvokeMethod/mcpToolHandler can classify it (got %T: %v)",
				method, err, err)
		})
	}
}

// frostMethods is the exact method set routeFrostMethods dispatches, in both
// its frost-tagged form (handlers_frost.go) and its !frost stub
// (handlers_frost_stub.go). These never appear in rpcMethodHandlers --
// InvokeMethod (module_support.go) tries routeFrostMethods before the map
// lookup -- so TestEveryRegisteredHandler_ReturnsKeyOpErrorOrNil's sweep
// over that map does not reach them; TestEveryFrostMethod_ReturnsKeyOpErrorOrNil
// below is their equivalent.
var frostMethods = []string{
	"frost.generateKey",
	"frost.importKey",
	"frost.listKeys",
	"frost.getKey",
	"frost.deleteKey",
	"frost.generateNonces",
	"frost.signRound",
	"frost.aggregate",
	"frost.verify",
}

// TestEveryFrostMethod_ReturnsKeyOpErrorOrNil is
// TestEveryRegisteredHandler_ReturnsKeyOpErrorOrNil's counterpart for the
// frost.* namespace, which routeFrostMethods dispatches before
// rpcMethodHandlers is ever consulted, so the sweep above cannot reach it.
// It runs unmodified under both the frost tag (against the real handlers in
// handlers_frost.go) and without it (against the stub in
// handlers_frost_stub.go), and is the test that pins go-xkms#930's fix to
// handlers_frost.go itself: every FROST hex-decode failure, threshold
// validation and backend-lookup refusal must be a *KeyOpError too.
func TestEveryFrostMethod_ReturnsKeyOpErrorOrNil(t *testing.T) {
	server := newMalformedParamsTestServer(t)
	defer cleanupXKMS()

	empty := json.RawMessage(`{}`)

	for _, method := range frostMethods {
		method := method
		t.Run(method, func(t *testing.T) {
			req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: empty, ID: 1}
			_, err, handled := server.routeFrostMethods(context.Background(), req)
			require.True(t, handled, "%s: routeFrostMethods must recognize its own dispatch table", method)
			if err == nil {
				return
			}

			var keyErr *KeyOpError
			require.ErrorAsf(t, err, &keyErr,
				"%s: every FROST handler failure must be a *KeyOpError (got %T: %v)",
				method, err, err)
		})
	}
}
