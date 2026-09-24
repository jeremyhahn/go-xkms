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

package apimodule

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// startSSHRoundTripMCPServer wires a real xkms MCP surface (pkg/api/mcp),
// with a real embedded SSH sub-system (sdk/go/client/ssh's in-process
// Client, backed by an in-memory storage.Backend), onto a real mcp-go
// Streamable HTTP server through the same module registration path
// production uses (Module.RegisterMCP). It returns the "host:port" the
// SDK's MCP SSH client can dial — go-xkms#792: proving the raw mcp://
// client this package retired in favor of the unified server actually
// reaches that server's ssh.keys.*/ssh.knownHosts.*/ssh.authorizedKeys.*
// tools, with every SSH sub-system error passing through mapSSHError
// (pkg/api/mcp/errors_ssh.go) onto a real go-qrdb wire.ErrorEnvelope, not
// just a fake harness that re-implements the wire protocol (see
// sdk/go/client/ssh/mcp_test.go and mcp_dial_test.go for that layer's own
// coverage).
func startSSHRoundTripMCPServer(t *testing.T) string {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: backend, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	sshBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	embeddedSSH, err := sdkssh.NewEmbedded(sdkssh.EmbeddedOptions{Backend: sshBackend})
	require.NoError(t, err)
	t.Cleanup(func() { _ = embeddedSSH.Close() })

	mcpSrv, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		SSHClient:     embeddedSSH,
	})
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithMCPServer(func() *xkmsmcp.Server { return mcpSrv }))
	require.NoError(t, err)

	srv := mcpserver.NewMCPServer("xkms-ssh-roundtrip-test", "0.0.0")
	m.RegisterMCP(srv)

	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath("/mcp"))
	testServer := httptest.NewServer(httpServer)
	t.Cleanup(testServer.Close)

	return strings.TrimPrefix(testServer.URL, "http://")
}

// TestSSHRoundTrip_RealServer drives the production sdk/go/client/ssh MCP
// client (mcp.go) against the real server wiring above: real tool
// registration, real pkg/api/mcp dispatch (tenant/authz gates included),
// and a real embedded SSH backend performing genuine Ed25519 key
// generation, export, and listing. This is the end-to-end proof go-xkms#792
// asks for: the raw mcp:// client was retired without a server counterpart
// until it was repointed at this, the unified server's real tool-call
// surface.
func TestSSHRoundTrip_RealServer(t *testing.T) {
	addr := startSSHRoundTripMCPServer(t)

	client, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()

	key, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "laptop", Algorithm: "ed25519",
	})
	require.NoError(t, err)
	assert.Equal(t, "laptop", key.Name)
	assert.NotEmpty(t, key.Fingerprint)

	pub, err := client.Keys().ExportPublic(ctx, sdkssh.ExportRequest{
		Scope: "user", Owner: "alice", Name: "laptop",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, pub.Line)

	keys, err := client.Keys().List(ctx, sdkssh.ListKeysRequest{Scope: "user", Owner: "alice"})
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

// TestSSHRoundTrip_NotFound proves a genuine server-side not-found
// condition (pkg/ssh/keys.KeyNotFoundError, from the real embedded key
// store) survives the full round trip -- real handler, real mapSSHError
// classification, real go-qrdb wire.ErrorEnvelope, real
// sdk/go/client/ssh MCP client decode -- reaching the caller as
// *sdkssh.InvalidRequestError with the server's message intact. It is
// *InvalidRequestError and not a dedicated *sdkssh.NotFoundError because
// mapSSHError's eight-code JSON-RPC vocabulary has no NotFound member (see
// that function's doc comment); the message is what still distinguishes
// the condition.
func TestSSHRoundTrip_NotFound(t *testing.T) {
	addr := startSSHRoundTripMCPServer(t)

	client, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Keys().Get(context.Background(), sdkssh.GetKeyRequest{
		Scope: "user", Owner: "alice", Name: "ghost",
	})
	require.Error(t, err)

	var invalidErr *sdkssh.InvalidRequestError
	require.ErrorAsf(t, err, &invalidErr, "expected *InvalidRequestError, got %T: %v", err, err)
	assert.Contains(t, invalidErr.Message, "not found")
}

// TestSSHRoundTrip_Mismatch proves a genuine server-side host-key mismatch
// (pkg/ssh/known_hosts.MismatchError, from the real embedded known_hosts
// store comparing an unrelated presented key against a pinned one) survives
// the same round trip as TestSSHRoundTrip_NotFound, landing on the
// identical *sdkssh.InvalidRequestError classification -- proving
// go-xkms#792's documented limitation (no wire.Code distinguishes Duplicate
// from Mismatch from NotFound today) rather than merely asserting it.
func TestSSHRoundTrip_Mismatch(t *testing.T) {
	addr := startSSHRoundTripMCPServer(t)

	client, err := sdkssh.NewMCP(sdkssh.MCPOptions{Addr: addr})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()

	// Pin a host key, then present an unrelated key for the same host.
	pinned, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "host-key", Algorithm: "ed25519",
	})
	require.NoError(t, err)
	pinnedPub, err := client.Keys().ExportPublic(ctx, sdkssh.ExportRequest{
		Scope: "user", Owner: "alice", Name: pinned.Name,
	})
	require.NoError(t, err)

	require.NoError(t, client.KnownHosts().Add(ctx, sdkssh.AddKnownHostRequest{
		Scope: "user", Owner: "alice", Host: "git.example.com",
		PublicKey: pinnedPub.Line,
	}))

	decoy, err := client.Keys().Generate(ctx, sdkssh.GenerateRequest{
		Scope: "user", Owner: "alice", Name: "decoy-key", Algorithm: "ed25519",
	})
	require.NoError(t, err)
	decoyPub, err := client.Keys().ExportPublic(ctx, sdkssh.ExportRequest{
		Scope: "user", Owner: "alice", Name: decoy.Name,
	})
	require.NoError(t, err)

	sshPub, _, _, _, parseErr := gossh.ParseAuthorizedKey([]byte(decoyPub.Line))
	require.NoError(t, parseErr)

	err = client.KnownHosts().Verify(ctx, "user", "alice", "git.example.com", sshPub)
	require.Error(t, err)

	var invalidErr *sdkssh.InvalidRequestError
	require.ErrorAsf(t, err, &invalidErr, "expected *InvalidRequestError, got %T: %v", err, err)
	assert.Contains(t, invalidErr.Message, "mismatch")
}
