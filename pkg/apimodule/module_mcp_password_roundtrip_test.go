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
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	mcpclient "github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/kdftest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newRoundTripPasswordManager builds a real TenantPasswordStoreManager
// over in-memory tenant stores, mirroring pkg/api/mcp's own
// passwordTestStores test helper. It exists here too because the two
// packages must not import each other's _test.go files.
func newRoundTripPasswordManager(t *testing.T) *staticpw.TenantPasswordStoreManager {
	t.Helper()
	store, err := staticpw.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	mgr, err := staticpw.NewTenantPasswordStoreManager(testutil.NewTenantStores(), store, staticpw.WithPasskeyRelyingParty("kms.example.com"), staticpw.WithPassphraseKDFParams(kdftest.CheapPassphraseParams))
	require.NoError(t, err)
	return mgr
}

// startRoundTripMCPServer wires the real xkms MCP surface (pkg/api/mcp) onto
// a real mcp-go Streamable HTTP server through the same module registration
// path production uses (Module.RegisterMCP), and returns the "host:port" a
// client.mcp Transport can dial. It is the harness for proving the client's
// method names are what the server actually registers as tools -- the
// regression go-xkms#762 exists to guard.
func startRoundTripMCPServer(t *testing.T) string {
	t.Helper()

	backend := newMCPBackend(t)

	mgr := newRoundTripPasswordManager(t)

	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetPasswordStoreManager(mgr)

	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)

	srv := mcpserver.NewMCPServer("xkms-roundtrip-test", "0.0.0")
	m.RegisterMCP(srv)

	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath("/mcp"))
	testServer := httptest.NewServer(httpServer)
	t.Cleanup(testServer.Close)

	return strings.TrimPrefix(testServer.URL, "http://")
}

// connectRoundTripClient connects the real client transport (the one
// production SDKs use) to addr over plain HTTP.
func connectRoundTripClient(t *testing.T, addr string) *mcpclient.Transport {
	t.Helper()
	tr, err := mcpclient.New(transport.WithAddress(addr))
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// requireRouted fails the test if err is a *mcpclient.ReceiveError, the
// client transport's signal that the MCP tool call itself failed (e.g. an
// unknown tool name) rather than that the invoked handler reported a
// business error. A renamed-but-mismatched method surfaces here; a
// correctly named one may still return a domain error (store not
// configured, and so on), which this helper accepts.
func requireRouted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var recvErr *mcpclient.ReceiveError
	require.Falsef(t, errors.As(err, &recvErr), "tool call failed to route: %v", err)
}

// TestPasswordFamilyRoundTrip_RealServer proves the client's renamed
// "password.*" methods (go-xkms#762) are exactly the tool names the real
// server registers, by driving the production client transport against a
// real mcp-go server built from the real Module.RegisterMCP wiring. Before
// the rename the client sent "xkms.password*", which the server never
// registered as a tool, so every one of these calls failed to route.
func TestPasswordFamilyRoundTrip_RealServer(t *testing.T) {
	addr := startRoundTripMCPServer(t)
	tr := connectRoundTripClient(t, addr)
	ctx := context.Background()

	t.Run("PasswordAdd", func(t *testing.T) {
		_, err := tr.PasswordAdd(ctx, &transport.PasswordAddRequest{Name: "svc", Password: "s3cret!"})
		requireRouted(t, err)
	})

	t.Run("PasswordList", func(t *testing.T) {
		_, err := tr.PasswordList(ctx, &transport.PasswordListRequest{})
		requireRouted(t, err)
	})

	t.Run("PasswordGet", func(t *testing.T) {
		_, err := tr.PasswordGet(ctx, &transport.PasswordGetRequest{ID: "does-not-exist"})
		requireRouted(t, err)
	})

	t.Run("PasswordUpdate", func(t *testing.T) {
		err := tr.PasswordUpdate(ctx, &transport.PasswordUpdateRequest{ID: "does-not-exist"})
		requireRouted(t, err)
	})

	t.Run("PasswordDelete", func(t *testing.T) {
		err := tr.PasswordDelete(ctx, &transport.PasswordDeleteRequest{ID: "does-not-exist"})
		requireRouted(t, err)
	})

	t.Run("PasswordStoreUnlock", func(t *testing.T) {
		err := tr.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{})
		requireRouted(t, err)
	})

	t.Run("PasswordStoreLock", func(t *testing.T) {
		err := tr.PasswordStoreLock(ctx)
		requireRouted(t, err)
	})

	t.Run("PasswordStoreStatus", func(t *testing.T) {
		_, err := tr.PasswordStoreStatus(ctx)
		requireRouted(t, err)
	})

	t.Run("PasswordStoreSetAccessMode", func(t *testing.T) {
		err := tr.PasswordStoreSetAccessMode(ctx, &transport.PasswordStoreSetAccessModeRequest{Mode: "session_based"})
		requireRouted(t, err)
	})

	t.Run("PasswordGenerate", func(t *testing.T) {
		_, err := tr.PasswordGenerate(ctx, &transport.PasswordGenerateRequest{Length: 16})
		requireRouted(t, err)
	})
}
