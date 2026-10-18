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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	apitransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	mcptransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	quictransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// loopbackPortReservation holds open listeners on ephemeral loopback ports, so
// that nothing else on the host can take them between the moment the test
// learns the port numbers and the moment the server binds them. Release closes
// them immediately before that bind.
//
// It replaces a helper that closed each listener as soon as it had read the
// port number, whose comment described the result as "the small reuse race is
// acceptable in-process". Measured, it is not. With a 2 ms gap between
// allocation and bind, 24 concurrent allocators produced 5 collisions in 4800
// attempts on an idle host, each failing with the "address already in use"
// that turned the Race Detector job red on #339 — and on a loaded CI runner
// the gap is not 2 ms but the whole of TLS material generation and qrdb node
// composition.
//
// Handing the server a net.Listener would close the window rather than shrink
// it, and is the better fix where it is available. It is not available here:
// only the legacy REST path has such a seam (Server.SetRESTListener), while
// the gRPC, QUIC and MCP ports reach the embedded qrdb node as port numbers in
// its configuration (see qrdb_node.go), so there is nothing to hand a listener
// to. MCP is the port that actually collided.
//
// Holding the reservation until the last possible statement is therefore the
// strongest fix available from the test side. The window is not zero, but it
// is now a few statements rather than the whole of test setup. Deliberately
// not a retry loop around the bind: that would hide the window instead of
// shrinking it, and leave the same trap for the next test to use.
type loopbackPortReservation struct {
	listeners []net.Listener
	ports     []int
}

// reserveLoopbackPorts binds n ephemeral loopback ports and keeps them held.
// The reservation is released on cleanup if the test never calls Release, so a
// failure path cannot leak listeners into the rest of the package's run.
func reserveLoopbackPorts(t *testing.T, n int) *loopbackPortReservation {
	t.Helper()

	r := &loopbackPortReservation{
		listeners: make([]net.Listener, 0, n),
		ports:     make([]int, 0, n),
	}
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		r.listeners = append(r.listeners, l)
		r.ports = append(r.ports, l.Addr().(*net.TCPAddr).Port)
	}
	t.Cleanup(r.release)
	return r
}

// port returns the i-th reserved port. The port stays held until Release.
func (r *loopbackPortReservation) port(i int) int { return r.ports[i] }

// Release drops every reservation. Call it immediately before the code that
// binds the ports, and nothing in between.
func (r *loopbackPortReservation) Release(t *testing.T) {
	t.Helper()
	r.release()
}

func (r *loopbackPortReservation) release() {
	for _, l := range r.listeners {
		_ = l.Close()
	}
	r.listeners = nil
}

// TestUnifiedAPIServer_E2E_RESTThroughEmbeddedNode is the end-to-end proof
// of the Phase 4 cutover switch: with server.unified_api enabled, the
// embedded qrdb node's own multi-protocol server takes xkmsd's REST port
// during composition and serves the xkms capability plane through the
// registered ServiceModule — real HTTP traffic, real port, no legacy REST
// listener (Server.Start is never called here, so ONLY the node can be
// answering).
func TestUnifiedAPIServer_E2E_RESTThroughEmbeddedNode(t *testing.T) {
	tempDir := t.TempDir()

	// Held, not merely sampled: the ports stay bound by this test until the
	// Release immediately before New composes the server. Generating the TLS
	// material below is the expensive step that used to sit inside the window.
	ports := reserveLoopbackPorts(t, 4)
	restPort := ports.port(0)

	// qrdb's transports are TLS-only; the cutover requires explicit TLS
	// material (see config.Validate). The test CA-signed server cert
	// carries the "localhost" SAN.
	certFile, keyFile, caFile := createTestTLSFiles(t)

	// The Unix socket lives in a private runtime directory, as a daemon's
	// would.
	socketDir := t.TempDir()
	require.NoError(t, os.Chmod(socketDir, 0o700))
	socketPath := filepath.Join(socketDir, "xkms.sock")

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: restPort,
			GRPCPort: ports.port(1),
			QUICPort: ports.port(2),
			MCPPort:  ports.port(3),
		},
		Protocols: config.ProtocolsConfig{
			Unix: true,
			REST: true,
			GRPC: true,
			MCP:  true,
		},
		Unix:    config.UnixConfig{SocketPath: socketPath},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
		Auth:      testJWTAuthConfig(t),
		Datastore: config.DatastoreConfig{Path: tempDir},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(tempDir, "software"),
			},
		},
		// First boot issues the administrator's certificate from this CA and
		// binds it. An administrator created without one leaves the node
		// serving only the ceremony endpoints until a certificate binds.
		CA: &ca.MultiIdentityCAConfig{
			DefaultValidityDays: 365,
			Identity: []ca.Identity{
				{
					IsRoot:  true,
					Valid:   1,
					Subject: ca.Subject{CommonName: "Unified API E2E Root CA", Organization: "Test Org", Country: "US"},
					Keys: []*types.KeyConfig{
						{KeyAlgorithm: types.AlgorithmECDSA, ECCConfig: &types.ECCConfig{Curve: types.CurveP256}},
					},
				},
			},
		},
	}

	// Hand the ports over. Nothing may run between here and New: every
	// statement in between is window in which another process can take one.
	// The admin plane as xkmsd mounts it: each route under its own
	// permission over a resolved router that answers once the node has
	// authenticated and authorized a caller.
	adminModule, err := apimodule.NewAdminModule(func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}, []apimodule.AdminRoute{
		{Method: http.MethodGet, Path: "/admin/accounts", Permission: "acme_accounts:list"},
		{Method: http.MethodGet, Path: "/api/v1/tenants", Permission: qrdbsdk.PermissionTenantsListCross, SelfPermission: "tenants:list"},
	})
	require.NoError(t, err)

	ports.Release(t)

	server, err := New(cfg, WithExtraModules(adminModule))
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Shutdown() })

	// Trust exactly the test CA; the cert's SAN is "localhost".
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	base := fmt.Sprintf("https://localhost:%d", restPort)
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	// The node binds during construction; poll briefly for readiness.
	var resp *http.Response
	require.Eventually(t, func() bool {
		var derr error
		resp, derr = client.Get(base + "/health")
		return derr == nil
	}, 10*time.Second, 100*time.Millisecond, "unified server never became reachable on the REST port")
	_ = resp.Body.Close()

	// The xkms-only public discovery route must be served by the module —
	// qrdb has no /api/v1/algorithms of its own, so a 200 with algorithm
	// content proves module route registration end to end.
	resp, err = client.Get(base + "/api/v1/algorithms")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, strings.ToLower(string(body)), "algorithm",
		"module-served algorithms discovery must answer with algorithm content; got: %.200s", string(body))

	// The capability discovery route is public as well and xkms-specific.
	resp, err = client.Get(base + "/api/v1/capabilities")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// A session JWT as xkmsd's login plane mints it: signed by the key the
	// configured authenticator verifies against.
	session := mintTestSessionJWT(t)

	// Admin plane: the node's chain refuses an anonymous caller before the
	// admin router runs, over HTTP/1.1-2 and over HTTP/3 alike; the session
	// JWT is let through to it. gRPC and MCP carry no admin routes and refuse
	// anonymous callers outright (below).
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	t.Cleanup(func() { _ = h3.Close() })
	adminClients := map[string]*http.Client{
		"REST":   client,
		"HTTP/3": {Timeout: 2 * time.Second, Transport: h3},
	}
	for name, c := range adminClients {
		for _, path := range []string{"/admin/accounts", "/api/v1/tenants"} {
			assert.Equal(t, http.StatusUnauthorized, adminStatus(t, c, base+path, ""),
				"%s %s: an anonymous admin-plane call must be refused", name, path)
			assert.Equal(t, http.StatusOK, adminStatus(t, c, base+path, session),
				"%s %s: a session JWT must reach the admin router", name, path)
		}
	}

	// gRPC surface: the module's KeystoreService is registered on the node's
	// gRPC transport. An anonymous call is refused by the node's
	// authentication chain (Unauthenticated, not Unimplemented: the service
	// resolves), and the same call carrying the session JWT as bearer
	// metadata is authenticated by the chain and served by the module.
	grpcConn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", cfg.Server.GRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = grpcConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keystore := pb.NewKeystoreServiceClient(grpcConn)
	_, err = keystore.ListBackends(ctx, &pb.ListBackendsRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "an anonymous gRPC call must be refused: %v", err)

	authed := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+session)
	backends, err := keystore.ListBackends(authed, &pb.ListBackendsRequest{})
	require.NoError(t, err, "a session JWT must reach the module RPC over gRPC")
	assert.NotEmpty(t, backends.GetBackends())

	// Unix surface: the node's TLS unix listener carries the same chain.
	// gRPC dials a unix target with the authority "localhost", which the
	// server certificate names. An anonymous module RPC and an anonymous
	// qrdb control-plane RPC are both refused; the session JWT is served.
	unixConn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unixConn.Close() })

	unixKeystore := pb.NewKeystoreServiceClient(unixConn)
	_, err = unixKeystore.ListBackends(ctx, &pb.ListBackendsRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "an anonymous unix module call must be refused: %v", err)

	err = unixConn.Invoke(ctx, "/qrdb.v1.QRDBService/ListUsers", &emptypb.Empty{}, &emptypb.Empty{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "an anonymous unix control-plane call must be refused: %v", err)

	unixBackends, err := unixKeystore.ListBackends(authed, &pb.ListBackendsRequest{})
	require.NoError(t, err, "a session JWT must reach the module RPC over the unix socket")
	assert.NotEmpty(t, unixBackends.GetBackends())

	// QUIC surface: qrdb's REST server serves the identical handler over an
	// HTTP/3 listener on the same port, and xkms's QUIC wire IS HTTP/3 with
	// the shared /api/v1 dialect — so the real xkms QUIC transport client
	// must work against the unified port unchanged. Connect performs a
	// health check over HTTP/3; Algorithms exercises a module route.
	quicClient, err := quictransport.NewWithConfig(&apitransport.Config{
		Address:   fmt.Sprintf("localhost:%d", restPort),
		TLSCAFile: caFile,
	})
	require.NoError(t, err)
	require.NoError(t, quicClient.Connect(ctx),
		"xkms QUIC (HTTP/3) client must reach the unified server's HTTP/3 listener")
	t.Cleanup(func() { _ = quicClient.Close() })

	algs, err := quicClient.Algorithms(ctx)
	require.NoError(t, err, "module route over HTTP/3 must serve")
	assert.NotNil(t, algs)

	// MCP surface: the node's real MCP server (Streamable HTTP at /mcp)
	// carries the module's xkms_* tools. An anonymous client cannot open a
	// session; with the session JWT the rewritten MCP transport client
	// connects (health via the xkms_health tool) and drives a module tool.
	mcpConfig := &apitransport.Config{
		Address:    fmt.Sprintf("localhost:%d", cfg.Server.MCPPort),
		TLSEnabled: true,
		TLSCAFile:  caFile,
	}
	anonymous, err := mcptransport.NewWithConfig(mcpConfig)
	require.NoError(t, err)
	require.Error(t, anonymous.Connect(ctx), "an anonymous MCP session must be refused")

	mcpConfig.JWTToken = session
	mcpClient, err := mcptransport.NewWithConfig(mcpConfig)
	require.NoError(t, err)
	require.NoError(t, mcpClient.Connect(ctx),
		"a session JWT must open an MCP session against the unified MCP port")
	t.Cleanup(func() { _ = mcpClient.Close() })

	mcpAlgs, err := mcpClient.Algorithms(ctx)
	require.NoError(t, err, "module MCP tool must serve")
	assert.NotNil(t, mcpAlgs)
}

// adminStatus issues GET url through c, as bearer when token is set, and
// returns the response status.
func adminStatus(t *testing.T, c *http.Client, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode
}
