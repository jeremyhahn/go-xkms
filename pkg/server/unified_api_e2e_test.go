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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	apitransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	mcptransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	quictransport "github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/pkg/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// freeLoopbackPort reserves an ephemeral loopback TCP port and returns it.
// The listener is closed before returning; the small reuse race is
// acceptable in-process.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
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
	restPort := freeLoopbackPort(t)

	// qrdb's transports are TLS-only; the cutover requires explicit TLS
	// material (see config.Validate). The test CA-signed server cert
	// carries the "localhost" SAN.
	certFile, keyFile, caFile := createTestTLSFiles(t)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: restPort,
			GRPCPort: freeLoopbackPort(t),
			QUICPort: freeLoopbackPort(t),
			MCPPort:  freeLoopbackPort(t),
		},
		Protocols: config.ProtocolsConfig{
			REST: true,
			GRPC: true,
			MCP:  true,
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
		Auth: config.AuthConfig{Enabled: false},
		Storage: config.StorageConfig{
			Backend: "qrdb",
			Path:    tempDir,
			QRDB:    config.QRDBConfig{Transport: "embedded"},
		},
		Default: config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(tempDir, "software"),
			},
		},
	}

	server, err := New(cfg)
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

	// gRPC surface: the module's KeystoreService must be registered on the
	// node's gRPC transport. An unauthenticated call is expected to be
	// denied by qrdb's default-deny interceptor — the discriminator is that
	// the service RESOLVES: an "unknown service" error would mean the
	// module never registered.
	grpcConn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", cfg.Server.GRPCPort),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = grpcConn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = pb.NewKeystoreServiceClient(grpcConn).ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok, "expected a gRPC status error, got: %v", err)
		assert.NotEqual(t, codes.Unimplemented, st.Code(),
			"Unimplemented means the xkms KeystoreService was never registered on the unified server: %v", err)
	}

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
	// carries the module's xkms_* tools; the rewritten MCP transport client
	// connects (health via the xkms_health tool) and drives a discovery
	// method end to end.
	mcpClient, err := mcptransport.NewWithConfig(&apitransport.Config{
		Address:    fmt.Sprintf("localhost:%d", cfg.Server.MCPPort),
		TLSEnabled: true,
		TLSCAFile:  caFile,
	})
	require.NoError(t, err)
	require.NoError(t, mcpClient.Connect(ctx),
		"real-MCP client must initialize a session against the unified MCP port")
	t.Cleanup(func() { _ = mcpClient.Close() })

	mcpAlgs, err := mcpClient.Algorithms(ctx)
	require.NoError(t, err, "module MCP tool must serve")
	assert.NotNil(t, mcpAlgs)
}
