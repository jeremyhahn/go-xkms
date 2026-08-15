// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnect_MutualTLS exercises the full Connect() path against a real,
// in-process MCP Streamable HTTP server over TLS with client certificate
// verification, matching the unified qrdb MCP server's contract: TLS-only,
// authenticated by mTLS peer certificate. It mirrors the certificate setup
// pattern used by the REST transport's TestConnect_TLSWithClientCert
// (pkg/api/transport/rest/transport_boost_test.go), which this test does
// not modify.
func TestConnect_MutualTLS(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	// Server certificate signed by the CA.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	srvCertParsed, err := x509.ParseCertificate(srvDER)
	require.NoError(t, err)

	// Client certificate signed by the same CA — this is what authenticates
	// the caller to the unified qrdb MCP server.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	tmpDir := t.TempDir()

	caFile := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	clientCertFile := filepath.Join(tmpDir, "client.pem")
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	require.NoError(t, os.WriteFile(clientCertFile, clientCertPEM, 0o600))

	clientKeyFile := filepath.Join(tmpDir, "client-key.pem")
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	require.NoError(t, os.WriteFile(clientKeyFile, clientKeyPEM, 0o600))

	// Real MCP server, exposing the "xkms_health" tool Connect() relies on.
	srv := mcpserver.NewMCPServer("xkms-mtls-test", "1.0.0")
	srv.AddTool(mcp.Tool{Name: "xkms_health"}, func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(`{"status":"ok","version":"1.0.0"}`), nil
	})
	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(mcpEndpointPath))

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	ts := httptest.NewUnstartedServer(httpServer)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{srvDER},
				PrivateKey:  srvKey,
				Leaf:        srvCertParsed,
			},
		},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = ts.URL
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	cfg.TLSCertFile = clientCertFile
	cfg.TLSKeyFile = clientKeyFile

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.NoError(t, err)
	assert.True(t, tr.IsConnected())
	require.NoError(t, tr.Close())
}

// TestConnect_MutualTLS_NoClientCert exercises the failure path: a server
// that requires a client certificate rejects a Connect() that omits one,
// and the transport reports ErrConnectionFailed rather than leaving
// IsConnected true.
func TestConnect_MutualTLS_NoClientCert(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	srvCertParsed, err := x509.ParseCertificate(srvDER)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))

	srv := mcpserver.NewMCPServer("xkms-mtls-test", "1.0.0")
	srv.AddTool(mcp.Tool{Name: "xkms_health"}, func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(`{"status":"ok"}`), nil
	})
	httpServer := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(mcpEndpointPath))

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	ts := httptest.NewUnstartedServer(httpServer)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{srvDER},
				PrivateKey:  srvKey,
				Leaf:        srvCertParsed,
			},
		},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = ts.URL
	cfg.TLSEnabled = true
	cfg.TLSCAFile = caFile
	// Deliberately omit TLSCertFile/TLSKeyFile.

	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConnectionFailed))
	assert.False(t, tr.IsConnected())
}
