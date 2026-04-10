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

package xkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertPEM creates a self-signed ECDSA P-256 certificate PEM for testing.
func generateTestCertPEM(t *testing.T) string {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// ipcCertResponse is a simplified IPC response structure for testing.
type ipcCertResponse struct {
	Status string               `json:"status"`
	Error  string               `json:"error,omitempty"`
	PKCS11 *ipcCertPKCS11Result `json:"pkcs11,omitempty"`
}

type ipcCertPKCS11Result struct {
	PIVCert *ipcCertPIVResult `json:"piv_cert,omitempty"`
}

type ipcCertPIVResult struct {
	Certificate string `json:"certificate"`
	Slot        string `json:"slot"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"not_after"`
}

// startTestIPCServer starts a mock IPC server that serves a certificate.
func startTestIPCServer(t *testing.T, certPEM string) string {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return
				}
				resp := ipcCertResponse{
					Status: "ok",
					PKCS11: &ipcCertPKCS11Result{
						PIVCert: &ipcCertPIVResult{
							Certificate: certPEM,
							Slot:        "9a",
							Subject:     "CN=test-signer",
							Issuer:      "CN=test-signer",
							NotAfter:    "2030-01-01T00:00:00Z",
						},
					},
				}
				data, _ := json.Marshal(resp)
				_, _ = c.Write(data)
			}(conn)
		}
	}()

	// Wait for the server to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return sockPath
}

func TestWithXKeyAuth_Success(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	sockPath := startTestIPCServer(t, certPEM)

	opts := newDefaultClientOptions()
	opt := WithXKeyAuth(sockPath)
	err := opt(opts)
	require.NoError(t, err)

	assert.True(t, opts.tlsEnabled)
	assert.NotNil(t, opts.tlsConfig)
	assert.Len(t, opts.tlsConfig.Certificates, 1)
}

func TestWithXKeyAuth_EmptyPath(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	sockPath := startTestIPCServer(t, certPEM)

	// Set the env var so WithXKeyAuth picks it up when path is empty.
	t.Setenv(defaultXKeySocketEnvVar, sockPath)

	opts := newDefaultClientOptions()
	opt := WithXKeyAuth("")
	err := opt(opts)
	require.NoError(t, err)

	assert.True(t, opts.tlsEnabled)
	assert.NotNil(t, opts.tlsConfig)
}

func TestWithXKeyAuth_NoServer(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	opts := newDefaultClientOptions()
	opt := WithXKeyAuth(sockPath)
	err := opt(opts)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrXKeyAuthFailed))
}

func TestXKeyAuthResolver_ResolveTLSConfig(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	sockPath := startTestIPCServer(t, certPEM)

	resolver := &xkeyAuthResolver{socketPath: sockPath}
	tlsCfg, err := resolver.ResolveTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	assert.Len(t, tlsCfg.Certificates, 1)
}

func TestXKeyAuthResolver_ResolveTLSConfig_NoServer(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	resolver := &xkeyAuthResolver{socketPath: sockPath}
	tlsCfg, err := resolver.ResolveTLSConfig()
	assert.Nil(t, tlsCfg)
	assert.Error(t, err)
}

func TestXKeyAuthResolver_HasCertificate_True(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	sockPath := startTestIPCServer(t, certPEM)

	resolver := &xkeyAuthResolver{socketPath: sockPath}
	assert.True(t, resolver.HasCertificate())
}

func TestXKeyAuthResolver_HasCertificate_False(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	resolver := &xkeyAuthResolver{socketPath: sockPath}
	assert.False(t, resolver.HasCertificate())
}

func TestWithXKeyAuth_ToConfig(t *testing.T) {
	certPEM := generateTestCertPEM(t)
	sockPath := startTestIPCServer(t, certPEM)

	opts := newDefaultClientOptions()
	opt := WithXKeyAuth(sockPath)
	err := opt(opts)
	require.NoError(t, err)

	cfg := opts.toConfig()
	assert.True(t, cfg.TLSEnabled)
	assert.NotNil(t, cfg.TLSConfig)
	assert.Len(t, cfg.TLSConfig.Certificates, 1)
}
