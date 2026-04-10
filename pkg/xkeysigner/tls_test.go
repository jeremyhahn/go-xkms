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

package xkeysigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCA creates a self-signed CA certificate for testing.
func generateTestCA(t *testing.T) []byte {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func TestTLSCertificate_Success(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	tlsCert, err := TLSCertificate(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	require.NoError(t, err)
	require.NotNil(t, tlsCert)

	assert.Len(t, tlsCert.Certificate, 1)
	assert.NotNil(t, tlsCert.PrivateKey)
	assert.NotNil(t, tlsCert.Leaf)
	assert.Equal(t, "test-signer", tlsCert.Leaf.Subject.CommonName)

	// Verify the private key is a Signer.
	_, ok := tlsCert.PrivateKey.(*Signer)
	assert.True(t, ok)
}

func TestTLSCertificate_NilConfig(t *testing.T) {
	tlsCert, err := TLSCertificate(nil)
	assert.Nil(t, tlsCert)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestTLSCertificate_NoCertAvailable(t *testing.T) {
	handler := func(raw json.RawMessage) []byte {
		return errorResponse("no certificate in slot")
	}
	sockPath := startMockIPCServer(t, handler)

	tlsCert, err := TLSCertificate(&SignerConfig{
		SocketPath: sockPath,
		Slot:       "9a",
	})
	assert.Nil(t, tlsCert)
	assert.Error(t, err)
}

func TestTLSCertificate_InvalidSlot(t *testing.T) {
	tlsCert, err := TLSCertificate(&SignerConfig{
		SocketPath: "/tmp/nonexistent.sock",
		Slot:       "zz",
	})
	assert.Nil(t, tlsCert)
	assert.True(t, errors.Is(err, ErrInvalidSlot))
}

func TestTLSClientConfig_Success(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: &SignerConfig{
			SocketPath: sockPath,
			Slot:       "9a",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Len(t, tlsConfig.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
}

func TestTLSClientConfig_WithCACert(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))
	caPEM := generateTestCA(t)

	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: &SignerConfig{
			SocketPath: sockPath,
			Slot:       "9a",
		},
		CACertPEM: caPEM,
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestTLSClientConfig_WithServerName(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: &SignerConfig{
			SocketPath: sockPath,
			Slot:       "9a",
		},
		ServerName: "example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, "example.com", tlsConfig.ServerName)
}

func TestTLSClientConfig_NilConfig(t *testing.T) {
	tlsConfig, err := TLSClientConfig(nil)
	assert.Nil(t, tlsConfig)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestTLSClientConfig_NilSignerConfig(t *testing.T) {
	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: nil,
	})
	assert.Nil(t, tlsConfig)
	assert.True(t, errors.Is(err, ErrNilConfig))
}

func TestTLSClientConfig_InvalidCACert(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: &SignerConfig{
			SocketPath: sockPath,
			Slot:       "9a",
		},
		CACertPEM: []byte("not-valid-pem"),
	})
	assert.Nil(t, tlsConfig)
	assert.True(t, errors.Is(err, ErrInvalidCertFormat))
}

func TestTLSClientConfig_EmptyCACert(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	sockPath := startMockIPCServer(t, certHandler(certPEM))

	// Empty CA cert should be fine (no custom CA).
	tlsConfig, err := TLSClientConfig(&TLSConfig{
		SignerConfig: &SignerConfig{
			SocketPath: sockPath,
			Slot:       "9a",
		},
		CACertPEM: nil,
	})
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Nil(t, tlsConfig.RootCAs)
}
