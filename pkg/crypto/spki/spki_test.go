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

package spki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate for testing.
func generateTestCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// generateTestCertWithSAN creates a self-signed certificate with a SAN for localhost.
func generateTestCertWithSAN(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// encodeCertPEM encodes a certificate as PEM data.
func encodeCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// buildCertPool creates a certificate pool containing the given certificate.
func buildCertPool(t *testing.T, cert *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// startTLSServer starts a TLS server on a random port and returns the address.
// The server performs a full TLS handshake before closing each connection.
func startTLSServer(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) string {
	t.Helper()

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Use a plain TCP listener so we can control the TLS handshake explicitly
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := tcpListener.Addr().String()

	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			// Wrap in TLS and perform handshake before closing
			tlsConn := tls.Server(tcpConn, tlsConfig)
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = tcpListener.Close()
	})

	return addr
}

func TestComputePin(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin, err := ComputePin(cert)
	require.NoError(t, err)
	assert.NotEmpty(t, pin)

	// Verify pin length: SHA-256 produces 32 bytes = 64 hex chars
	assert.Len(t, pin, 64)

	// Verify pin matches manual computation
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, hex.EncodeToString(expected[:]), pin)
}

func TestComputePinNilCert(t *testing.T) {
	pin, err := ComputePin(nil)
	assert.ErrorIs(t, err, ErrNilCertificate)
	assert.Empty(t, pin)
}

func TestComputePinDeterministic(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin1, err := ComputePin(cert)
	require.NoError(t, err)

	pin2, err := ComputePin(cert)
	require.NoError(t, err)

	assert.Equal(t, pin1, pin2)
}

func TestComputePinUniqueness(t *testing.T) {
	cert1, _ := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	pin1, err := ComputePin(cert1)
	require.NoError(t, err)

	pin2, err := ComputePin(cert2)
	require.NoError(t, err)

	assert.NotEqual(t, pin1, pin2)
}

func TestComputePinBytes(t *testing.T) {
	cert, _ := generateTestCert(t)

	pinBytes, err := ComputePinBytes(cert)
	require.NoError(t, err)

	// Verify the raw bytes match a manual SHA-256 computation
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, expected, pinBytes)

	// Verify consistency with ComputePin hex encoding
	pinHex, err := ComputePin(cert)
	require.NoError(t, err)
	assert.Equal(t, pinHex, hex.EncodeToString(pinBytes[:]))
}

func TestComputePinBytesNilCert(t *testing.T) {
	pinBytes, err := ComputePinBytes(nil)
	assert.ErrorIs(t, err, ErrNilCertificate)
	assert.Equal(t, [32]byte{}, pinBytes)
}

func TestComputePinBytesDeterministic(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin1, err := ComputePinBytes(cert)
	require.NoError(t, err)

	pin2, err := ComputePinBytes(cert)
	require.NoError(t, err)

	assert.Equal(t, pin1, pin2)
}

func TestComputePinBytesUniqueness(t *testing.T) {
	cert1, _ := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	pin1, err := ComputePinBytes(cert1)
	require.NoError(t, err)

	pin2, err := ComputePinBytes(cert2)
	require.NoError(t, err)

	assert.NotEqual(t, pin1, pin2)
}

func TestVerifyPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin, err := ComputePin(cert)
	require.NoError(t, err)

	err = VerifyPin(cert, pin)
	assert.NoError(t, err)
}

func TestVerifyPinMismatch(t *testing.T) {
	cert, _ := generateTestCert(t)

	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"
	err := VerifyPin(cert, wrongPin)
	assert.ErrorIs(t, err, ErrInvalidPin)
}

func TestVerifyPinEmptyPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	err := VerifyPin(cert, "")
	assert.ErrorIs(t, err, ErrEmptyPin)
}

func TestVerifyPinNilCert(t *testing.T) {
	err := VerifyPin(nil, "somepin")
	assert.ErrorIs(t, err, ErrNilCertificate)
}

func TestVerifyConnection(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin, err := ComputePin(cert)
	require.NoError(t, err)

	verifyFunc := VerifyConnection(pin)
	require.NotNil(t, verifyFunc)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	err = verifyFunc(cs)
	assert.NoError(t, err)
}

func TestVerifyConnectionMismatch(t *testing.T) {
	cert, _ := generateTestCert(t)

	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"
	verifyFunc := VerifyConnection(wrongPin)
	require.NotNil(t, verifyFunc)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	err := verifyFunc(cs)
	assert.ErrorIs(t, err, ErrInvalidPin)
}

func TestVerifyConnectionNoPeerCerts(t *testing.T) {
	verifyFunc := VerifyConnection("somepin")
	require.NotNil(t, verifyFunc)

	cs := tls.ConnectionState{
		PeerCertificates: nil,
	}
	err := verifyFunc(cs)
	assert.ErrorIs(t, err, ErrNoPeerCertificates)
}

func TestVerifyConnectionEmptyPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	verifyFunc := VerifyConnection("")
	require.NotNil(t, verifyFunc)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	err := verifyFunc(cs)
	assert.ErrorIs(t, err, ErrEmptyPin)
}

func TestNewPinnedTLSConfig(t *testing.T) {
	pin := "abc123deadbeef"
	cfg := NewPinnedTLSConfig(pin)

	require.NotNil(t, cfg)
	// InsecureSkipVerify must be true: CA chain is skipped during bootstrap
	assert.True(t, cfg.InsecureSkipVerify, "InsecureSkipVerify must be true for SPKI bootstrap")
	// VerifyConnection must be set: this IS the actual verification
	assert.NotNil(t, cfg.VerifyConnection, "VerifyConnection must be set for pin verification")
	// MinVersion must be TLS 1.2+
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestNewPinnedTLSConfig_VerifiesCorrectPin(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin, err := ComputePin(cert)
	require.NoError(t, err)

	cfg := NewPinnedTLSConfig(pin)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	assert.NoError(t, cfg.VerifyConnection(cs))
}

func TestNewPinnedTLSConfig_RejectsWrongPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	cfg := NewPinnedTLSConfig("wrong-pin-value")
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	err := cfg.VerifyConnection(cs)
	assert.ErrorIs(t, err, ErrInvalidPin)
}

func TestComputePinFromPEM(t *testing.T) {
	cert, _ := generateTestCert(t)
	pemData := encodeCertPEM(t, cert)

	pin, err := ComputePinFromPEM(pemData)
	require.NoError(t, err)
	assert.NotEmpty(t, pin)

	// Verify it matches ComputePin on the same certificate
	directPin, err := ComputePin(cert)
	require.NoError(t, err)
	assert.Equal(t, directPin, pin)
}

func TestComputePinFromPEMInvalid(t *testing.T) {
	pin, err := ComputePinFromPEM([]byte("not valid PEM data"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
	assert.Empty(t, pin)
}

func TestComputePinFromPEMInvalidDER(t *testing.T) {
	// Valid PEM encoding but invalid certificate DER data
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a valid DER certificate"),
	})
	pin, err := ComputePinFromPEM(badPEM)
	assert.ErrorIs(t, err, ErrParseCertificate)
	assert.Empty(t, pin)
}

func TestFetchServerPinWithCA(t *testing.T) {
	cert, key := generateTestCertWithSAN(t)
	addr := startTLSServer(t, cert, key)

	// Build a CA pool that trusts our self-signed cert
	caPool := buildCertPool(t, cert)

	pin, serverCert, err := FetchServerPinWithCA(addr, caPool)
	require.NoError(t, err)
	assert.NotEmpty(t, pin)
	require.NotNil(t, serverCert)

	// Verify the returned pin matches the certificate
	expectedPin, err := ComputePin(cert)
	require.NoError(t, err)
	assert.Equal(t, expectedPin, pin)

	// Verify the returned certificate matches the server certificate
	assert.Equal(t, cert.Raw, serverCert.Raw)
}

func TestFetchServerPinDialFailure(t *testing.T) {
	// Use a non-routable address to trigger connection failure
	pin, cert, err := FetchServerPin("127.0.0.1:1")
	assert.ErrorIs(t, err, ErrDialFailed)
	assert.Empty(t, pin)
	assert.Nil(t, cert)
}

func TestFetchServerPinWithCADialFailure(t *testing.T) {
	pin, cert, err := FetchServerPinWithCA("127.0.0.1:1", nil)
	assert.ErrorIs(t, err, ErrDialFailed)
	assert.Empty(t, pin)
	assert.Nil(t, cert)
}

func TestFetchServerPinVerifyRoundtrip(t *testing.T) {
	// Test the full workflow: fetch a pin from a server, then verify it
	cert, key := generateTestCertWithSAN(t)
	addr := startTLSServer(t, cert, key)

	// Build a CA pool that trusts our self-signed cert
	caPool := buildCertPool(t, cert)

	// Fetch the pin using CA-verified connection
	pin, _, err := FetchServerPinWithCA(addr, caPool)
	require.NoError(t, err)

	// Verify the pin against the original certificate
	err = VerifyPin(cert, pin)
	assert.NoError(t, err)

	// Verify the VerifyConnection callback also works
	verifyFunc := VerifyConnection(pin)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	err = verifyFunc(cs)
	assert.NoError(t, err)
}

func TestFetchServerPinWithCAFile(t *testing.T) {
	cert, key := generateTestCertWithSAN(t)
	addr := startTLSServer(t, cert, key)

	// Write the cert to a temp file
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	pemData := encodeCertPEM(t, cert)
	require.NoError(t, os.WriteFile(caFile, pemData, 0600))

	pin, serverCert, err := FetchServerPinWithCAFile(addr, caFile)
	require.NoError(t, err)
	assert.NotEmpty(t, pin)
	require.NotNil(t, serverCert)

	expectedPin, err := ComputePin(cert)
	require.NoError(t, err)
	assert.Equal(t, expectedPin, pin)
}

func TestFetchServerPinWithCAFileReadError(t *testing.T) {
	pin, cert, err := FetchServerPinWithCAFile("127.0.0.1:1", "/nonexistent/path/ca.pem")
	assert.ErrorIs(t, err, ErrReadCAFile)
	assert.Empty(t, pin)
	assert.Nil(t, cert)
}

func TestFetchServerPinWithCAFileParseError(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a PEM certificate"), 0600))

	pin, cert, err := FetchServerPinWithCAFile("127.0.0.1:1", caFile)
	assert.ErrorIs(t, err, ErrParseCAFile)
	assert.Empty(t, pin)
	assert.Nil(t, cert)
}

func TestFetchServerPinUntrustedServer(t *testing.T) {
	// Server uses a self-signed cert, but we don't trust it
	cert, key := generateTestCertWithSAN(t)
	addr := startTLSServer(t, cert, key)

	// Fetch without adding the cert to a CA pool - should fail because
	// the system trust store does not contain our self-signed cert
	pin, serverCert, err := FetchServerPin(addr)
	assert.ErrorIs(t, err, ErrDialFailed)
	assert.Empty(t, pin)
	assert.Nil(t, serverCert)
}

func TestErrorMessages(t *testing.T) {
	// Verify error messages are descriptive
	assert.Equal(t, "certificate is nil", ErrNilCertificate.Error())
	assert.Equal(t, "pin is empty", ErrEmptyPin.Error())
	assert.Equal(t, "SPKI pin does not match certificate", ErrInvalidPin.Error())
	assert.Equal(t, "no PEM data found", ErrInvalidPEM.Error())
	assert.Equal(t, "failed to parse certificate", ErrParseCertificate.Error())
	assert.Equal(t, "no peer certificates in connection state", ErrNoPeerCertificates.Error())
	assert.Equal(t, "failed to connect to server", ErrDialFailed.Error())
	assert.Equal(t, "failed to read CA certificate file", ErrReadCAFile.Error())
	assert.Equal(t, "failed to parse CA certificate file", ErrParseCAFile.Error())
}

func TestComputePinHexEncoding(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin, err := ComputePin(cert)
	require.NoError(t, err)

	// Verify the pin is valid hex
	decoded, err := hex.DecodeString(pin)
	require.NoError(t, err)
	assert.Len(t, decoded, 32) // SHA-256 = 32 bytes

	// Verify lowercase hex
	assert.Equal(t, pin, fmt.Sprintf("%x", decoded))
}
