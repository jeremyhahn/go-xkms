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

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPKIShowPin_FromCertFile(t *testing.T) {
	// Generate a self-signed cert
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

	// Write cert to PEM file
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.pem")

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(certFile, pemData, 0644))

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showSPKIPin(certFile)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "SPKI SHA-256 pin:")
	assert.Contains(t, output, "Subject:")

	// Verify the pin matches what we compute manually
	expectedPin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	expectedHex := hex.EncodeToString(expectedPin[:])
	assert.Contains(t, output, expectedHex)
}

func TestSPKIShowPin_NoInput(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showSPKIPin("")
	assert.True(t, exitCalled)
}

func TestSPKIShowPin_InvalidCertFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showSPKIPin("/nonexistent/cert.pem")
	assert.True(t, exitCalled)
}

func TestSPKIShowPin_InvalidPEM(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad.pem")
	require.NoError(t, os.WriteFile(certFile, []byte("not PEM data"), 0644))

	showSPKIPin(certFile)
	assert.True(t, exitCalled)
}
