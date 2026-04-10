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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

func TestNoiseGenerateKey(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	generateNoiseKey("")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Private key:")
	assert.Contains(t, output, "Public key:")

	// Extract private key and verify it's valid hex of correct length
	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Len(t, lines, 2)

	privateHex := strings.TrimPrefix(lines[0], "Private key: ")
	assert.Len(t, privateHex, 64) // 32 bytes = 64 hex chars

	publicHex := strings.TrimPrefix(lines[1], "Public key:  ")
	assert.Len(t, publicHex, 64)
}

func TestNoiseGenerateKey_OutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "noise.key")

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	generateNoiseKey(keyFile)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	// Verify file was created
	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Len(t, strings.TrimSpace(string(data)), 64)

	// Verify file permissions
	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestNoiseShowKey_FromHex(t *testing.T) {
	// First generate a key to get valid hex
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	hexKey := noiseproto.EncodeStaticKey(key)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showNoiseKey("", hexKey)

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Public key:")
}

func TestNoiseShowKey_FromFile(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	hexKey := noiseproto.EncodeStaticKey(key)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(hexKey+"\n"), 0600))

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	showNoiseKey(keyFile, "")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Public key:")
}

func TestNoiseShowKey_NoInput(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showNoiseKey("", "")
	assert.True(t, exitCalled)
}

func TestNoiseShowKey_InvalidHex(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showNoiseKey("", "not-valid-hex")
	assert.True(t, exitCalled)
}

func TestNoiseShowKey_InvalidFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showNoiseKey("/nonexistent/path/key.hex", "")
	assert.True(t, exitCalled)
}

func TestNoiseShowSPKIPin_FromCertFile(t *testing.T) {
	// Generate a self-signed cert, write as PEM, compute pin
	cert, _ := generateTestCertForNoise(t)

	// Write cert to PEM file
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.pem")

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(certFile, pemData, 0644))

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
}

func TestNoiseShowSPKIPin_NoInput(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showSPKIPin("")
	assert.True(t, exitCalled)
}

func TestNoiseShowSPKIPin_InvalidCertFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	showSPKIPin("/nonexistent/path/cert.pem")
	assert.True(t, exitCalled)
}

func TestNoiseShowSPKIPin_InvalidPEM(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad.pem")
	require.NoError(t, os.WriteFile(certFile, []byte("not a PEM file"), 0644))

	showSPKIPin(certFile)
	assert.True(t, exitCalled)
}

func TestNoiseShowSPKIPin_InvalidDER(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad-der.pem")

	// Valid PEM structure but invalid DER content
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	}
	pemData := pem.EncodeToMemory(pemBlock)
	require.NoError(t, os.WriteFile(certFile, pemData, 0644))

	showSPKIPin(certFile)
	assert.True(t, exitCalled)
}

func generateTestCertForNoise(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
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
