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
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	noiseproto "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// newTestStaticKeyHex generates a static key and returns its hex encoding for
// use as test input. Production code writes the encoding to a file instead;
// tests need it as a value, and there is no encode-to-string helper by design.
func newTestStaticKeyHex(t *testing.T) (string, bool) {
	t.Helper()

	// Noise keys are X25519, which GODEBUG=fips140=only refuses: there the
	// refusal is asserted, the test re-runs outside FIPS and the caller returns.
	key, err := noiseproto.GenerateStaticKey()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, noiseproto.ErrFIPSUnsupported) {
		return "", false
	}
	require.NoError(t, err)
	defer key.Destroy()

	encoded := make([]byte, noiseproto.HexKeySize)
	require.NoError(t, noiseproto.EncodeStaticKey(encoded, key))
	return string(encoded), true
}

// noiseKeygenOutsideFIPS reports whether a test may go on to generate a
// Noise key. Noise keys are X25519, which GODEBUG=fips140=only refuses: there
// it runs generate, requires exit code 1 with the module's refusal and no key
// file written, re-runs the test outside FIPS and reports false.
func noiseKeygenOutsideFIPS(t *testing.T, keyFile string, generate func()) bool {
	t.Helper()
	if !fips140.Enforced() {
		return true
	}

	var stderr string
	code := captureExit(t, func() { stderr = captureStderr(t, generate) })

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "not allowed in FIPS 140-only mode")
	assert.NoFileExists(t, keyFile)
	fipstest.OutsideFIPS(t)
	return false
}

// TestNoiseGenerateKey_RequiresOutputFile covers the ruling that the private
// key is only ever written to a file: with no --output there is nowhere safe
// to put it, so the command must fail rather than print it.
func TestNoiseGenerateKey_RequiresOutputFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	stderr := captureStderr(t, func() { generateNoiseKey("") })

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	assert.True(t, exitCalled)
	assert.NotContains(t, buf.String(), "Private key")

	// Assert WHICH error, not merely that one happened. Checking only that
	// the command exited passes for any failure at all — including a write
	// error from whatever fallback path a regression might introduce, which
	// is exactly how this test slipped through its own mutation check.
	assert.Contains(t, stderr, "--output is required",
		"expected the missing-output error specifically, got: %s", stderr)
}

// captureStderr collects what handleError prints, so a test can assert which
// error was reported rather than only that the command exited.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// TestNoiseGenerateKey_RefusesExistingFile covers the permission hole that
// os.WriteFile leaves open: it applies its mode only when it creates the file,
// so writing over an existing 0644 path would publish the private key to every
// user on the box. Refusing the path also stops a rerun from silently
// replacing a Noise identity that peers have already pinned.
func TestNoiseGenerateKey_RefusesExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "noise.key")

	// A pre-existing, world-readable file at the target path.
	const sentinel = "do not overwrite me\n"
	require.NoError(t, os.WriteFile(keyFile, []byte(sentinel), 0644))

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	captureStdout(t, func() { generateNoiseKey(keyFile) })

	assert.True(t, exitCalled, "expected generate-key to fail on an existing path")

	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(data), "the existing file was overwritten")

	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(),
		"permissions changed on a file the command should not have touched")
}

func TestNoiseShowKey_FromFile(t *testing.T) {
	hexKey, ok := newTestStaticKeyHex(t)
	if !ok {
		return
	}

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
