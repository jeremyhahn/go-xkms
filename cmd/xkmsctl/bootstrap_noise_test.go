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
	"errors"
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

// newTestStaticKeyHex generates a static key and returns its hex encoding for
// use as test input. Production code writes the encoding to a file instead;
// tests need it as a value, and there is no encode-to-string helper by design.
func newTestStaticKeyHex(t *testing.T) string {
	t.Helper()

	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	encoded := make([]byte, noiseproto.HexKeySize)
	require.NoError(t, noiseproto.EncodeStaticKey(encoded, key))
	return string(encoded)
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

	// The private key goes to the file and nowhere else.
	output := buf.String()
	assert.Contains(t, output, "Private key written to:")
	assert.NotContains(t, output, "Private key: ")

	// Verify file was created
	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Len(t, strings.TrimSpace(string(data)), 64)

	// Verify file permissions
	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
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

func TestNoiseShowKey_FromHex(t *testing.T) {
	// First generate a key to get valid hex
	hexKey := newTestStaticKeyHex(t)

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
	hexKey := newTestStaticKeyHex(t)

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

// failingWriter fails on Write or on Close, so the cleanup path can be driven
// without depending on a full disk or a revoked permission.
type failingWriter struct {
	f        *os.File
	writeErr error
	closeErr error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		// Land a partial key on disk first: the point of the test is that a
		// truncated private key does not survive the failure.
		_, _ = w.f.Write(p[:len(p)/2])
		return 0, w.writeErr
	}
	return w.f.Write(p)
}

func (w *failingWriter) Close() error {
	_ = w.f.Close()
	if w.closeErr != nil {
		return w.closeErr
	}
	return nil
}

func (w *failingWriter) Stat() (os.FileInfo, error) { return w.f.Stat() }

// swappingWriter reproduces the window between a failed write and the
// cleanup: it lands a partial key, then something else with write access to
// the directory renames that file away and puts an unrelated file at the same
// path, and only then does the write report failure.
type swappingWriter struct {
	f    *os.File
	path string
}

func (w *swappingWriter) Write(p []byte) (int, error) {
	_, _ = w.f.Write(p[:len(p)/2])

	// Somebody else wins the race for the name.
	if err := os.Rename(w.path, w.path+".stolen"); err != nil {
		return 0, err
	}
	if err := os.WriteFile(w.path, []byte("not yours\n"), 0600); err != nil {
		return 0, err
	}

	return 0, errors.New("disk full")
}

func (w *swappingWriter) Close() error               { return w.f.Close() }
func (w *swappingWriter) Stat() (os.FileInfo, error) { return w.f.Stat() }

// TestGenerateNoiseKey_DoesNotDeleteAReplacementFile pins the identity check
// in the failure cleanup. os.Remove unlinks whatever holds the name at the
// moment it runs, not the file the failure produced, so an unconditional
// removal deletes a file this command never created — somebody else's data,
// destroyed while tidying up after ourselves.
//
// The stranded partial key this leaves behind is the deliberate trade: it is
// reported to the caller and refused by the next run's O_EXCL, where a wrong
// unlink is silent and irreversible.
func TestGenerateNoiseKey_DoesNotDeleteAReplacementFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "noise.key")

	original := createNoiseKeyFile
	createNoiseKeyFile = func(path string) (noiseKeyFile, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		return &swappingWriter{f: f, path: path}, nil
	}
	defer func() { createNoiseKeyFile = original }()

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	captureStdout(t, func() { generateNoiseKey(keyFile) })

	require.True(t, exitCalled, "expected the failure to be reported")

	replacement, err := os.ReadFile(keyFile)
	require.NoError(t, err, "the replacement file was deleted by the cleanup")
	assert.Equal(t, "not yours\n", string(replacement),
		"the cleanup unlinked the path rather than the file it created")
}

// TestGenerateNoiseKey_RemovesPartialFileOnFailure covers the interaction
// between O_EXCL and a failed write. Leaving the file behind would strand a
// truncated private key on disk, and because the next attempt refuses an
// existing path it would also block the retry that replaces it.
func TestGenerateNoiseKey_RemovesPartialFileOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		writeErr error
		closeErr error
	}{
		{name: "write fails", writeErr: errors.New("disk full")},
		{name: "close fails", closeErr: errors.New("flush failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "noise.key")

			original := createNoiseKeyFile
			createNoiseKeyFile = func(path string) (noiseKeyFile, error) {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return nil, err
				}
				return &failingWriter{f: f, writeErr: tc.writeErr, closeErr: tc.closeErr}, nil
			}
			defer func() { createNoiseKeyFile = original }()

			exitCalled := false
			oldExit := exitFunc
			exitFunc = func(code int) { exitCalled = true }
			defer func() { exitFunc = oldExit }()

			captureStdout(t, func() { generateNoiseKey(keyFile) })

			assert.True(t, exitCalled, "expected the failure to be reported")

			_, err := os.Stat(keyFile)
			assert.True(t, os.IsNotExist(err),
				"partial key file survived the failure: stat err = %v", err)
		})
	}

	// And the retry that the leftover would have blocked now succeeds.
	keyFile := filepath.Join(t.TempDir(), "noise.key")
	captureStdout(t, func() { generateNoiseKey(keyFile) })

	info, err := os.Stat(keyFile)
	require.NoError(t, err, "retry after a cleaned-up failure should succeed")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
