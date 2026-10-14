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

// password_vault_key_formats_test.go pins the PEM private-key encodings a
// software vault key file may use.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePEMKey writes der as a PEM block of the given type and returns the path.
func writePEMKey(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.key")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600))
	return path
}

func TestReadPEMPrivateKey_LegacyEncodings(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	got, err := readPEMPrivateKey(writePEMKey(t, "EC PRIVATE KEY", sec1))
	require.NoError(t, err)
	assert.True(t, ecKey.Equal(got), "a SEC 1 EC key is read")

	got, err = readPEMPrivateKey(writePEMKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)))
	require.NoError(t, err)
	assert.True(t, rsaKey.Equal(got), "a PKCS #1 RSA key is read")
}

func TestReadPEMPrivateKey_RefusesUnparsableBlock(t *testing.T) {
	_, err := readPEMPrivateKey(writePEMKey(t, "PRIVATE KEY", []byte("not a key")))
	assert.ErrorIs(t, err, ErrVaultKeyFileInvalid)
}
