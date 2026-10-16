// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// writePEM writes one PEM block of blockType to a file under dir.
func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
	return path
}

// TestReferenceSigner resolves backends.tpm2.reference_signer into the
// endorsement a signed CoRIM is verified under.
func TestReferenceSigner(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	keyPath := writePEM(t, dir, "signer.pem", "PUBLIC KEY", spki)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Reference Value Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	rootsPath := writePEM(t, dir, "roots.pem", "CERTIFICATE", der)

	s := newMinimalServer(t, &config.Config{})
	opts, err := s.referenceSigner()
	require.NoError(t, err)
	assert.Nil(t, opts, "no TPM2 section leaves reference-value updates off")

	s.config.Backends.TPM2 = &config.TPM2Config{Enabled: true, ReferenceSigner: &config.ReferenceSignerConfig{PublicKey: keyPath}}
	opts, err = s.referenceSigner()
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(opts.PublicKey), "the pinned key is the file's key")
	assert.Nil(t, opts.Roots)

	s.config.Backends.TPM2.ReferenceSigner = &config.ReferenceSignerConfig{Roots: rootsPath}
	opts, err = s.referenceSigner()
	require.NoError(t, err)
	require.NotNil(t, opts.Roots)
	assert.Nil(t, opts.PublicKey)
}

func TestReferenceSigner_Errors(t *testing.T) {
	dir := t.TempDir()
	garbage := writePEM(t, dir, "garbage.pem", "PUBLIC KEY", []byte("not a key"))
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name   string
		signer config.ReferenceSignerConfig
		check  func(t *testing.T, err error)
	}{
		{"missing public key file", config.ReferenceSignerConfig{PublicKey: missing}, func(t *testing.T, err error) {
			var fileErr *ErrFileRead
			require.ErrorAs(t, err, &fileErr)
			assert.Equal(t, missing, fileErr.Path)
		}},
		{"unparseable public key", config.ReferenceSignerConfig{PublicKey: garbage}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, ErrParsePublicKey)
		}},
		{"roots without a certificate", config.ReferenceSignerConfig{Roots: garbage}, func(t *testing.T, err error) {
			var parseErr *ErrCertParse
			require.ErrorAs(t, err, &parseErr)
		}},
		{"neither a key nor roots", config.ReferenceSignerConfig{}, func(t *testing.T, err error) {
			require.ErrorIs(t, err, ErrReferenceSignerUnset)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newMinimalServer(t, &config.Config{})
			s.config.Backends.TPM2 = &config.TPM2Config{Enabled: true, ReferenceSigner: &tt.signer}
			_, err := s.referenceSigner()
			tt.check(t, err)
		})
	}
}
