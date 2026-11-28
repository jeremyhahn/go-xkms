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

package localtpm_test

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

	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
)

func writeSignerFile(t *testing.T, dir string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, localtpm.ReferenceSignerFile), data, 0o600))
}

// TestLoadReferenceSigner_None proves a data directory without the trusted
// signer file configures no signer: signed branch updates stay refused.
func TestLoadReferenceSigner_None(t *testing.T) {
	signer, err := localtpm.LoadReferenceSigner(t.TempDir())
	require.NoError(t, err)
	assert.Nil(t, signer)
}

// TestLoadReferenceSigner_PublicKey trusts the PEM public key in the file.
func TestLoadReferenceSigner_PublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	dir := t.TempDir()
	writeSignerFile(t, dir, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	signer, err := localtpm.LoadReferenceSigner(dir)
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.True(t, key.PublicKey.Equal(signer.PublicKey))
	assert.Nil(t, signer.Roots)
}

// TestLoadReferenceSigner_Roots trusts the PEM certificates in the file as
// the roots a signer's chain must reach.
func TestLoadReferenceSigner_Roots(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Reference Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	dir := t.TempDir()
	writeSignerFile(t, dir, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	signer, err := localtpm.LoadReferenceSigner(dir)
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.Nil(t, signer.PublicKey)
	require.NotNil(t, signer.Roots)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	_, err = cert.Verify(x509.VerifyOptions{Roots: signer.Roots})
	assert.NoError(t, err, "the root in the file must be trusted")
}

// TestLoadReferenceSigner_Invalid refuses a file that names no key or
// certificate, or an unparsable one, rather than opening without a signer.
func TestLoadReferenceSigner_Invalid(t *testing.T) {
	for name, data := range map[string][]byte{
		"not pem":          []byte("not a key"),
		"bad public key":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2}}),
		"bad certificate":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}),
		"other block type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}}),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeSignerFile(t, dir, data)
			_, err := localtpm.LoadReferenceSigner(dir)
			assert.ErrorIs(t, err, localtpm.ErrReferenceSignerInvalid)
		})
	}
}
