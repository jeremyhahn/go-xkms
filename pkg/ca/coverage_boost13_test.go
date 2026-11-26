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

// Package ca coverage boost, thirteenth pass: targets remaining sub-91% functions
// not covered in passes 1–12. All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// constructors.go — NewParentCA: root.Validate() error path (empty CN)
// =============================================================================

// TestNewParentCA_EmptyCN_B13 exercises the root.Validate() error path in
// NewParentCA when the root identity has an empty common name.
func TestNewParentCA_EmptyCN_B13(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	params := &Params{
		Identity: []Identity{
			{
				// CommonName is intentionally empty to trigger Validate() error.
				Subject: Subject{CommonName: ""},
				Valid:   10,
				Keys:    DefaultKeyConfig(),
			},
		},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	_, err := NewParentCA(params)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// constructors.go — NewIntermediateCA: keyAttrs.KeyType == 0 for intermediate
// (covers line 280-282: KeyType not set defaults to KeyTypeCA)
// =============================================================================

// TestNewIntermediateCA_NoKeyType_B13 exercises the keyAttrs.KeyType == 0 branch
// in NewIntermediateCA by providing an intermediate key config without a KeyType.
func TestNewIntermediateCA_NoKeyType_B13(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "Root NoKeyType B13"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "Intermediate NoKeyType B13"
	// Clear intermediate KeyType.
	config.Identity[1].Keys[0].KeyType = ""

	rootParams := &Params{
		Identity:        []Identity{config.Identity[0]},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	root, err := NewParentCA(rootParams)
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))

	intParams := &Params{
		Identity:        config.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	intermediate, err := NewIntermediateCA(context.Background(), intParams, root)
	require.NoError(t, err)
	assert.NotNil(t, intermediate)
}

// =============================================================================
// trust_chain_extensions.go — RootCertificate: switch branches for
// intermediateCert match (line 232) and rootCert match (line 234)
// =============================================================================

// b13MakeRawCert creates a minimal self-signed or CA-signed certificate
// for testing purposes without using the full CA setup machinery.
func b13MakeRawCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// TestRootCertificate_SwitchFallback_B13 exercises the switch branches in
// RootCertificate that are only reached when certStore is nil:
//   - case intermediateCert: issuerCert = intermediateCert (line 232)
//   - case rootCert: return rootCert (line 234)
func TestRootCertificate_SwitchFallback_B13(t *testing.T) {
	t.Parallel()

	// Build a minimal root → intermediate → leaf chain without certStore.
	rootCert, rootKey := b13MakeRawCert(t, "B13 Root CA", nil, nil, true)
	intCert, intKey := b13MakeRawCert(t, "B13 Intermediate CA", rootCert, rootKey, true)
	leafCert, _ := b13MakeRawCert(t, "B13 Leaf", intCert, intKey, false)

	// Build a CA with no certStore so GetCertificate always returns an error,
	// forcing the switch to be taken.
	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	ca := &CA{
		rootCert:         rootCert,
		intermediateCert: intCert,
		certStore:        cs, // certStore exists but has NO certs stored
	}
	ca.initialized.Store(true)

	// leafCert is issued by intCert; intCert is issued by rootCert.
	// certStore.GetCertificate("B13 Intermediate CA") will return error (not found).
	// → switch takes the intermediateCert branch (line 232)
	// Then certStore.GetCertificate("B13 Root CA") will also return error.
	// → switch takes the rootCert branch (line 234) → returns rootCert, nil
	result, err := ca.RootCertificate(leafCert)
	require.NoError(t, err)
	assert.Equal(t, rootCert.Subject.CommonName, result.Subject.CommonName)
}
