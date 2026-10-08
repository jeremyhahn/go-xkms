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
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// config.go — GetSignatureAlgorithm: parsedCurve == nil branch
// (covers line 485-487: ECCConfig with unrecognized curve name)
// =============================================================================

// TestGetSignatureAlgorithm_UnknownCurveName_B13 exercises an ECDSA identity
// with an unrecognized ECCConfig.Curve string. GetSignatureAlgorithm used to
// swallow types.ParseCurve's error and silently default to ECDSAWithSHA256
// (#701); a misconfigured curve name is a real configuration error and must
// be reported, not papered over with a default signature algorithm.
func TestGetSignatureAlgorithm_UnknownCurveName_B13(t *testing.T) {
	t.Parallel()
	id := &Identity{
		Subject: Subject{CommonName: "unknown-curve-b13"},
		Keys: []*types.KeyConfig{
			{
				KeyAlgorithm: types.AlgorithmECDSA,
				KeyType:      "CA",
				ECCConfig:    &types.ECCConfig{Curve: "CURVE_UNKNOWN_B13"},
			},
		},
	}
	algo, err := id.GetSignatureAlgorithm()
	require.ErrorIs(t, err, types.ErrUnknownCurve)
	assert.Equal(t, x509.UnknownSignatureAlgorithm, algo)
}

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
// constructors.go — NewParentCA: keyAttrs.KeyType == 0 inner block
// (covers line 205-207: KeyType not set in key config defaults to KeyTypeCA)
// =============================================================================

// TestNewParentCA_NoKeyType_B13 exercises the keyAttrs.KeyType == 0 branch in
// NewParentCA by providing a key config without an explicit KeyType.
func TestNewParentCA_NoKeyType_B13(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	// Build an identity whose KeyConfig has NO KeyType set.
	// DefaultKeyConfig() has no KeyType — but most tests set it explicitly.
	keys := DefaultKeyConfig()
	// Explicitly clear KeyType to ensure it is zero.
	keys[0].KeyType = ""

	params := &Params{
		Identity: []Identity{
			{
				Subject: Subject{CommonName: "No KeyType Root B13", Organization: "Test"},
				Valid:   10,
				Keys:    keys,
			},
		},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	root, err := NewParentCA(params)
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))
}

// =============================================================================
// constructors.go — NewIntermediateCA: intermediateID.Validate() error (empty CN)
// =============================================================================

// TestNewIntermediateCA_EmptyIntermediateCN_B13 exercises the intermediateID.Validate()
// error path in NewIntermediateCA when Identity[1] has an empty common name.
func TestNewIntermediateCA_EmptyIntermediateCN_B13(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "Root For Empty Int B13"
	config.Identity[0].Keys[0].KeyType = "CA"
	// Empty CN for intermediate.
	config.Identity[1].Subject.CommonName = ""
	config.Identity[1].Keys[0].KeyType = "CA"

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
	_, err = NewIntermediateCA(context.Background(), intParams, root)
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

// =============================================================================
// ca_extensions.go — Issued: success path (88.9%)
// =============================================================================

// =============================================================================
// constructors.go — NewCA: single-identity path (line 394-396)
// =============================================================================

// TestNewCA_SingleIdentity_B13 exercises the single-identity path in NewCA
// (len(params.Identity) == 1) which returns the root CA with a nil intermediate.
func TestNewCA_SingleIdentity_B13(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	params := &Params{
		Identity: []Identity{
			{
				Subject: Subject{CommonName: "Single Identity Root B13", Organization: "Test"},
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
	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	assert.NotNil(t, root)
	// Single identity: intermediate must be nil (line 394-396).
	assert.Nil(t, intermediate)
	assert.True(t, root.IsInitialized())
}

// =============================================================================
// ca_extensions.go — PubKey: nil attrs path (88.9%)
// =============================================================================

// TestPubKey_NilAttrs_B13 exercises PubKey when nil attrs are passed.
func TestPubKey_NilAttrs_B13(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.PubKey(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestPubKey_Success_B13 exercises the success path of PubKey on an initialized CA.
func TestPubKey_Success_B13(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	cn := "pubkey-b13"
	issueCertAndSaveToKeyStore(t, ca, cn)

	attrs := softwareKeyAttrs(cn)
	key, err := ca.PubKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// =============================================================================
// ca.go — Load: already-initialized guard (81.8%)
// =============================================================================

// TestLoad_AlreadyInitialized_B13 exercises the ErrAlreadyInitialized path in Load.
func TestLoad_AlreadyInitialized_B13(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// ca is already initialized; calling Load should return ErrAlreadyInitialized.
	err := ca.Load(context.Background())
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// =============================================================================
// bundle.go — encodeCertsToPEM: empty certs slice path (90.0%)
// =============================================================================

// TestEncodeCertsToPEM_Empty_B13 exercises encodeCertsToPEM with an empty slice
// which triggers the ErrNoCACertificates error path.
func TestEncodeCertsToPEM_Empty_B13(t *testing.T) {
	t.Parallel()
	_, err := encodeCertsToPEM(nil)
	assert.ErrorIs(t, err, ErrNoCACertificates)
}

// TestEncodeCertsToPEM_WithCerts_B13 exercises encodeCertsToPEM with a valid cert.
func TestEncodeCertsToPEM_WithCerts_B13(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	cert, err := ca.CACertificate()
	require.NoError(t, err)
	result, err := encodeCertsToPEM([]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	block, _ := pem.Decode(result)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}
