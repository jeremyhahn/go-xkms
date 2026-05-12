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

// Package ca tests for cross-signing. Complements session1_extensions_test.go
// by covering error-path semantics (invalid inputs, storage surface failures)
// and chain-walking behaviour (root detection, intermediate enumeration).
package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeChainedCert issues a short-lived CA certificate whose Issuer CN is
// parentCN. When parentCN == cn the certificate is self-signed (usable as a
// chain-walk terminator). Only the Subject / Issuer CN fields matter to the
// cross-signing tests; signature verification is not attempted by
// XSignedRootCertificate or XSignedIntermediateCertificates.
func makeChainedCert(t *testing.T, cn, parentCN string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	// Build a parent template whose Subject CN is parentCN. x509.CreateCertificate
	// copies the parent's Subject into the issued cert's Issuer field.
	parentTemplate := subjectTemplate
	parentKey := key
	if cn != parentCN {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		parentKey = pk
		parentTemplate = &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
			Subject:               pkix.Name{CommonName: parentCN},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, parentTemplate, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// =============================================================================
// ImportXSignedCertificate — input validation
// =============================================================================

// TestImportXSignedCertificate_EmptyIssuerCN asserts that an empty issuer CN
// is rejected with ErrInvalidConfig. Without this guard the object-store key
// would collapse to "cross-signed//<subject>.pem", silently creating an
// ambiguous entry.
func TestImportXSignedCertificate_EmptyIssuerCN(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "leaf")
	err := ca.ImportXSignedCertificate("", cert)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// XSignedCertificate — retrieval
// =============================================================================

// TestXSignedCertificate_NotFound asserts ErrCertificateNotFound for an
// issuer+subject pair that has never been imported.
func TestXSignedCertificate_NotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.XSignedCertificate("MissingIssuer", &types.KeyAttributes{CN: "missing-subject"})
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// TestXSignedCertificate_EmptyIssuerCN asserts that the issuer-CN guard
// rejects empty strings with ErrInvalidConfig.
func TestXSignedCertificate_EmptyIssuerCN(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.XSignedCertificate("", &types.KeyAttributes{CN: "any"})
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestXSignedCertificate_NilAttrs asserts that nil KeyAttributes are
// rejected with ErrInvalidCertificate.
func TestXSignedCertificate_NilAttrs(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.XSignedCertificate("issuer", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// XSignedRootCertificate — chain walk
// =============================================================================

// TestXSignedRootCertificate_SelfSignedReturnsSelf asserts that a cert which
// is already self-signed (Issuer == Subject) is returned directly without
// consulting the object store.
func TestXSignedRootCertificate_SelfSignedReturnsSelf(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	root := makeChainedCert(t, "Self Signed Root", "Self Signed Root")

	got, err := ca.XSignedRootCertificate("AnyIssuer", root)
	require.NoError(t, err)
	assert.Equal(t, root.Raw, got.Raw)
}

// TestXSignedRootCertificate_WalksToRoot asserts that the walk follows the
// cross-signed chain up to the first self-signed cert and returns it.
func TestXSignedRootCertificate_WalksToRoot(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	root := makeChainedCert(t, "Root", "Root")
	intermediate := makeChainedCert(t, "Int", "Root")
	leaf := makeChainedCert(t, "Leaf", "Int")

	require.NoError(t, ca.ImportXSignedCertificate("ExtIssuer", root))
	require.NoError(t, ca.ImportXSignedCertificate("ExtIssuer", intermediate))

	got, err := ca.XSignedRootCertificate("ExtIssuer", leaf)
	require.NoError(t, err)
	assert.Equal(t, root.Raw, got.Raw)
}

// TestXSignedRootCertificate_ParentNotFound asserts ErrCertificateNotFound
// when the chain walk encounters a parent that has not been imported.
func TestXSignedRootCertificate_ParentNotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	leaf := makeChainedCert(t, "Leaf", "MissingParent")

	_, err := ca.XSignedRootCertificate("ExtIssuer", leaf)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// TestXSignedRootCertificate_EmptyIssuerCN asserts the issuer-CN guard.
func TestXSignedRootCertificate_EmptyIssuerCN(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert := makeChainedCert(t, "Leaf", "Parent")
	_, err := ca.XSignedRootCertificate("", cert)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// XSignedIntermediateCertificates — chain walk
// =============================================================================

// TestXSignedIntermediateCertificates_NoChain asserts that a self-signed
// input returns an empty slice (the walk terminates immediately).
func TestXSignedIntermediateCertificates_NoChain(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	root := makeChainedCert(t, "Root", "Root")

	got, err := ca.XSignedIntermediateCertificates("ExtIssuer", root)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestXSignedIntermediateCertificates_RootExcluded asserts that the
// self-signed root is not included in the intermediate list.
func TestXSignedIntermediateCertificates_RootExcluded(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	root := makeChainedCert(t, "Root", "Root")
	intermediate := makeChainedCert(t, "Int", "Root")
	leaf := makeChainedCert(t, "Leaf", "Int")

	require.NoError(t, ca.ImportXSignedCertificate("ExtIssuer", root))
	require.NoError(t, ca.ImportXSignedCertificate("ExtIssuer", intermediate))

	got, err := ca.XSignedIntermediateCertificates("ExtIssuer", leaf)
	require.NoError(t, err)
	require.Len(t, got, 1, "root must not be counted as an intermediate")
	assert.Equal(t, "Int", got[0].Subject.CommonName)
}

// TestXSignedIntermediateCertificates_BrokenChain asserts that the walk
// terminates cleanly (no error) when a parent is missing from the store.
func TestXSignedIntermediateCertificates_BrokenChain(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	leaf := makeChainedCert(t, "Leaf", "MissingParent")
	got, err := ca.XSignedIntermediateCertificates("ExtIssuer", leaf)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// =============================================================================
// CrossSignedPEM — bundle assembly
// =============================================================================

// TestCrossSignedPEM_AggregatesAcrossIssuers asserts that the returned bundle
// contains every cross-signed certificate matching attrs.CN regardless of
// which issuer directory stored them.
func TestCrossSignedPEM_AggregatesAcrossIssuers(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	leafA, _ := makeSelfSignedCert(t, "shared-leaf")
	leafB, _ := makeSelfSignedCert(t, "shared-leaf")

	require.NoError(t, ca.ImportXSignedCertificate("IssuerA", leafA))
	require.NoError(t, ca.ImportXSignedCertificate("IssuerB", leafB))

	bundle, err := ca.CrossSignedPEM(&types.KeyAttributes{CN: "shared-leaf"})
	require.NoError(t, err)
	// Both certs must appear in the bundle; splitting on PEM headers is a
	// simple way to count them without asserting on order.
	assert.Equal(t, 2, bytes.Count(bundle, []byte("BEGIN CERTIFICATE")))
}

// TestCrossSignedPEM_NilAttrs asserts the nil-attrs guard.
func TestCrossSignedPEM_NilAttrs(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.CrossSignedPEM(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestCrossSignedPEM_EmptyCN asserts that an attrs whose CN is empty is
// rejected. Otherwise CrossSignedPEM would accidentally match every entry
// whose key ends in "/.pem".
func TestCrossSignedPEM_EmptyCN(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	_, err := ca.CrossSignedPEM(&types.KeyAttributes{CN: ""})
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// Object-store tampering
// =============================================================================

// TestReadCrossSignedCertificate_InvalidPEM asserts that a cross-signed
// entry whose body is not a valid PEM block surfaces ErrInvalidPEM rather
// than a generic storage error.
func TestReadCrossSignedCertificate_InvalidPEM(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	key := crossSignedStoreKey("ExtIssuer", "tampered")
	require.NoError(t, ca.objectStore.Put(key, bytes.NewReader([]byte("not a PEM"))))

	_, err := ca.XSignedCertificate("ExtIssuer", &types.KeyAttributes{CN: "tampered"})
	assert.ErrorIs(t, err, ErrInvalidPEM)
}
