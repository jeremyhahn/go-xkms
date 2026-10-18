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

package clusterca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stagedTrustedCA pre-stages a real TrustedCA hierarchy (root, platform and
// cluster CA identities) over in-memory software keystores, the same CA the
// first node issues from.
func stagedTrustedCA(t *testing.T, dataDir string) SigningCA {
	t.Helper()
	p, err := New(firstNodeOptions(t, dataDir, softwareBackends(t)), testLogger())
	require.NoError(t, err)
	issuer, err := p.stageBootstrapCA(context.Background())
	require.NoError(t, err)
	trustedCA, ok := issuer.(SigningCA)
	require.True(t, ok, "the staged TrustedCA must satisfy SigningCA")
	return trustedCA
}

// issueNodeLeafWith signs a node leaf for a fresh key with the provider's
// signer and certificate, as go-qrdb does with Key A.
func issueNodeLeafWith(t *testing.T, p *KeyProvider) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	signer, err := p.Signer(ctx)
	require.NoError(t, err)
	caCert, err := p.Certificate(ctx)
	require.NoError(t, err)

	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	nodeURI, err := url.Parse("spiffe://test.cluster/node/127.0.0.1:8301")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "node-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{nodeURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, nodeKey.Public(), signer)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf, caCert
}

// TestKeyProvider_SignsAsTrustedCA verifies the bound TrustedCA is the cluster
// CA: a node leaf signed through the provider chains to the TrustedCA's
// cluster CA identity, and no CA key bytes are written to disk (go-xkms#1381).
func TestKeyProvider_SignsAsTrustedCA(t *testing.T) {
	dataDir := t.TempDir()
	p := NewKeyProvider("Cluster Test Cluster CA")
	require.NoError(t, p.Bind(stagedTrustedCA(t, dataDir)))

	leaf, caCert := issueNodeLeafWith(t, p)
	assert.Equal(t, "Cluster Test Cluster CA", caCert.Subject.CommonName)
	assert.True(t, caCert.IsCA)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "the node leaf must chain to the TrustedCA's cluster CA")

	assertNoCAKeyOnDisk(t, dataDir)
}

// TestKeyProvider_DefaultIdentity verifies an empty identity CN selects the
// TrustedCA's issuing identity, whose signer matches its certificate.
func TestKeyProvider_DefaultIdentity(t *testing.T) {
	p := NewKeyProvider("")
	require.NoError(t, p.Bind(stagedTrustedCA(t, t.TempDir())))

	leaf, caCert := issueNodeLeafWith(t, p)
	require.NoError(t, leaf.CheckSignatureFrom(caCert))
}

// TestKeyProvider_Unbound verifies the provider refuses to sign before the
// TrustedCA is bound, with a typed error go-qrdb logs and retries past.
func TestKeyProvider_Unbound(t *testing.T) {
	p := NewKeyProvider("Cluster Test Cluster CA")

	signer, err := p.Signer(context.Background())
	var unbound *ErrClusterCAUnbound
	require.ErrorAs(t, err, &unbound)
	assert.Nil(t, signer)

	cert, err := p.Certificate(context.Background())
	require.ErrorAs(t, err, &unbound)
	assert.Nil(t, cert)
}

// TestKeyProvider_BindNil verifies binding no CA is refused.
func TestKeyProvider_BindNil(t *testing.T) {
	err := NewKeyProvider("").Bind(nil)
	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "TrustedCA", missing.Field)
}

// fakeSigningCA is a SigningCA with a fixed signer and certificate, or a
// fixed error, for the provider's failure paths.
type fakeSigningCA struct {
	signer    crypto.Signer
	cert      *x509.Certificate
	signerErr error
	certErr   error
}

func (f *fakeSigningCA) Signer(context.Context) (crypto.Signer, error) {
	return f.signer, f.signerErr
}

func (f *fakeSigningCA) CACertificate() (*x509.Certificate, error) {
	return f.cert, f.certErr
}

// selfSignedCACert returns a self-signed CA certificate over a fresh key.
func selfSignedCACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Cluster CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// TestKeyProvider_KeyMismatch verifies a CA whose signer does not hold the key
// its certificate certifies is refused rather than minting unverifiable leaves.
func TestKeyProvider_KeyMismatch(t *testing.T) {
	_, cert := selfSignedCACert(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p := NewKeyProvider("")
	require.NoError(t, p.Bind(&fakeSigningCA{signer: otherKey, cert: cert}))

	signer, err := p.Signer(context.Background())
	var mismatch *ErrClusterCAKeyMismatch
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, "Fake Cluster CA", mismatch.Subject)
	assert.Nil(t, signer)
}

// TestKeyProvider_PropagatesCAFailure verifies a TrustedCA that cannot produce
// its signer or certificate surfaces the cause.
func TestKeyProvider_PropagatesCAFailure(t *testing.T) {
	key, cert := selfSignedCACert(t)
	cause := errors.New("hsm session closed")

	p := NewKeyProvider("")
	require.NoError(t, p.Bind(&fakeSigningCA{cert: cert, signerErr: cause}))
	_, err := p.Signer(context.Background())
	require.ErrorIs(t, err, cause)

	require.NoError(t, p.Bind(&fakeSigningCA{signer: key, certErr: cause}))
	_, err = p.Signer(context.Background())
	require.ErrorIs(t, err, cause)
	_, err = p.Certificate(context.Background())
	require.ErrorIs(t, err, cause)
}

// TestKeyProvider_NamedIdentityUnsupported verifies a named cluster CA identity
// on a CA without per-identity issuance is refused, not silently replaced by
// the default issuing identity.
func TestKeyProvider_NamedIdentityUnsupported(t *testing.T) {
	key, cert := selfSignedCACert(t)
	p := NewKeyProvider("Cluster CA")
	require.NoError(t, p.Bind(&fakeSigningCA{signer: key, cert: cert}))

	var missing *ErrMissingOption
	_, err := p.Signer(context.Background())
	require.ErrorAs(t, err, &missing)
	_, err = p.Certificate(context.Background())
	require.ErrorAs(t, err, &missing)
}

// TestKeyProvider_NamedIdentityUnknown verifies an identity CN the TrustedCA
// does not hold surfaces the TrustedCA's error.
func TestKeyProvider_NamedIdentityUnknown(t *testing.T) {
	p := NewKeyProvider("No Such CA")
	require.NoError(t, p.Bind(stagedTrustedCA(t, t.TempDir())))

	signer, err := p.Signer(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "No Such CA")
	assert.Nil(t, signer)
}
