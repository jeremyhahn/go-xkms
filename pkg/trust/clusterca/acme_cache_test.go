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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// expiringChain builds a self-consistent chain whose leaf sits inside the
// renewal window (less than a quarter of its validity remaining), which is the
// condition that must force re-enrollment at boot.
func expiringChain(t *testing.T, uri string) (anchorPEM []byte, leafChainPEM []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expiring root"},
		NotBefore:             time.Now().Add(-200 * time.Hour),
		NotAfter:              time.Now().Add(200 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	parsed, err := url.Parse(uri)
	require.NoError(t, err)

	// 100 hours total validity with 1 hour left: well inside the 1/4 window.
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expiring leaf"},
		NotBefore:    time.Now().Add(-99 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{parsed},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return certsToPEM(rootCert), certsToPEM(leafCert)
}

// TestResultFromCache_RejectsCertificateInsideRenewalWindow verifies a cached
// certificate close to expiry is refused so the node re-enrolls while it can
// still authenticate. Accepting it would let the node boot with a certificate
// that expires mid-flight and silently drop out of the cluster.
func TestResultFromCache_RejectsCertificateInsideRenewalWindow(t *testing.T) {
	p, err := New(firstNodeOptions(t, t.TempDir(), softwareBackends(t)), testLogger())
	require.NoError(t, err)

	anchorPEM, leafChainPEM := expiringChain(t, p.expectedNodeURI())

	res, err := p.resultFromCache(context.Background(), leafChainPEM, anchorPEM)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Contains(t, err.Error(), "renewal window")
}

// TestResultFromCache_RejectsUnparseableChain verifies a corrupted cache file
// is rejected rather than partially trusted.
func TestResultFromCache_RejectsUnparseableChain(t *testing.T) {
	p, err := New(firstNodeOptions(t, t.TempDir(), softwareBackends(t)), testLogger())
	require.NoError(t, err)

	res, err := p.resultFromCache(context.Background(), []byte("not a pem chain"), []byte("anchor"))
	require.Error(t, err)
	assert.Nil(t, res)
}

// TestResultFromCache_RejectsChainThatDoesNotAnchor verifies a cached leaf that
// does not chain to the cached anchor is refused. This is the on-disk tampering
// case: swapping in a certificate from a foreign CA must not yield a usable
// cluster identity.
func TestResultFromCache_RejectsChainThatDoesNotAnchor(t *testing.T) {
	p, err := New(firstNodeOptions(t, t.TempDir(), softwareBackends(t)), testLogger())
	require.NoError(t, err)

	// A well-formed, in-date chain from one CA, presented against a different
	// CA's anchor bundle.
	_, intermediate, leaf := miniChain(t, p.expectedNodeURI())
	foreignAnchorPEM, _, _ := miniChain(t, p.expectedNodeURI())

	res, err := p.resultFromCache(context.Background(),
		certsToPEM(leaf, intermediate), foreignAnchorPEM)

	var anchorErr *ErrAnchorMismatch
	require.ErrorAs(t, err, &anchorErr)
	assert.Nil(t, res)
}

// TestResultFromCache_RejectsWrongSPIFFEIdentity verifies a cached certificate
// issued for a different node is refused even though it chains correctly. A
// node must never adopt a peer's identity out of its own cache.
func TestResultFromCache_RejectsWrongSPIFFEIdentity(t *testing.T) {
	p, err := New(firstNodeOptions(t, t.TempDir(), softwareBackends(t)), testLogger())
	require.NoError(t, err)

	anchorPEM, intermediate, leaf := miniChain(t, "spiffe://test.cluster/node/10.9.9.9:9999")

	res, err := p.resultFromCache(context.Background(), certsToPEM(leaf, intermediate), anchorPEM)

	var spiffeErr *ErrSPIFFEMismatch
	require.ErrorAs(t, err, &spiffeErr)
	assert.Nil(t, res)
}

// TestResultFromCache_RejectsCertificateForAnotherKey verifies a cached
// certificate whose public key does not match the backend-held node key is
// refused. Without this check the node would present a certificate it cannot
// produce handshake signatures for, failing every mTLS connection with an
// opaque error instead of re-enrolling.
func TestResultFromCache_RejectsCertificateForAnotherKey(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	// Provision once so a genuine cached identity exists.
	p1, err := New(firstNodeOptions(t, dataDir, softwareBackends(t)), testLogger())
	require.NoError(t, err)
	_, err = p1.Provision(ctx)
	require.NoError(t, err)

	leafChainPEM, anchorPEM, ok := p1.loadCachedIdentity()
	require.True(t, ok)

	// A second provisioner over the SAME cache but a FRESH (empty) backend
	// holds no node key: reload refuses rather than generating one.
	p2, err := New(firstNodeOptions(t, dataDir, softwareBackends(t)), testLogger())
	require.NoError(t, err)

	res, err := p2.resultFromCache(ctx, leafChainPEM, anchorPEM)
	require.Error(t, err)
	assert.Nil(t, res)

	// Once that backend holds a different node key, the cached certificate
	// no longer matches it.
	backend, err := p2.nodeKeyBackend()
	require.NoError(t, err)
	_, err = p2.nodeSigner(ctx, backend.KeyProvider())
	require.NoError(t, err)

	res, err = p2.resultFromCache(ctx, leafChainPEM, anchorPEM)

	var anchorErr *ErrAnchorMismatch
	require.ErrorAs(t, err, &anchorErr)
	assert.Contains(t, anchorErr.Reason, "public key")
	assert.Nil(t, res)
}

// TestProvisionACME_ReprovisionsWhenCacheIsUnusable verifies the end-to-end
// recovery path: a damaged cache is discarded and the node provisions a fresh
// identity instead of failing to boot.
func TestProvisionACME_ReprovisionsWhenCacheIsUnusable(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	p1, err := New(firstNodeOptions(t, dataDir, softwareBackends(t)), testLogger())
	require.NoError(t, err)
	res1, err := p1.Provision(ctx)
	require.NoError(t, err)

	// Corrupt the cached node certificate.
	require.NoError(t, os.WriteFile(
		filepath.Join(dataDir, nodeCertFile), []byte("corrupted"), 0o600))

	// Fresh backends stand in for a node whose keystore was also lost, so the
	// pre-stage growth guard does not fire and provisioning can complete.
	p2, err := New(firstNodeOptions(t, dataDir, softwareBackends(t)), testLogger())
	require.NoError(t, err)
	res2, err := p2.Provision(ctx)
	require.NoError(t, err, "a corrupt cache must be recovered from, not fatal")

	require.NotNil(t, res2.MTLS.Certificate)
	assert.NotEqual(t, res1.MTLS.Certificate.Leaf.SerialNumber, res2.MTLS.Certificate.Leaf.SerialNumber,
		"a fresh certificate must be issued, not the corrupt cached one")

	// The repaired cache must be usable on the next boot.
	_, _, ok := p2.loadCachedIdentity()
	assert.True(t, ok)
}

// TestIdevidSigner_BackendWithoutTPMFailsClosed verifies that selecting the
// tpm2 key backend while the resolved backend cannot expose a TPM is refused.
// Falling back to a software key here would silently downgrade the node from
// hardware-attested to software identity — exactly the substitution the
// attested mode exists to prevent.
func TestIdevidSigner_BackendWithoutTPMFailsClosed(t *testing.T) {
	backend, err := softwareBackends(t)("tpm2")
	require.NoError(t, err)

	signer, err := idevidSigner(backend, "tpm2")

	var noTPM *ErrNoTPM
	require.ErrorAs(t, err, &noTPM)
	assert.Equal(t, "tpm2", noTPM.KeyBackend)
	assert.Nil(t, signer)
}

// TestCachedNodeSigner_PropagatesBackendResolutionFailure verifies a node key
// resolver error surfaces on reload instead of being masked by a fallback.
func TestCachedNodeSigner_PropagatesBackendResolutionFailure(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	wantErr := &ErrMissingOption{Field: "NodeKeyBackends", Mode: "test"}
	opts.NodeKeyBackends = func(string) (xkms.Backend, error) { return nil, wantErr }

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	signer, err := p.cachedNodeSigner(context.Background())
	var unavailable *ErrKeyBackendUnavailable
	require.ErrorAs(t, err, &unavailable)
	require.ErrorIs(t, err, error(wantErr))
	assert.Nil(t, signer)
}

// TestKeyBackendName_DefaultsToSoftware verifies the unset key backend resolves
// to "software". This name is stamped into the issued certificate as the
// key-provenance OID, so a wrong default would misreport where the key lives.
func TestKeyBackendName_DefaultsToSoftware(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.KeyBackend = ""
	p, err := New(opts, testLogger())
	require.NoError(t, err)
	assert.Equal(t, "software", p.keyBackendName())

	opts2 := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts2.KeyBackend = "pkcs11"
	p2, err := New(opts2, testLogger())
	require.NoError(t, err)
	assert.Equal(t, "pkcs11", p2.keyBackendName())
}

// TestNewACMEClient_UsesOnlyTheClusterAnchor verifies the joiner's ACME client
// is constructed against the fetched cluster anchor. Each call must also mint a
// fresh, independent client: the account key is ephemeral per enrollment, so
// two enrollments must not share client state.
func TestNewACMEClient_UsesOnlyTheClusterAnchor(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.ACME.DirectoryURL = "https://node1:8443/api/v1/acme/directory"
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	anchorPEM, _, _ := miniChain(t, p.expectedNodeURI())

	first, err := p.newACMEClient(anchorPEM)
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := p.newACMEClient(anchorPEM)
	require.NoError(t, err)
	assert.NotSame(t, first, second, "each enrollment gets its own ephemeral client")
}

// TestPersistStagedCACerts_NonIdentityIssuerIsANoOp verifies the staged-CA
// export degrades gracefully when the issuer cannot enumerate identities: the
// anchor bundle remains the fallback and no partial file is written.
func TestPersistStagedCACerts_NonIdentityIssuerIsANoOp(t *testing.T) {
	dataDir := t.TempDir()
	opts := firstNodeOptions(t, dataDir, softwareBackends(t))
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	require.NoError(t, p.persistStagedCACerts(context.Background(), &plainIssuer{}))

	_, statErr := os.Stat(StagedCACertsPath(dataDir))
	assert.True(t, os.IsNotExist(statErr),
		"no staged-CA file may be written when identities cannot be enumerated")
}

// TestIssueNodeLeaf_ClusterCACNRequiresIdentityIssuer verifies that naming a
// cluster CA identity against an issuer that cannot select identities fails
// closed instead of quietly issuing from the default identity — which would put
// node certificates under the wrong intermediate.
func TestIssueNodeLeaf_ClusterCACNRequiresIdentityIssuer(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.ClusterCACN = "Cluster Test Cluster CA"
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf, issuerCert, err := p.issueNodeLeaf(context.Background(), &plainIssuer{}, signer)

	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Nil(t, leaf)
	assert.Nil(t, issuerCert)
}

// TestStageBootstrapCA_RequiresCAConfig verifies pre-staging refuses to run
// without a CA hierarchy to stage.
func TestStageBootstrapCA_RequiresCAConfig(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.CAConfig = nil
	opts.CA = &plainIssuer{} // satisfies New's first-node requirement
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	bootstrapCA, err := p.stageBootstrapCA(context.Background())
	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "CAConfig", missing.Field)
	assert.Nil(t, bootstrapCA)
}

// TestStageBootstrapCA_RequiresRootIdentity verifies a CA config carrying no
// identities is refused rather than producing a CA with nothing to anchor to.
func TestStageBootstrapCA_RequiresRootIdentity(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.CAConfig = &ca.MultiIdentityCAConfig{}
	p, err := New(opts, testLogger())
	require.NoError(t, err)

	bootstrapCA, err := p.stageBootstrapCA(context.Background())
	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "CAConfig.Identity", missing.Field)
	assert.Nil(t, bootstrapCA)
}

// plainIssuer is a CAIssuer that does NOT implement ca.IdentityIssuer, used to
// prove the per-identity paths fail closed rather than silently degrading.
type plainIssuer struct{}

func (i *plainIssuer) SignCSR(context.Context, []byte, *ca.SignOptions) (*x509.Certificate, error) {
	return nil, &ErrMissingOption{Field: "SignCSR", Mode: "test"}
}
func (i *plainIssuer) CABundle() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{}}), nil
}
func (i *plainIssuer) CACertificate() (*x509.Certificate, error) {
	return nil, &ErrMissingOption{Field: "CACertificate", Mode: "test"}
}

// TestResultFromCache_PropagatesSignerResolutionFailure verifies that a fully
// valid cached chain is still rejected when the backend cannot produce the
// node's signer. The cache says "this identity is yours", but without the key
// the node cannot use it, so provisioning must fall through to re-enrollment
// rather than returning a certificate it cannot sign with.
func TestResultFromCache_PropagatesSignerResolutionFailure(t *testing.T) {
	opts := firstNodeOptions(t, t.TempDir(), softwareBackends(t))
	opts.KeyBackend = "tpm2" // the node key resolver has no TPM
	nodeKeys, err := NewNodeKeyBackends(&NodeKeyBackendsParams{DataDir: nodeLocalDataDir(t)})
	require.NoError(t, err)
	opts.NodeKeyBackends = nodeKeys

	p, err := New(opts, testLogger())
	require.NoError(t, err)

	// A chain that passes renewal, anchor and SPIFFE checks, so the failure can
	// only come from signer resolution.
	anchorPEM, intermediate, leaf := miniChain(t, p.expectedNodeURI())

	res, err := p.resultFromCache(context.Background(), certsToPEM(leaf, intermediate), anchorPEM)

	var noTPM *ErrNoTPM
	require.ErrorAs(t, err, &noTPM)
	assert.Nil(t, res)
}
