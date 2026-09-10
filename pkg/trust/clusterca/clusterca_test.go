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
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// clusterenrollBootstrap returns join-side bootstrap options (unreachable
// endpoints — used only to select the joiner path in guard tests).
func clusterenrollBootstrap() clusterenroll.BootstrapOptions {
	return clusterenroll.BootstrapOptions{
		NoiseKey:  "aa",
		NoiseAddr: "127.0.0.1:63999",
	}
}

// certPool returns an x509 pool containing the given certificates.
func certPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// softwareBackends returns a Backends seam over a single in-memory software
// backend, shared across calls so keys persist within a test.
func softwareBackends(t *testing.T) func(name string) (xkms.Backend, error) {
	t.Helper()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	return func(name string) (xkms.Backend, error) {
		return backend, nil
	}
}

// clusterCAConfig mirrors the recommended hierarchy: root + sibling platform
// and cluster intermediates.
func clusterCAConfig() *ca.MultiIdentityCAConfig {
	cfg := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	cfg.Identity[0].Subject.CommonName = "Cluster Test Root CA"
	cfg.Identity[0].Keys[0].KeyType = "CA"
	cfg.Identity[1].Subject.CommonName = "Cluster Test Platform CA"
	cfg.Identity[1].Keys[0].KeyType = "CA"
	cfg.Identity[1].ParentCA = "Cluster Test Root CA"
	clusterKeys := ca.DefaultKeyConfig()
	clusterKeys[0].KeyType = "CA"
	cfg.Identity = append(cfg.Identity, ca.Identity{
		Subject: ca.Subject{
			CommonName:   "Cluster Test Cluster CA",
			Organization: "Organization",
			Country:      "US",
		},
		Valid:             ca.DefaultIntermediateValidityYears,
		Keys:              clusterKeys,
		KeystoreType:      types.StoreSoftware,
		ParentCA:          "Cluster Test Root CA",
		MaxPathLengthZero: true,
	})
	return cfg
}

// ---------------------------------------------------------------------------
// New (validation)
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	logger := testLogger()

	_, err := New(nil, logger)
	require.Error(t, err)

	// Files mode needs nothing else.
	_, err = New(&Options{RaftTLSFiles: &ExplicitFiles{
		CACertFile: "a", CertFile: "b", KeyFile: "c",
	}}, logger)
	require.NoError(t, err)

	// Auto-enrollment requires RaftAddress and DataDir.
	_, err = New(&Options{}, logger)
	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "RaftAddress", missing.Field)

	_, err = New(&Options{RaftAddress: "10.0.0.1:8300"}, logger)
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "DataDir", missing.Field)

	// ACME mode requires the Backends seam.
	_, err = New(&Options{
		RaftAddress: "10.0.0.1:8300", DataDir: t.TempDir(), ACME: &ACMEOptions{},
	}, logger)
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "Backends", missing.Field)

	// ACME first node requires a CA source.
	_, err = New(&Options{
		RaftAddress: "10.0.0.1:8300", DataDir: t.TempDir(), ACME: &ACMEOptions{},
		Backends: softwareBackends(t),
	}, logger)
	require.ErrorAs(t, err, &missing)
	assert.Contains(t, missing.Field, "CA or CAConfig")

	// Valid ACME first-node options default the challenge port.
	opts := &Options{
		RaftAddress: "10.0.0.1:8300", DataDir: t.TempDir(), ACME: &ACMEOptions{},
		Backends: softwareBackends(t), CAConfig: clusterCAConfig(),
	}
	_, err = New(opts, logger)
	require.NoError(t, err)
	assert.Equal(t, "8080", opts.ACME.ChallengePort)
	assert.Empty(t, opts.ACME.ChallengeHost, "the default bind host is every interface; the composition root supplies the daemon's")

	// Hardware mode requires the Backends seam.
	_, err = New(&Options{
		RaftAddress: "10.0.0.1:8300", DataDir: t.TempDir(), KeyBackend: "tpm2",
	}, logger)
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "Backends", missing.Field)
}

// ---------------------------------------------------------------------------
// Explicit files (precedence 1)
// ---------------------------------------------------------------------------

func TestProvision_ExplicitFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	files := &ExplicitFiles{
		CACertFile: write("ca.pem", "ca-pem"),
		CertFile:   write("cert.pem", "cert-pem"),
		KeyFile:    write("key.pem", "key-pem"),
	}

	p, err := New(&Options{RaftTLSFiles: files}, testLogger())
	require.NoError(t, err)
	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte("ca-pem"), res.MTLS.CACert)
	assert.Equal(t, []byte("cert-pem"), res.MTLS.Cert)
	assert.Equal(t, []byte("key-pem"), res.MTLS.Key)
	assert.Nil(t, res.Advertiser)
}

func TestProvision_ExplicitFiles_ReadError(t *testing.T) {
	p, err := New(&Options{RaftTLSFiles: &ExplicitFiles{
		CACertFile: "/nonexistent/ca.pem", CertFile: "x", KeyFile: "y",
	}}, testLogger())
	require.NoError(t, err)
	_, err = p.Provision(context.Background())
	var readErr *ErrFileRead
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, "CACertFile", readErr.Field)
}

// ---------------------------------------------------------------------------
// Software mode (precedence 4) — delegates to qrdb clusterenroll
// ---------------------------------------------------------------------------

func TestProvision_SoftwareSingleNode(t *testing.T) {
	p, err := New(&Options{
		RaftAddress: "127.0.0.1:8300",
		TrustDomain: "test.cluster",
		DataDir:     t.TempDir(),
		Members:     map[uint64]string{1: "127.0.0.1:8300"},
	}, testLogger())
	require.NoError(t, err)

	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.MTLS)
	assert.NotEmpty(t, res.MTLS.CACert)
	assert.NotEmpty(t, res.MTLS.Cert)
	assert.NotEmpty(t, res.MTLS.Key)
	assert.Nil(t, res.Advertiser)
}

// ---------------------------------------------------------------------------
// Chain / SAN verification helpers
// ---------------------------------------------------------------------------

// miniChain builds root → intermediate → leaf where the leaf carries uri.
func miniChain(t *testing.T, uri string) (rootPEM []byte, intermediate, leaf *x509.Certificate) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	rootKey, intKey, leafKey := newKey(), newKey(), newKey()

	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mini root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mini intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err)

	parsed, err := url.Parse(uri)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "mini leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		URIs:        []*url.URL{parsed},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return certsToPEM(rootCert), intCert, leafCert
}

func TestVerifyLeafAgainstAnchor(t *testing.T) {
	p, err := New(&Options{
		RaftAddress: "10.0.0.1:8300", TrustDomain: "test.cluster", DataDir: t.TempDir(),
	}, testLogger())
	require.NoError(t, err)

	uri := p.expectedNodeURI()
	rootPEM, intermediate, leaf := miniChain(t, uri)

	// Correct chain and SAN verifies.
	require.NoError(t, p.verifyLeafAgainstAnchor(leaf, []*x509.Certificate{intermediate}, rootPEM))

	// Wrong SPIFFE identity is rejected.
	otherRootPEM, otherInt, otherLeaf := miniChain(t, "spiffe://test.cluster/node/10.9.9.9:1")
	var spiffeErr *ErrSPIFFEMismatch
	err = p.verifyLeafAgainstAnchor(otherLeaf, []*x509.Certificate{otherInt}, otherRootPEM)
	require.ErrorAs(t, err, &spiffeErr)

	// Foreign anchor is rejected.
	var anchorErr *ErrAnchorMismatch
	err = p.verifyLeafAgainstAnchor(leaf, []*x509.Certificate{intermediate}, otherRootPEM)
	require.ErrorAs(t, err, &anchorErr)

	// Garbage anchor is rejected.
	err = p.verifyLeafAgainstAnchor(leaf, nil, []byte("not pem"))
	require.ErrorAs(t, err, &anchorErr)
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	fresh := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(100 * time.Hour)}
	assert.False(t, needsRenewal(fresh, now))

	nearExpiry := &x509.Certificate{NotBefore: now.Add(-100 * time.Hour), NotAfter: now.Add(time.Hour)}
	assert.True(t, needsRenewal(nearExpiry, now))

	expired := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	assert.True(t, needsRenewal(expired, now))
}

// ---------------------------------------------------------------------------
// First-node ACME pre-stage (end-to-end over in-memory/file stores)
// ---------------------------------------------------------------------------

func firstNodeOptions(t *testing.T, dataDir string, backends func(string) (xkms.Backend, error)) *Options {
	return &Options{
		RaftAddress: "127.0.0.1:8301",
		NodeID:      1,
		TrustDomain: "test.cluster",
		DataDir:     dataDir,
		Members:     map[uint64]string{1: "127.0.0.1:8301"},
		ACME:        &ACMEOptions{},
		Backends:    backends,
		CAConfig:    clusterCAConfig(),
		ClusterCACN: "Cluster Test Cluster CA",
	}
}

func TestProvisionACME_FirstNode_PreStage(t *testing.T) {
	dataDir := t.TempDir()
	backends := softwareBackends(t)

	p, err := New(firstNodeOptions(t, dataDir, backends), testLogger())
	require.NoError(t, err)
	res, err := p.Provision(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.MTLS)
	require.NotNil(t, res.MTLS.Certificate)

	// The leaf carries the SPIFFE node SAN and chains to the staged root.
	leaf := res.MTLS.Certificate.Leaf
	require.NotNil(t, leaf)
	require.Len(t, leaf.URIs, 1)
	assert.Equal(t, "spiffe://test.cluster/node/127.0.0.1:8301", leaf.URIs[0].String())

	// Issued by the CLUSTER intermediate, not the platform/issuing identity.
	assert.Equal(t, "Cluster Test Cluster CA", leaf.Issuer.CommonName)

	// The node presents its issuing cluster CA in the chain so peers can
	// build leaf → cluster CA → root against the pinned anchor.
	require.GreaterOrEqual(t, len(res.MTLS.Certificate.Certificate), 2, "chain should include the cluster CA")
	clusterCACert, err := x509.ParseCertificate(res.MTLS.Certificate.Certificate[1])
	require.NoError(t, err)
	assert.Equal(t, "Cluster Test Cluster CA", clusterCACert.Subject.CommonName)

	// The anchor pool is cert-only PEM (no key material) and contains the
	// self-signed root; the cache was written for restart reuse and adoption.
	assert.NotEmpty(t, res.MTLS.CACert)
	assert.NotContains(t, string(res.MTLS.CACert), "PRIVATE KEY")
	for _, name := range []string{nodeCertFile, anchorCertFile} {
		_, statErr := os.Stat(filepath.Join(dataDir, name))
		require.NoError(t, statErr, name)
	}
	anchorPEM, err := os.ReadFile(AnchorCachePath(dataDir))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(anchorPEM))
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: certPool(clusterCACert),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "node leaf must verify to the cached anchor via the cluster CA")

	// The FULL CA certificate set (root + BOTH intermediates) is persisted for
	// the runtime CA to adopt — the anchor bundle alone omits the non-selected
	// cluster intermediate, which Load verifies.
	stagedPEM, err := os.ReadFile(StagedCACertsPath(dataDir))
	require.NoError(t, err)
	stagedCNs := map[string]bool{}
	rest := stagedPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		require.NoError(t, perr)
		stagedCNs[cert.Subject.CommonName] = true
	}
	assert.True(t, stagedCNs["Cluster Test Root CA"], "staged set must include the root")
	assert.True(t, stagedCNs["Cluster Test Platform CA"], "staged set must include the platform intermediate")
	assert.True(t, stagedCNs["Cluster Test Cluster CA"], "staged set must include the cluster intermediate")

	// Single-node membership: no advertiser.
	assert.Nil(t, res.Advertiser)
}

func TestProvisionACME_FirstNode_CacheReuse(t *testing.T) {
	dataDir := t.TempDir()
	backends := softwareBackends(t)

	p1, err := New(firstNodeOptions(t, dataDir, backends), testLogger())
	require.NoError(t, err)
	res1, err := p1.Provision(context.Background())
	require.NoError(t, err)

	// A fresh Provisioner over the same DataDir + backends restores the
	// identity from cache (same leaf serial, no re-issuance).
	p2, err := New(firstNodeOptions(t, dataDir, backends), testLogger())
	require.NoError(t, err)
	res2, err := p2.Provision(context.Background())
	require.NoError(t, err)

	assert.Equal(t, res1.MTLS.Certificate.Leaf.SerialNumber, res2.MTLS.Certificate.Leaf.SerialNumber)
}

func TestProvisionACME_FirstNode_GrowthGuard(t *testing.T) {
	dataDir := t.TempDir()
	backends := softwareBackends(t)

	p1, err := New(firstNodeOptions(t, dataDir, backends), testLogger())
	require.NoError(t, err)
	_, err = p1.Provision(context.Background())
	require.NoError(t, err)

	// Simulate a wiped cache with surviving keystore state (grown-from-
	// standalone shape): provisioning must fail closed, never fork a root.
	require.NoError(t, os.RemoveAll(dataDir))
	p2, err := New(firstNodeOptions(t, dataDir, backends), testLogger())
	require.NoError(t, err)
	_, err = p2.Provision(context.Background())
	var growthErr *ErrExistingCAWithoutStagedCerts
	require.ErrorAs(t, err, &growthErr)
	assert.Equal(t, "Cluster Test Root CA", growthErr.Identity)
}

// ---------------------------------------------------------------------------
// Joiner guards
// ---------------------------------------------------------------------------

func TestEnrollJoiner_RequiresDirectoryURLAndTPM(t *testing.T) {
	base := func() *Options {
		return &Options{
			RaftAddress: "127.0.0.1:8302",
			TrustDomain: "test.cluster",
			DataDir:     t.TempDir(),
			ACME:        &ACMEOptions{},
			Backends:    softwareBackends(t),
			Bootstrap:   clusterenrollBootstrap(),
		}
	}

	// Missing directory URL.
	p, err := New(base(), testLogger())
	require.NoError(t, err)
	_, err = p.Provision(context.Background())
	var missing *ErrMissingOption
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "ACME.DirectoryURL", missing.Field)

	// Non-tpm2 backend: the CSR variant is not implemented yet.
	opts := base()
	opts.ACME.DirectoryURL = "https://node1:8443/api/v1/acme/directory"
	p, err = New(opts, testLogger())
	require.NoError(t, err)
	_, err = p.Provision(context.Background())
	var unsupported *ErrACMEBackendUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, "software", unsupported.KeyBackend)
}
