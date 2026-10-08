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
//    Contact licensing@automatethettings.com for commercial licensing options.

package clusterca

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

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// singleBackendFactory returns a ca.BackendForStoreFunc that resolves every
// StoreType to the same backend — the explicit, canonical choice for a
// fixture with one uniform backend.
func singleBackendFactory(b xkms.Backend) ca.BackendForStoreFunc {
	return func(string, types.StoreType) (xkms.Backend, error) {
		return b, nil
	}
}

// clusterIntermediateCN is the cluster intermediate identity in clusterCAConfig().
const clusterIntermediateCN = "Cluster Test Cluster CA"

// issueLeafFrom issues a short-lived leaf certificate from the CA identity named
// cn and returns it — proving the node holding this CA can issue.
func issueLeafFrom(t *testing.T, ctx context.Context, c ca.TrustedCA, cn string) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	signer, issuerCert, err := c.(ca.IdentityIssuer).IssuerForIdentity(ctx, cn)
	require.NoError(t, err, "resolve issuer %q", cn)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "node-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, leafKey.Public(), signer)
	require.NoError(t, err, "issue leaf from %q", cn)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf, issuerCert
}

// TestBarrierStrategy_AnyNodeIssues is the end-to-end proof of the barrier
// strategy's core property: a cluster CA key created node-local on the FIRST
// node is promoted into the replicated store, and a SECOND node loads it and can
// issue certificates that chain to the same cluster trust anchor. This is what
// "any node can issue" means in practice.
func TestBarrierStrategy_AnyNodeIssues(t *testing.T) {
	ctx := context.Background()

	// The first node's node-local key store and the replicated store both nodes
	// share (in a real cluster the latter is the qrdb-routed, barrier-encrypted
	// datastore). The cert store is shared so the second node loads the first
	// node's issued CA certificates. In-memory stores are used so the promotion
	// mechanism can be exercised without the server's transaction servicer (a
	// full docker cluster covers that path — see test/integration/cluster).
	nodeLocalKeys := storage.NewMemory()
	replicatedKeys := storage.NewMemory()
	certStore, err := certstore.New(&certstore.Config{
		DAOs: testutil.NewMemoryDAOFactory(),
	})
	require.NoError(t, err)

	// --- First node: create the CA in its node-local store and issue. ---
	caConfigA := clusterCAConfig()
	backendA, err := newSoftwareBackend(nodeLocalKeys, storage.NewMemory())
	require.NoError(t, err)
	caA, err := ca.NewHierarchicalCA(&ca.MultiIdentityParams{
		Config:          caConfigA,
		KeyStore:        backendA,
		BackendForStore: singleBackendFactory(backendA),
		CertStore:       certStore,
		SerialGen:       ca.NewSerialGenerator(ca.NewMemoryStorage()),
		RevocationStore: storage.NewMemory(),
	})
	require.NoError(t, err)
	require.NoError(t, caA.Init(ctx), "first node CA init")

	leafA, clusterCertA := issueLeafFrom(t, ctx, caA, clusterIntermediateCN)
	require.Equal(t, clusterIntermediateCN, leafA.Issuer.CommonName)

	// Promote the node-local CA key blobs into the replicated store — the exact
	// mechanism barrierStrategy.RuntimeBackend uses.
	require.NoError(t, promoteKeyStorage(ctx, nodeLocalKeys, replicatedKeys))

	// --- Second node: load the promoted key from the replicated store, issue. ---
	caConfigB := clusterCAConfig()
	backendB, err := newSoftwareBackend(replicatedKeys, storage.NewMemory())
	require.NoError(t, err)
	caB, err := ca.NewHierarchicalCA(&ca.MultiIdentityParams{
		Config:          caConfigB,
		KeyStore:        backendB,
		BackendForStore: singleBackendFactory(backendB),
		CertStore:       certStore, // shared — has the first node's CA certs
		SerialGen:       ca.NewSerialGenerator(ca.NewMemoryStorage()),
		RevocationStore: storage.NewMemory(),
	})
	require.NoError(t, err)
	require.NoError(t, caB.Load(ctx), "second node must LOAD the promoted CA, not fork a new one")

	leafB, clusterCertB := issueLeafFrom(t, ctx, caB, clusterIntermediateCN)
	require.Equal(t, clusterIntermediateCN, leafB.Issuer.CommonName)

	// The second node signed with the SAME cluster intermediate key it loaded
	// from the replicated store — so both nodes' leaves chain to one anchor.
	require.Equal(t, clusterCertA.Raw, clusterCertB.Raw,
		"both nodes must use the same promoted cluster intermediate certificate/key")

	root, err := caB.TrustedRoot()
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	inter.AddCert(clusterCertB)

	for name, leaf := range map[string]*x509.Certificate{"first-node": leafA, "second-node": leafB} {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		require.NoError(t, err, "%s leaf must verify to the shared cluster root", name)
	}
}
