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

package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gocsp "golang.org/x/crypto/ocsp"
)

// go-xkms#1116: revocation state replicates through ca.revocationStore, but
// IsRevoked, Verify and CRL generation used to read only the in-memory map,
// which is filled at Load and by this instance's own revocations. A
// certificate revoked on one cluster node therefore stayed valid on every
// other node. These tests model a cluster as two *CA instances over one
// shared in-memory revocation store, and drive every read path through a
// fault-injecting store to prove each one fails closed.

// errRevocationFault is the injected storage fault.
var errRevocationFault = errors.New("revocation_cluster_test: store unavailable")

// revocationFaultStore wraps a storage.Backend and fails Get for keys the
// failGet predicate selects, every Scan when failScan is set, and
// PutIfAbsent for keys the failPutIfAbsent predicate selects. All other
// calls delegate unchanged.
type revocationFaultStore struct {
	storage.Backend
	failGet         func(key string) bool
	failScan        bool
	failPutIfAbsent func(key string) bool
}

func (f *revocationFaultStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet != nil && f.failGet(key) {
		return nil, errRevocationFault
	}
	return f.Backend.Get(ctx, key)
}

func (f *revocationFaultStore) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.failScan {
		return errRevocationFault
	}
	return f.Backend.Scan(ctx, prefix, fn)
}

func (f *revocationFaultStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.failPutIfAbsent != nil && f.failPutIfAbsent(key) {
		return false, errRevocationFault
	}
	return f.Backend.PutIfAbsent(ctx, key, value)
}

// failKeysWithPrefix returns a failGet predicate selecting keys under prefix.
func failKeysWithPrefix(prefix string) func(string) bool {
	return func(key string) bool { return strings.HasPrefix(key, prefix) }
}

// newClusterPeer returns a second *CA over node's CA certificates, keys and
// revocation store -- another cluster node -- loaded before any revocation
// it is asked about, so its in-memory map cannot already hold one.
func newClusterPeer(t *testing.T, node *CA) *CA {
	t.Helper()
	peer := newUnloadedPeer(node, node.revocationStore)
	require.NoError(t, peer.Load(context.Background()))
	return peer
}

// newUnloadedPeer returns a second *CA sharing node's certificates and keys
// over the given revocation store, without calling Load.
func newUnloadedPeer(node *CA, revocationStore storage.Backend) *CA {
	return &CA{
		keyStore:        node.keyStore,
		keystoreMap:     node.keystoreMap,
		certStore:       node.certStore,
		config:          node.config,
		revocationStore: revocationStore,
		revocations:     make(map[string]*RevocationInfo),
	}
}

// issueTestCert issues a leaf certificate from ca for cn.
func issueTestCert(t *testing.T, ca *CA, cn string) *x509.Certificate {
	t.Helper()
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: cn},
		Valid:   365,
	})
	require.NoError(t, err)
	require.NotNil(t, issued.Certificate)
	return issued.Certificate
}

// crlSerials returns the revoked serials, in decimal, listed in crlDER.
func crlSerials(t *testing.T, crlDER []byte) []string {
	t.Helper()
	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	serials := make([]string, 0, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		serials = append(serials, e.SerialNumber.Text(10))
	}
	return serials
}

// =============================================================================
// Cluster visibility
// =============================================================================

// TestCluster_RevocationOnA_EnforcedOnB is the go-xkms#1116 regression: a
// certificate revoked on node A must be refused by node B's IsRevoked and
// Verify, and listed in B's next CRL, although B loaded before the
// revocation and never saw it in its own map.
func TestCluster_RevocationOnA_EnforcedOnB(t *testing.T) {
	ctx := context.Background()
	nodeA := setupTestCA(t)
	nodeB := newClusterPeer(t, nodeA)

	cert := issueTestCert(t, nodeA, "cluster-revoked.example.com")
	_, err := nodeB.Verify(cert)
	require.NoError(t, err, "precondition: B accepts the certificate before revocation")

	require.NoError(t, nodeA.RevokeCert(ctx, cert, RevokeOptions{Reason: ReasonKeyCompromise}))

	revoked, err := nodeB.IsRevoked(cert.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked, "B must see the revocation recorded on A")

	_, err = nodeB.Verify(cert)
	assert.ErrorIs(t, err, ErrCertificateRevoked)

	crlDER, err := nodeB.GenerateCRL(ctx)
	require.NoError(t, err)
	assert.Contains(t, crlSerials(t, crlDER), cert.SerialNumber.Text(10))
}

// TestCluster_CRLRegeneratedOnB_KeepsRevocationsFromA covers the overwrite
// half of go-xkms#1116: B's revocation regenerates the shared crl/<ski>
// artifact, which must still list what A revoked.
func TestCluster_CRLRegeneratedOnB_KeepsRevocationsFromA(t *testing.T) {
	ctx := context.Background()
	nodeA := setupTestCA(t)
	nodeB := newClusterPeer(t, nodeA)

	certA := issueTestCert(t, nodeA, "revoked-on-a.example.com")
	certB := issueTestCert(t, nodeA, "revoked-on-b.example.com")
	require.NoError(t, nodeA.RevokeCert(ctx, certA, RevokeOptions{}))
	require.NoError(t, nodeB.RevokeCert(ctx, certB, RevokeOptions{}))

	issuing, err := nodeB.CACertificate()
	require.NoError(t, err)
	rec, err := nodeB.getCRLBlob(ctx, issuing.SubjectKeyId)
	require.NoError(t, err)

	serials := crlSerials(t, rec.DER)
	assert.Contains(t, serials, certA.SerialNumber.Text(10), "B's CRL must not drop A's revocation")
	assert.Contains(t, serials, certB.SerialNumber.Text(10))
}

// =============================================================================
// IsRevoked read-through
// =============================================================================

// TestIsRevoked_CachesStoreHitButNotMiss pins the caching rule: a miss is
// re-read every time (another node may revoke next), and a hit is cached,
// which is safe because revocation is permanent.
func TestIsRevoked_CachesStoreHitButNotMiss(t *testing.T) {
	ctx := context.Background()
	nodeA := setupTestCA(t)
	faults := &revocationFaultStore{Backend: nodeA.revocationStore}
	nodeB := newUnloadedPeer(nodeA, faults)
	require.NoError(t, nodeB.Load(ctx))

	serial := big.NewInt(1116)
	revoked, err := nodeB.IsRevoked(serial)
	require.NoError(t, err)
	require.False(t, revoked)
	nodeB.revocationsMutex.RLock()
	_, cachedMiss := nodeB.revocations[serial.Text(10)]
	nodeB.revocationsMutex.RUnlock()
	assert.False(t, cachedMiss, "a miss must never be cached")

	require.NoError(t, nodeA.Revoke(ctx, serial, ReasonSuperseded))

	revoked, err = nodeB.IsRevoked(serial)
	require.NoError(t, err)
	require.True(t, revoked)

	// With the store now failing, the cached hit still answers.
	faults.failGet = failKeysWithPrefix(revocationKeyPrefix)
	revoked, err = nodeB.IsRevoked(serial)
	require.NoError(t, err)
	assert.True(t, revoked)
}

// TestIsRevoked_StoreError_FailsClosed proves a store fault on the
// read-through is an error, never "not revoked", and that Verify refuses
// the certificate on it.
func TestIsRevoked_StoreError_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	cert := issueTestCert(t, ca, "store-fault.example.com")
	ca.revocationStore = &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: failKeysWithPrefix(revocationKeyPrefix),
	}

	revoked, err := ca.IsRevoked(cert.SerialNumber)
	require.ErrorIs(t, err, ErrStorageError)
	assert.ErrorIs(t, err, errRevocationFault)
	assert.False(t, revoked)

	chains, err := ca.Verify(cert)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Nil(t, chains)
}

// TestIsRevoked_CorruptRecord_FailsClosed proves an undecodable record for
// the serial is reported as ErrRevocationRecordCorrupt, never "not revoked".
func TestIsRevoked_CorruptRecord_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	serial := big.NewInt(4040)
	key := revocationKey(serial) + ".json"
	require.NoError(t, ca.revocationStore.Put(context.Background(), key, []byte("{truncated")))

	_, err := ca.IsRevoked(serial)
	require.ErrorIs(t, err, ErrRevocationRecordCorrupt)
	assert.Contains(t, err.Error(), key)
}

// =============================================================================
// CRL generation
// =============================================================================

// TestGenerateCRL_ListError_FailsClosed proves a revocation listing fault
// aborts CRL generation and publishes nothing.
func TestGenerateCRL_ListError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := setupTestCA(t)
	ca.revocationStore = &revocationFaultStore{Backend: ca.revocationStore, failScan: true}

	_, err := ca.GenerateCRL(ctx)
	require.ErrorIs(t, err, ErrCRLGenerationFailed)
	assert.ErrorIs(t, err, ErrStorageError)

	issuing, err := ca.CACertificate()
	require.NoError(t, err)
	_, err = ca.getCRLBlob(ctx, issuing.SubjectKeyId)
	assert.ErrorIs(t, err, ErrCRLNotFound, "no CRL may be published after a listing fault")
}

// TestGenerateCRL_CorruptRecord_FailsClosed proves a corrupt revocation
// record aborts CRL generation instead of dropping the serial.
func TestGenerateCRL_CorruptRecord_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	key := revocationKey(big.NewInt(77)) + ".json"
	require.NoError(t, ca.revocationStore.Put(context.Background(), key, []byte("not-json")))

	_, err := ca.GenerateCRL(context.Background())
	require.ErrorIs(t, err, ErrCRLGenerationFailed)
	assert.ErrorIs(t, err, ErrRevocationRecordCorrupt)
}

// TestNextCRLNumber_NotFound_StartsAtOne covers the one case allowed to
// start the sequence: no artifact has been published.
func TestNextCRLNumber_NotFound_StartsAtOne(t *testing.T) {
	ca := &CA{revocationStore: storage.NewMemory()}
	n, err := ca.nextCRLNumber(context.Background(), []byte{0x01})
	require.NoError(t, err)
	assert.Equal(t, int64(1), n.Int64())
}

// TestNextCRLNumber_Increments covers the normal path.
func TestNextCRLNumber_Increments(t *testing.T) {
	ctx := context.Background()
	ca := &CA{revocationStore: storage.NewMemory()}
	require.NoError(t, ca.putCRLBlob(ctx, []byte{0x01}, &persistedCRL{Number: "41"}))

	n, err := ca.nextCRLNumber(ctx, []byte{0x01})
	require.NoError(t, err)
	assert.Equal(t, int64(42), n.Int64())
}

// TestNextCRLNumber_StoreError_FailsClosed proves a store fault reading the
// previous number is an error, not a restart at 1 (a CRL number going
// backwards).
func TestNextCRLNumber_StoreError_FailsClosed(t *testing.T) {
	ca := &CA{revocationStore: &revocationFaultStore{
		Backend: storage.NewMemory(),
		failGet: failKeysWithPrefix(crlKeyPrefix),
	}}
	_, err := ca.nextCRLNumber(context.Background(), []byte{0x01})
	require.ErrorIs(t, err, ErrStorageError)
	assert.ErrorIs(t, err, errRevocationFault)
}

// TestNextCRLNumber_InvalidNumber_FailsClosed proves an unreadable persisted
// number is an error, not a restart at 1.
func TestNextCRLNumber_InvalidNumber_FailsClosed(t *testing.T) {
	for _, number := range []string{"", "not-a-number", "-3"} {
		t.Run(number, func(t *testing.T) {
			ctx := context.Background()
			ca := &CA{revocationStore: storage.NewMemory()}
			require.NoError(t, ca.putCRLBlob(ctx, []byte{0x01}, &persistedCRL{Number: number}))

			_, err := ca.nextCRLNumber(ctx, []byte{0x01})
			require.ErrorIs(t, err, ErrStorageError)
			assert.Contains(t, err.Error(), crlKey([]byte{0x01}))
		})
	}
}

// TestGenerateCRL_CRLNumberStoreError_FailsClosed proves generation aborts
// when the previous CRL number cannot be read.
func TestGenerateCRL_CRLNumberStoreError_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	ca.revocationStore = &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: failKeysWithPrefix(crlKeyPrefix),
	}

	_, err := ca.GenerateCRL(context.Background())
	require.ErrorIs(t, err, ErrCRLGenerationFailed)
	assert.ErrorIs(t, err, ErrStorageError)
}

// =============================================================================
// Load
// =============================================================================

// TestLoad_CorruptRevocationRecord_Fails proves Load refuses to bring up a
// CA over a corrupt revocation record, naming its key, rather than skipping
// the record and un-revoking the certificate.
func TestLoad_CorruptRevocationRecord_Fails(t *testing.T) {
	nodeA := setupTestCA(t)
	key := revocationKey(big.NewInt(9001)) + ".json"
	require.NoError(t, nodeA.revocationStore.Put(context.Background(), key, []byte("not-json")))

	peer := newUnloadedPeer(nodeA, nodeA.revocationStore)
	err := peer.Load(context.Background())
	require.ErrorIs(t, err, ErrRevocationRecordCorrupt)
	assert.Contains(t, err.Error(), key)
	assert.False(t, peer.IsInitialized())
}

// TestLoad_RevocationListError_Fails proves Load fails when the revocation
// records cannot be listed.
func TestLoad_RevocationListError_Fails(t *testing.T) {
	nodeA := setupTestCA(t)
	peer := newUnloadedPeer(nodeA, &revocationFaultStore{Backend: nodeA.revocationStore, failScan: true})

	err := peer.Load(context.Background())
	require.ErrorIs(t, err, ErrStorageError)
	assert.False(t, peer.IsInitialized())
}

// TestDecodeRevocationRecord covers the valid record and every corrupt shape,
// including a record whose serial does not match its key: accepting that
// would leave the serial the key names un-revoked.
func TestDecodeRevocationRecord(t *testing.T) {
	key := revocationKey(big.NewInt(12345)) + ".json"

	info, err := decodeRevocationRecord(key, []byte(`{"serial":"12345","reason":1,"revoked_at":"2026-01-01T00:00:00Z"}`))
	require.NoError(t, err)
	assert.Equal(t, int64(12345), info.SerialNumber.Int64())
	assert.Equal(t, 1, info.Reason)

	corrupt := map[string][]byte{
		"not json":        []byte("not-json"),
		"invalid serial":  []byte(`{"serial":"12x45"}`),
		"missing serial":  []byte(`{"reason":1}`),
		"serial mismatch": []byte(`{"serial":"54321"}`),
	}
	for name, data := range corrupt {
		t.Run(name, func(t *testing.T) {
			_, err := decodeRevocationRecord(key, data)
			require.ErrorIs(t, err, ErrRevocationRecordCorrupt)
			assert.Contains(t, err.Error(), key)
		})
	}
}

// =============================================================================
// VerifyPeerCertificate
// =============================================================================

// TestVerifyPeerCertificate_RevocationCheckError_FailsClosed proves a peer
// certificate whose revocation status cannot be read is refused.
func TestVerifyPeerCertificate_RevocationCheckError_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	cert := issueTestCert(t, ca, "peer-fault.example.com")
	ca.revocationStore = &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: failKeysWithPrefix(revocationKeyPrefix),
	}

	err := ca.VerifyPeerCertificate([][]byte{cert.Raw}, nil)
	require.ErrorIs(t, err, ErrPeerVerificationFailed)
	assert.ErrorIs(t, err, ErrStorageError)
}

// TestVerifyPeerCertificate_IntermediateRevocationCheckError_FailsClosed
// proves the same for a chain certificate: only the intermediate's record
// is unreadable, and the chain is still refused.
func TestVerifyPeerCertificate_IntermediateRevocationCheckError_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	leaf := issueTestCert(t, ca, "peer-leaf.example.com")
	chainCert := issueTestCert(t, ca, "peer-chain.example.com")
	chainKey := revocationKey(chainCert.SerialNumber) + ".json"
	ca.revocationStore = &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: func(key string) bool { return key == chainKey },
	}

	err := ca.VerifyPeerCertificate([][]byte{leaf.Raw, chainCert.Raw}, nil)
	require.ErrorIs(t, err, ErrPeerVerificationFailed)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Contains(t, err.Error(), chainCert.SerialNumber.String())
}

// TestVerifyPeerCertificate_RevokedOnPeerNode proves VerifyPeerCertificate
// on node B refuses a certificate revoked on node A.
func TestVerifyPeerCertificate_RevokedOnPeerNode(t *testing.T) {
	nodeA := setupTestCA(t)
	nodeB := newClusterPeer(t, nodeA)
	cert := issueTestCert(t, nodeA, "peer-revoked.example.com")
	require.NoError(t, nodeA.RevokeCert(context.Background(), cert, RevokeOptions{}))

	err := nodeB.VerifyPeerCertificate([][]byte{cert.Raw}, nil)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

// =============================================================================
// OCSP
// =============================================================================

// TestOCSPCheckCertificateStatus_StoreError_FailsClosed proves the OCSP
// responder, which shares IsRevoked's read path, answers Unknown with
// ErrOCSPStorageError -- keeping the storage cause -- rather than Good.
func TestOCSPCheckCertificateStatus_StoreError_FailsClosed(t *testing.T) {
	ca := setupTestCA(t)
	ca.revocationStore = &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: failKeysWithPrefix(revocationKeyPrefix),
	}
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	status, _, _, err := responder.checkCertificateStatus(context.Background(), big.NewInt(31337))
	require.ErrorIs(t, err, ErrOCSPStorageError)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.Equal(t, gocsp.Unknown, status)
}
