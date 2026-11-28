package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newPeerGateAnchorRoot(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestAttestedCallerGate_ReadsTheLiveTrustRootStore covers Codex P1 (round
// 2): the xkmsd gate takes the anchor pools its policy leaves nil from the
// persisted trust-root store (docs/SPEC.md trust-roots), read on every
// verification, so a store-only root configures the gate and quarantining
// or removing it withdraws it at once.
func TestAttestedCallerGate_ReadsTheLiveTrustRootStore(t *testing.T) {
	policy := testAttestedCallerPolicy()
	policy.Quote.Anchors = nil // store-only anchors
	s := newPeerGateTestServer(t, &config.AttestationConfig{PeerGate: "required"}, WithAttestedCallerPolicy(policy))

	_, err := s.attestedCallerNodeOptions()
	require.NoError(t, err, "a policy without anchors builds a gate over the store")
	require.NotNil(t, s.peerGate)

	source := s.attestedCallerAnchorSource()
	_, err = source(t.Context())
	require.Error(t, err, "until the store opens the gate stays undecided")

	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	idevid := newPeerGateAnchorRoot(t, "idevid issuer")
	require.NoError(t, store.Add(t.Context(), idevid,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeIDevIDIssuer}))
	require.NoError(t, store.Add(t.Context(), newPeerGateAnchorRoot(t, "user ca"),
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeUserCA}))
	s.peerTrustRoots.Store(store)

	only := func(certs ...*x509.Certificate) *x509.CertPool {
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		return pool
	}
	current := func() *x509.CertPool {
		pool, err := source(t.Context())
		require.NoError(t, err)
		return pool
	}
	require.True(t, only(idevid).Equal(current()), "a store-only root is trusted")

	_, err = store.SetPurpose(t.Context(), truststore.Fingerprint(idevid), truststore.PurposeSynced)
	require.NoError(t, err)
	assert.True(t, only().Equal(current()), "a quarantined root is withdrawn at once")

	imported := newPeerGateAnchorRoot(t, "imported issuer")
	require.NoError(t, store.Add(t.Context(), imported,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeIDevIDIssuer}))
	require.True(t, only(imported).Equal(current()))
	require.NoError(t, store.Delete(t.Context(), truststore.Fingerprint(imported)))
	assert.True(t, only().Equal(current()), "a removed root is withdrawn at once")
}
