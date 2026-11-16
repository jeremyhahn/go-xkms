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

package apimodule

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newAnchorsTestRoot returns a self-signed CA certificate named cn.
func newAnchorsTestRoot(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newAnchorsTestStore returns a persisted trust-root store holding idevid
// under PurposeIDevIDIssuer and other under PurposeUserCA.
func newAnchorsTestStore(t *testing.T, idevid, other *x509.Certificate) *truststore.DAOStore {
	t.Helper()
	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Add(t.Context(), idevid,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeIDevIDIssuer}))
	require.NoError(t, store.Add(t.Context(), other,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeUserCA}))
	return store
}

// TestAttestedCallerAnchors_FromPersistedStore: the gate's anchor source is
// the persisted store's IDevID-issuer roots, and no root filed under another
// purpose.
func TestAttestedCallerAnchors_FromPersistedStore(t *testing.T) {
	idevid := newAnchorsTestRoot(t, "idevid issuer")
	other := newAnchorsTestRoot(t, "user ca")
	store := newAnchorsTestStore(t, idevid, other)

	got, err := attestedCallerAnchors(store)(t.Context())
	require.NoError(t, err)
	want := x509.NewCertPool()
	want.AddCert(idevid)
	assert.True(t, want.Equal(got), "anchors are the IDevID-issuer roots")
}

// TestAttestedCallerAnchors_FollowsTheStore: quarantining, removing and
// importing a root change the very next answer of the anchor source.
func TestAttestedCallerAnchors_FollowsTheStore(t *testing.T) {
	idevid := newAnchorsTestRoot(t, "idevid issuer")
	store := newAnchorsTestStore(t, idevid, newAnchorsTestRoot(t, "user ca"))
	source := attestedCallerAnchors(store)
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
	require.True(t, only(idevid).Equal(current()))

	_, err := store.SetPurpose(t.Context(), truststore.Fingerprint(idevid), truststore.PurposeSynced)
	require.NoError(t, err)
	assert.True(t, only().Equal(current()), "a quarantined root is withdrawn at once")

	imported := newAnchorsTestRoot(t, "imported issuer")
	require.NoError(t, store.Add(t.Context(), imported,
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeIDevIDIssuer}))
	assert.True(t, only(imported).Equal(current()), "an imported root is trusted at once")

	require.NoError(t, store.Delete(t.Context(), truststore.Fingerprint(imported)))
	assert.True(t, only().Equal(current()), "a removed root is withdrawn at once")
}

// TestWithAttestedCallerGate_AnchorsFromTrustRootStore: a gate policy with
// no anchors builds over the host node's persisted trust-root store instead
// of being refused as anchorless.
func TestWithAttestedCallerGate_AnchorsFromTrustRootStore(t *testing.T) {
	client := newHostNodeClient(t)
	policy := testAttestedCallerPolicy()
	policy.Quote.Anchors = nil

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(func() *qrdbsdk.Client { return client }),
		WithAttestedCallerGate(policy))
	require.NoError(t, err)
	require.NotNil(t, m.PeerAttestationGate())
}

// TestWithAttestedCallerGate_AnchorsLoadOnFirstUse: NewModule runs before
// the host node exists (docs/attested-peer/api.md), so a gate without
// anchors builds while the client is still composing and opens the
// trust-root store only when a peer is verified.
func TestWithAttestedCallerGate_AnchorsLoadOnFirstUse(t *testing.T) {
	var resolved atomic.Pointer[qrdbsdk.Client]
	policy := testAttestedCallerPolicy()
	policy.Quote.Anchors = nil

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithQRDBClient(resolved.Load),
		WithAttestedCallerGate(policy))
	require.NoError(t, err, "the store is not opened at NewModule")
	require.NotNil(t, m.PeerAttestationGate())

	source := m.attestedCallerAnchorSource()
	_, err = source(t.Context())
	var composing *SurfaceComposingError
	require.ErrorAs(t, err, &composing, "no anchors until the host node resolves")

	resolved.Store(newHostNodeClient(t))
	pool, err := source(t.Context())
	require.NoError(t, err)
	assert.NotNil(t, pool)
}
