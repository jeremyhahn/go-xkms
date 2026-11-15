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
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
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

// TestAttestedCallerAnchors_FromPersistedStore: a gate policy given no
// anchors takes the persisted store's IDevID-issuer roots as both its quote
// and its device-identity anchors, and no root filed under another purpose.
func TestAttestedCallerAnchors_FromPersistedStore(t *testing.T) {
	idevid := newAnchorsTestRoot(t, "idevid issuer")
	other := newAnchorsTestRoot(t, "user ca")
	store := newAnchorsTestStore(t, idevid, other)

	policy := testAttestedCallerPolicy()
	policy.Quote.Anchors = nil
	policy.DeviceIdentity = &peer.DevIDPolicy{}

	got, err := attestedCallerAnchors(policy, store)
	require.NoError(t, err)

	want := x509.NewCertPool()
	want.AddCert(idevid)
	require.NotNil(t, got.Quote.Anchors)
	require.NotNil(t, got.DeviceIdentity)
	require.NotNil(t, got.DeviceIdentity.Anchors)
	assert.True(t, want.Equal(got.Quote.Anchors), "quote anchors are the IDevID-issuer roots")
	assert.True(t, want.Equal(got.DeviceIdentity.Anchors), "device-identity anchors are the IDevID-issuer roots")
	assert.Nil(t, policy.DeviceIdentity.Anchors, "the caller's policy is not mutated")
}

// TestAttestedCallerAnchors_KeepsGivenAnchors: anchors the embedder gave
// win over the store.
func TestAttestedCallerAnchors_KeepsGivenAnchors(t *testing.T) {
	store := newAnchorsTestStore(t, newAnchorsTestRoot(t, "idevid issuer"), newAnchorsTestRoot(t, "user ca"))

	given := x509.NewCertPool()
	given.AddCert(newAnchorsTestRoot(t, "embedder root"))
	policy := testAttestedCallerPolicy()
	policy.Quote.Anchors = given
	policy.DeviceIdentity = &peer.DevIDPolicy{Anchors: given}

	got, err := attestedCallerAnchors(policy, store)
	require.NoError(t, err)
	assert.Same(t, given, got.Quote.Anchors)
	assert.Same(t, given, got.DeviceIdentity.Anchors)
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
