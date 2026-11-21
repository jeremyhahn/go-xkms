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

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// quarantineTestApplications is a configured allow-list, so LoadTrust in this
// file's tests reaches the quarantine behavior under test rather than the
// unrelated unconfigured-policy refusal (#1305).
func quarantineTestApplications() pairing.ApplicationPolicy {
	return pairing.ApplicationPolicy{AllowedApplications: []pairing.AllowedApplication{{
		PackageName:    "com.automatethethings.xkey",
		SigningDigests: []string{"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"},
	}}}
}

// quarantineCA is a generated CA plus its key, so a test can issue a chain
// under it and ask whether the trust store lets that chain verify.
type quarantineCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newQuarantineCA mints a self-signed CA with the given subject.
func newQuarantineCA(t *testing.T, subject pkix.Name) *quarantineCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &quarantineCA{cert: cert, key: key}
}

// issueLeaf issues a leaf certificate under ca.
func (ca *quarantineCA) issueLeaf(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// pemOf PEM-encodes a certificate.
func pemOf(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// newQuarantineSyncService wires a real file trust store into a real sync
// service through the production trustStoreAdapter, exactly as
// openSyncService does.
func newQuarantineSyncService(t *testing.T) (*xkeysync.Service, *truststore.FileStore) {
	t.Helper()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	svc, err := xkeysync.NewService(&xkeysync.Config{DeviceName: "test-laptop"},
		xkeysync.WithTrustStore(&trustStoreAdapter{store: store}))
	require.NoError(t, err)
	return svc, store
}

// TestSyncTrustStore_ForgedGoogleRootAnchorsNothing is issue #1304 end to
// end: a paired phone syncs a self-signed CA dressed as a Google hardware
// attestation root, and a self-signed CA of its own. Neither may anchor
// anything on the laptop: not Android attestation (attestation.LoadTrust),
// and not TLS (TLSRoots).
func TestSyncTrustStore_ForgedGoogleRootAnchorsNothing(t *testing.T) {
	svc, store := newQuarantineSyncService(t)

	forged := newQuarantineCA(t, pkix.Name{
		CommonName:   "Google Hardware Attestation Root",
		Organization: []string{"Google LLC"},
	})
	planted := newQuarantineCA(t, pkix.Name{CommonName: "Phone Planted CA", Organization: []string{"Phone"}})

	applied, err := svc.ApplyTrustStoreDelta(&xkeysync.TrustStoreDelta{
		Certificates: []xkeysync.TrustStoreCertSync{
			{PEM: pemOf(forged.cert), Fingerprint: truststore.Fingerprint(forged.cert)},
			{PEM: pemOf(planted.cert), Fingerprint: truststore.Fingerprint(planted.cert)},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 2, applied.Added)

	for _, ca := range []*quarantineCA{forged, planted} {
		meta, err := store.Metadata(truststore.Fingerprint(ca.cert))
		require.NoError(t, err)
		assert.Equal(t, truststore.PurposeSynced, meta.Purpose, "%s", ca.cert.Subject)
	}

	trust, err := attestation.LoadTrust(store, quarantineTestApplications())
	require.NoError(t, err)
	_, err = forged.issueLeaf(t, "attested.example.com").Verify(x509.VerifyOptions{
		Roots:     trust.Roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, err, &unknownAuthority, "a synced forged root must not anchor Android attestation")

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	assert.Empty(t, roots, "a synced self-signed CA must not be a TLS anchor")
}

// TestSyncCADelta_CAAndChainAreQuarantined covers the CA sync path: the
// synced CA certificate and its chain land in the same quarantine.
func TestSyncCADelta_CAAndChainAreQuarantined(t *testing.T) {
	svc, store := newQuarantineSyncService(t)

	ca := newQuarantineCA(t, pkix.Name{CommonName: "Synced Issuing CA"})
	chain := newQuarantineCA(t, pkix.Name{CommonName: "Synced Chain Root"})

	applied, err := svc.ApplyCADelta(&xkeysync.CADelta{
		CACertPEM:  pemOf(ca.cert),
		CAChainPEM: pemOf(chain.cert),
	})
	require.NoError(t, err)
	require.Equal(t, 2, applied.Added)

	synced, err := store.CertificatesByPurpose(truststore.PurposeSynced)
	require.NoError(t, err)
	assert.Len(t, synced, 2)

	roots, err := store.TLSRoots()
	require.NoError(t, err)
	assert.Empty(t, roots)
}

// TestTrustStoreAdapter_ImportPEMRejectsInvalidPEM pins that the sync write
// path surfaces a bundle with no certificate as an error instead of reporting
// an empty success.
func TestTrustStoreAdapter_ImportPEMRejectsInvalidPEM(t *testing.T) {
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()

	result, err := (&trustStoreAdapter{store: store}).ImportPEM([]byte("not a certificate"),
		&truststore.AddCertificateOptions{Purpose: truststore.PurposeSynced})
	require.Error(t, err)
	assert.Equal(t, truststore.ImportResult{}, result)
}
