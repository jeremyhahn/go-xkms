// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package hardware

import (
	"context"
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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// The adapter deliberately does NOT claim storage.CompareAndDeleter, and the
// absence is the contract. Its write lock serialises only this process's
// callers; a PKCS#11 token or a TPM NV index has other writers (another
// process, another module, an administrator's tool) and offers no guarded
// primitive of its own, so a compare done here and a delete done there can
// have the record replaced between them and still report success. The
// contract requires the guard to be evaluated where the store serialises
// writes, and there is nowhere on the hardware to do that.
//
// Pinned as a type assertion so that adding the method back -- the
// plausible mistake, since every sibling backend has one -- fails here
// instead of advertising a guarantee the hardware cannot keep.
func TestHardwareBackendAdapter_DoesNotClaimCompareAndDeleter(t *testing.T) {
	adapter := NewHardwareBackendAdapter(newMockHardwareCertStorage(10))
	_, ok := adapter.(storage.CompareAndDeleter)
	assert.False(t, ok, "a guard this adapter evaluated would not be evaluated where the token's writes serialise")
	assert.Implements(t, (*storage.Backend)(nil), adapter)
}

// TestHardwareBackendAdapter_DeleteReleasesOnlyTheAddressedRecord pins the
// property the guarded delete rests on: deleting the certificate leaves the
// chain, and deleting the chain leaves the certificate.
func TestHardwareBackendAdapter_DeleteReleasesOnlyTheAddressedRecord(t *testing.T) {
	ctx := context.Background()
	const id = "paired-delete"
	leaf := generateTestCertForAdapter(t, "paired-delete-leaf")
	primary := generateTestCertForAdapter(t, "paired-delete-primary")

	t.Run("certificate delete leaves the chain", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)
		require.NoError(t, hw.SaveCert(id, primary))
		require.NoError(t, hw.SaveCertChain(id, []*x509.Certificate{leaf}))

		require.NoError(t, adapter.Delete(ctx, "certs/"+id+".pem"))
		_, err := hw.GetCert(id)
		assert.ErrorIs(t, err, storage.ErrNotFound)
		chain, err := hw.GetCertChain(id)
		require.NoError(t, err, "the chain is a separate record and stays")
		assert.Len(t, chain, 1)
	})

	t.Run("chain delete leaves the certificate", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)
		require.NoError(t, hw.SaveCert(id, primary))
		require.NoError(t, hw.SaveCertChain(id, []*x509.Certificate{leaf}))

		require.NoError(t, adapter.Delete(ctx, "certs/"+id+"-chain.pem"))
		_, err := hw.GetCertChain(id)
		assert.ErrorIs(t, err, storage.ErrNotFound)
		cert, err := hw.GetCert(id)
		require.NoError(t, err, "the certificate is a separate record and stays")
		assert.Equal(t, primary.Raw, cert.Raw)
	})

	t.Run("deleting an absent chain is not found", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)
		require.NoError(t, hw.SaveCert(id, primary))
		assert.ErrorIs(t, adapter.Delete(ctx, "certs/"+id+"-chain.pem"), storage.ErrNotFound)
		_, err := hw.GetCert(id)
		require.NoError(t, err, "a not-found chain delete touches nothing")
	})
}

// generateSmallTestCert returns a self-signed ECDSA P-256 certificate, small
// enough for two of them to share one TPM2 NV index.
func generateSmallTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// newHybridOverSimulatedTPM2 builds a hybrid store whose hardware side is the
// TPM2 simulator (one record per id) and whose external side is an in-memory
// backend, the overflow target.
func newHybridOverSimulatedTPM2(t *testing.T) (hybrid, hw, ext HardwareCertStorage) {
	t.Helper()
	tpm := newMockTPM(t)
	t.Cleanup(func() { _ = tpm.Close() })
	tpmStore, err := NewTPM2CertStorage(tpm, &TPM2CertStorageConfig{BaseIndex: 0x01800000, MaxCertSize: 4096})
	require.NoError(t, err)
	external := NewBackendCertStorageAdapter(storage.NewMemory())
	h, err := NewHybridCertStorage(tpmStore, external)
	require.NoError(t, err)
	return h, tpmStore, external
}

// Every hardware store refuses an id the chain encoding reserves, so the
// adapter's key space is unambiguous by construction: certs/foo-chain.pem can
// only ever be foo's chain, never a certificate whose id is foo-chain.
func TestReservedChainIDsAreRefusedByEveryStore(t *testing.T) {
	leaf := generateSmallTestCert(t, "reserved-leaf")
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()
	tpmStore, err := NewTPM2CertStorage(tpm, &TPM2CertStorageConfig{BaseIndex: 0x01800000, MaxCertSize: 4096})
	require.NoError(t, err)
	external := NewBackendCertStorageAdapter(storage.NewMemory())

	for name, store := range map[string]HardwareCertStorage{"tpm2": tpmStore, "external": external} {
		for _, id := range []string{"foo-chain", "foo-chain-0"} {
			require.ErrorIs(t, store.SaveCert(id, leaf), ErrIDReservedForChain, "%s SaveCert(%q)", name, id)
			require.ErrorIs(t, store.SaveCertChain(id, []*x509.Certificate{leaf}), ErrIDReservedForChain, "%s SaveCertChain(%q)", name, id)
		}
	}
	_, err = external.GetCert("foo-chain")
	require.ErrorIs(t, err, ErrIDReservedForChain)
	require.ErrorIs(t, external.DeleteCert("foo-chain"), ErrIDReservedForChain)
	_, err = external.CertExists("foo-chain-0")
	require.ErrorIs(t, err, ErrIDReservedForChain)

	// The reserved shapes are exactly what the adapter's keys spell, so a
	// chain saved through the adapter under foo remains reachable as foo's.
	adapter := NewHardwareBackendAdapter(external)
	ctx := context.Background()
	require.NoError(t, adapter.Put(ctx, "certs/foo.pem", leaf.Raw))
	require.NoError(t, adapter.Put(ctx, "certs/foo-chain.pem", leaf.Raw))
	chain, err := external.GetCertChain("foo")
	require.NoError(t, err)
	assert.Len(t, chain, 1)
}

// The external adapter lists certificate records only: a chain record's key,
// certs/<id>-chain.pem, names no certificate and must not surface as a
// phantom id of the reserved shape.
func TestBackendCertStorageAdapter_ListCertsOmitsChainRecords(t *testing.T) {
	leaf := generateSmallTestCert(t, "list-leaf")
	external := NewBackendCertStorageAdapter(storage.NewMemory())
	require.NoError(t, external.SaveCert("alpha", leaf))
	require.NoError(t, external.SaveCertChain("alpha", []*x509.Certificate{leaf}))
	require.NoError(t, external.SaveCertChain("chain-only", []*x509.Certificate{leaf}))

	ids, err := external.ListCerts()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"alpha"}, ids, "chain records are not certificates")
}

// On TPM2 an id has one NV index, and the record in it says whether it is a
// certificate or a chain, so each delete releases the record only when it is
// of its kind; a one-member chain is a chain, not a certificate.
func TestTPM2CertStorage_DeleteReleasesOnlyTheRecordOfItsKind(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()
	hw, err := NewTPM2CertStorage(tpm, &TPM2CertStorageConfig{BaseIndex: 0x01800000, MaxCertSize: 4096})
	require.NoError(t, err)
	leaf := generateSmallTestCert(t, "kind-leaf")
	issuer := generateSmallTestCert(t, "kind-issuer")

	require.NoError(t, hw.SaveCert("cert", leaf))
	require.ErrorIs(t, hw.DeleteCertChain("cert"), storage.ErrNotFound, "a certificate record is not a chain")
	_, err = hw.GetCertChain("cert")
	require.ErrorIs(t, err, storage.ErrNotFound, "nor is it read as a one-member chain")
	_, err = hw.GetCert("cert")
	require.NoError(t, err, "the certificate record is left in place")
	require.NoError(t, hw.DeleteCert("cert"))

	require.NoError(t, hw.SaveCertChain("one-member", []*x509.Certificate{leaf}))
	require.ErrorIs(t, hw.DeleteCert("one-member"), storage.ErrNotFound, "a one-member chain is a chain record")
	_, err = hw.GetCert("one-member")
	require.ErrorIs(t, err, storage.ErrNotFound, "and not a certificate")
	exists, err := hw.CertExists("one-member")
	require.NoError(t, err)
	assert.False(t, exists, "CertExists answers for certificate records only")
	chain, err := hw.GetCertChain("one-member")
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	require.NoError(t, hw.DeleteCertChain("one-member"))
	_, err = hw.GetCertChain("one-member")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// A listing names certificate records only: a chain record is absent to
	// the certificate reads, so a key made from its id could not be read.
	require.NoError(t, hw.SaveCert("listed-cert", leaf))
	require.NoError(t, hw.SaveCertChain("listed-chain-rec", []*x509.Certificate{leaf, issuer}))
	ids, err := hw.ListCerts()
	require.NoError(t, err)
	assert.Contains(t, ids, "listed-cert")
	assert.NotContains(t, ids, "listed-chain-rec", "a chain record is not a certificate")
	adapter := NewHardwareBackendAdapter(hw)
	keys, err := adapter.List(context.Background(), "certs/")
	require.NoError(t, err)
	assert.Contains(t, keys, "certs/listed-cert.pem")
	assert.NotContains(t, keys, "certs/listed-chain-rec.pem", "the adapter never lists a key it cannot read")
	require.NoError(t, adapter.Scan(context.Background(), "certs/", func(key string, value []byte) error {
		_, readErr := adapter.Get(context.Background(), key)
		return readErr
	}), "every listed key is readable")
	require.NoError(t, hw.DeleteCert("listed-cert"))
	require.NoError(t, hw.DeleteCertChain("listed-chain-rec"))

	// The index holds whichever wrote last, and its kind follows the write.
	require.NoError(t, hw.SaveCertChain("rewritten", []*x509.Certificate{leaf, issuer}))
	require.NoError(t, hw.SaveCert("rewritten", leaf))
	require.ErrorIs(t, hw.DeleteCertChain("rewritten"), storage.ErrNotFound)
	require.NoError(t, hw.DeleteCert("rewritten"))
	require.ErrorIs(t, hw.DeleteCert("rewritten"), storage.ErrNotFound, "absent is ErrNotFound, not success")
}

// A record written before the chain marker existed carries no header. More
// than one certificate in it can only be a chain; a single unmarked
// certificate is the certificate it also is.
func TestTPM2CertStorage_LegacyUnmarkedRecordsClassifyByMemberCount(t *testing.T) {
	tpm := newMockTPM(t)
	defer func() { _ = tpm.Close() }()
	store, err := NewTPM2CertStorage(tpm, &TPM2CertStorageConfig{BaseIndex: 0x01800000, MaxCertSize: 4096})
	require.NoError(t, err)
	hw, ok := store.(*TPM2CertStorage)
	require.True(t, ok)
	leaf := generateSmallTestCert(t, "legacy-leaf")
	issuer := generateSmallTestCert(t, "legacy-issuer")

	unmarked := func(certs ...*x509.Certificate) []byte {
		var out []byte
		for _, c := range certs {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		return out
	}
	hw.mu.Lock()
	require.NoError(t, hw.saveRecord("legacy-chain-rec", unmarked(leaf, issuer), "write"))
	require.NoError(t, hw.saveRecord("legacy-cert", unmarked(leaf), "write"))
	hw.mu.Unlock()

	require.ErrorIs(t, hw.DeleteCert("legacy-chain-rec"), storage.ErrNotFound)
	require.NoError(t, hw.DeleteCertChain("legacy-chain-rec"))
	require.ErrorIs(t, hw.DeleteCertChain("legacy-cert"), storage.ErrNotFound)
	require.NoError(t, hw.DeleteCert("legacy-cert"))
}

// The hybrid store over TPM2 needs no special case: each side answers for the
// record it holds, so a chain that overflowed to the external side is
// released there while the hardware certificate stays, a certificate that
// overflowed is released while the hardware chain stays, and a stale
// one-member chain on the hardware behind a newer external chain goes with
// the chain rather than surviving to reappear on the next read.
func TestHybridCertStorage_TPM2_ReleasesTheRecordOnWhicheverSideHoldsIt(t *testing.T) {
	hybrid, hw, ext := newHybridOverSimulatedTPM2(t)
	leaf := generateSmallTestCert(t, "hy-leaf")
	issuer := generateSmallTestCert(t, "hy-issuer")

	require.NoError(t, hw.SaveCert("overflowed", leaf))
	require.NoError(t, ext.SaveCertChain("overflowed", []*x509.Certificate{leaf, issuer}))
	chain, err := hybrid.GetCertChain("overflowed")
	require.NoError(t, err)
	assert.Len(t, chain, 2, "the hardware certificate does not hide the external chain")
	require.NoError(t, hybrid.DeleteCertChain("overflowed"))
	_, err = ext.GetCertChain("overflowed")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = hybrid.GetCertChain("overflowed")
	assert.ErrorIs(t, err, storage.ErrNotFound, "the hardware certificate does not resurface as a phantom chain")
	cert, err := hw.GetCert("overflowed")
	require.NoError(t, err, "the hardware certificate was never addressed")
	assert.Equal(t, leaf.Raw, cert.Raw)

	require.NoError(t, hw.SaveCertChain("overflowed-cert", []*x509.Certificate{leaf, issuer}))
	require.NoError(t, ext.SaveCert("overflowed-cert", leaf))
	require.NoError(t, hybrid.DeleteCert("overflowed-cert"))
	_, err = ext.GetCert("overflowed-cert")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	chain, err = hw.GetCertChain("overflowed-cert")
	require.NoError(t, err, "the hardware chain was never addressed")
	assert.Len(t, chain, 2)
	_, err = hybrid.GetCert("overflowed-cert")
	assert.ErrorIs(t, err, storage.ErrNotFound, "the hardware chain does not resurface as a phantom certificate")

	require.NoError(t, hw.SaveCertChain("stale", []*x509.Certificate{leaf}))
	require.NoError(t, ext.SaveCertChain("stale", []*x509.Certificate{leaf, issuer}))
	require.NoError(t, hybrid.DeleteCertChain("stale"))
	_, err = hw.GetCertChain("stale")
	assert.ErrorIs(t, err, storage.ErrNotFound, "the stale one-member hardware chain is a chain and goes with it")
	_, err = hybrid.GetCertChain("stale")
	assert.ErrorIs(t, err, storage.ErrNotFound, "the deleted chain does not reappear on the next read")

	require.NoError(t, hw.SaveCert("cert-only", leaf))
	require.ErrorIs(t, hybrid.DeleteCertChain("cert-only"), storage.ErrNotFound)
	_, err = hw.GetCert("cert-only")
	require.NoError(t, err)
	assert.ErrorIs(t, hybrid.DeleteCertChain("never"), storage.ErrNotFound)
	assert.ErrorIs(t, hybrid.DeleteCert("never"), storage.ErrNotFound)
}
