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

//go:build integration

package piv

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-piv-" + t.Name()},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// TestPIVMultiBackend_CertificateIsolation verifies that certificates stored
// under one backend are NOT visible when listing another backend's slots.
// This is the regression test for the shared-storage bug where all backends
// shared a single PIV file store.
func TestPIVMultiBackend_CertificateIsolation(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Create separate namespaced stores for "software" and "tpm2" backends.
	baseBackend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, baseBackend.Close()) })

	softwareStore, err := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    baseBackend,
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err)

	tpm2NS, err := storage.NewPrefixBackend(baseBackend, "backends/tpm2/")
	require.NoError(t, err)
	tpm2Store, err := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    tpm2NS,
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err)

	// Initialize PIV manager with per-backend stores and a factory.
	xkms.ResetPIV()
	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": softwareStore,
			"tpm2":     tpm2Store,
		},
	})
	require.NoError(t, err)

	// Store a cert in software backend slot 9D.
	cert := generateTestCert(t)
	err = softwareStore.Store(pivcert.PIVSlotKeyManagement, cert)
	require.NoError(t, err)

	// Store a cert in tpm2 backend slot 9A.
	cert2 := generateTestCert(t)
	err = tpm2Store.Store(pivcert.PIVSlotAuthentication, cert2)
	require.NoError(t, err)

	// List software backend — should see 9D loaded, NOT 9A.
	softwareResp, err := xkms.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: "software",
	})
	require.NoError(t, err)

	var sw9D, sw9A *transport.PIVSlotStatus
	for i := range softwareResp.Slots {
		switch softwareResp.Slots[i].Slot {
		case "9d":
			sw9D = &softwareResp.Slots[i]
		case "9a":
			sw9A = &softwareResp.Slots[i]
		}
	}
	require.NotNil(t, sw9D, "software should have slot 9D")
	assert.True(t, sw9D.HasCert, "software 9D should have a certificate")
	require.NotNil(t, sw9A, "software should list slot 9A")
	assert.False(t, sw9A.HasCert, "software 9A should NOT have a certificate (belongs to tpm2)")

	// List tpm2 backend — should see 9A loaded, NOT 9D.
	tpm2Resp, err := xkms.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: "tpm2",
	})
	require.NoError(t, err)

	var t9A, t9D *transport.PIVSlotStatus
	for i := range tpm2Resp.Slots {
		switch tpm2Resp.Slots[i].Slot {
		case "9a":
			t9A = &tpm2Resp.Slots[i]
		case "9d":
			t9D = &tpm2Resp.Slots[i]
		}
	}
	require.NotNil(t, t9A, "tpm2 should have slot 9A")
	assert.True(t, t9A.HasCert, "tpm2 9A should have a certificate")
	require.NotNil(t, t9D, "tpm2 should list slot 9D")
	assert.False(t, t9D.HasCert, "tpm2 9D should NOT have a certificate (belongs to software)")
}

// TestPIVMultiBackend_LazyStoreFactory verifies that the store factory creates
// stores on demand for backends not pre-registered.
func TestPIVMultiBackend_LazyStoreFactory(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	baseBackend, err := filestorage.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, baseBackend.Close()) })

	// Initialize with only "software" pre-registered and a factory for others.
	softwareStore, err := pivfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    baseBackend,
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err)

	factory := func(backendName string) (pivcert.PIVCertificateStorage, error) {
		ns, nsErr := storage.NewPrefixBackend(baseBackend, "backends/"+backendName+"/")
		if nsErr != nil {
			return nil, nsErr
		}
		return pivfile.NewFileBackend(&pivcert.FileStorageConfig{
			Backend:    ns,
			DEREnabled: true,
			PEMEnabled: true,
		})
	}

	xkms.ResetPIV()
	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			"software": softwareStore,
		},
		StoreFactory: factory,
	})
	require.NoError(t, err)

	// Query "pkcs11" backend — not pre-registered but factory should create it.
	resp, err := xkms.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: "pkcs11",
	})
	require.NoError(t, err, "factory should create store on demand for pkcs11")
	assert.NotEmpty(t, resp.Slots, "should return standard PIV slots")

	// All slots should be empty (no certs stored yet).
	for _, slot := range resp.Slots {
		assert.False(t, slot.HasCert, "slot %s should be empty", slot.Slot)
		assert.Equal(t, "pkcs11", slot.Backend)
	}
}
