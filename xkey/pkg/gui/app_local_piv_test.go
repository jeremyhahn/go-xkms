package gui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
)

var errOpenStoreRefused = errors.New("open store refused")

// resetPIVManager clears the process-global PIV manager before and after
// a test, because initLocalPIV initializes it exactly once per process.
func resetPIVManager(t *testing.T) {
	t.Helper()
	xkmssdk.XKMSResetPIV()
	t.Cleanup(xkmssdk.XKMSResetPIV)
}

// newPIVTestCert returns a self-signed certificate suitable for storing in
// a PIV slot.
func newPIVTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "piv-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// slotHasCert reports whether the PIV manager shows a certificate in slot
// for the given backend.
func slotHasCert(t *testing.T, backend string, slot xkmssdk.PIVSlot) bool {
	t.Helper()
	resp, err := xkmssdk.ListPIVSlots(context.Background(), &xkmssdk.ListPIVSlotsRequest{Backend: backend})
	require.NoError(t, err)
	for _, s := range resp.Slots {
		if s.Slot == slot.String() {
			return s.HasCert
		}
	}
	t.Fatalf("slot %s not listed for backend %q", slot, backend)
	return false
}

func TestInitLocalPIV_EmptyDirDisablesPIV(t *testing.T) {
	resetPIVManager(t)

	opened := false
	store, backend, ok := initLocalPIV(lifecycleTestLogger(), "", nil, []string{"software"}, nil,
		func(string) (xkmssdk.StorageBackend, error) {
			opened = true
			return xkmssdk.NewStorageMemory(), nil
		})

	assert.False(t, ok)
	assert.Nil(t, store)
	assert.Nil(t, backend)
	assert.False(t, opened, "no store may be opened without a data directory")
}

func TestInitLocalPIV_OpenStoreErrorDisablesPIV(t *testing.T) {
	resetPIVManager(t)
	dir := t.TempDir()

	var openedPath string
	store, backend, ok := initLocalPIV(lifecycleTestLogger(), dir, nil, []string{"software"}, nil,
		func(path string) (xkmssdk.StorageBackend, error) {
			openedPath = path
			return nil, errOpenStoreRefused
		})

	assert.False(t, ok)
	assert.Nil(t, store)
	assert.Nil(t, backend)
	assert.Equal(t, filepath.Join(dir, "piv"), openedPath, "the PIV store lives under <dataDir>/piv")
	info, err := os.Stat(openedPath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestInitLocalPIV_UncreatableDirDisablesPIV(t *testing.T) {
	resetPIVManager(t)
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))

	opened := false
	_, _, ok := initLocalPIV(lifecycleTestLogger(), notADir, nil, nil, nil,
		func(string) (xkmssdk.StorageBackend, error) {
			opened = true
			return xkmssdk.NewStorageMemory(), nil
		})

	assert.False(t, ok)
	assert.False(t, opened, "no store may be opened when the PIV directory cannot be created")
}

func TestInitLocalPIV_WithoutBarrierUsesOpenedStore(t *testing.T) {
	resetPIVManager(t)
	opened := xkmssdk.NewStorageMemory()

	store, backend, ok := initLocalPIV(lifecycleTestLogger(), t.TempDir(), nil, nil, nil,
		func(string) (xkmssdk.StorageBackend, error) { return opened, nil })

	require.True(t, ok)
	require.NotNil(t, store)
	assert.Same(t, opened, backend, "without a barrier the opened file store backs PIV")

	// "software" is always registered, even when no backend IDs are given.
	require.NoError(t, store.Store(xkmssdk.PIVSlotAuthentication, newPIVTestCert(t)))
	assert.True(t, slotHasCert(t, "software", xkmssdk.PIVSlotAuthentication))
}

func TestInitLocalPIV_BarrierBackendIsolatesBackends(t *testing.T) {
	resetPIVManager(t)
	barrier := xkmssdk.NewStorageMemory()

	registry := backendregistry.NewMemoryRegistry()
	require.NoError(t, registry.Register(&backendregistry.RegisteredBackend{
		ID:          "tpm2-main",
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategoryTPM2,
		DisplayName: "TPM 2.0",
	}))

	opened := false
	store, backend, ok := initLocalPIV(lifecycleTestLogger(), t.TempDir(), barrier,
		[]string{"software", "tpm2-main"}, registry,
		func(string) (xkmssdk.StorageBackend, error) {
			opened = true
			return xkmssdk.NewStorageMemory(), nil
		})

	require.True(t, ok)
	assert.Same(t, barrier, backend, "the barrier backend must back PIV when present")
	assert.False(t, opened, "no plain file store may be opened while the barrier is active")

	require.NoError(t, store.Store(xkmssdk.PIVSlotAuthentication, newPIVTestCert(t)))

	assert.True(t, slotHasCert(t, "software", xkmssdk.PIVSlotAuthentication),
		"the software backend reads the root store")
	assert.False(t, slotHasCert(t, "tpm2-main", xkmssdk.PIVSlotAuthentication),
		"a registered non-software backend must not see software certificates")
	assert.False(t, slotHasCert(t, "tpm2", xkmssdk.PIVSlotAuthentication),
		"the backend's category alias shares its namespaced store")
	assert.False(t, slotHasCert(t, "pkcs11-added-later", xkmssdk.PIVSlotAuthentication),
		"a backend created on demand gets its own namespace")
}
