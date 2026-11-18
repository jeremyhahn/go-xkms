//go:build tpm_simulator

package server

import (
	"context"
	"crypto/ecdsa"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The tpm2 backend lists system keys with an empty TenantID; the system
// tenant's login CA key must still be found, reused and listed.
func TestTenantCAKeyFactory_TPM2SystemKeyIsReused(t *testing.T) {
	ctx := context.Background()
	tpm, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "tenant-ca-test",
	})
	require.NoError(t, err)
	base, err := xkms.New(&xkms.BackendConfig{Backend: tpm, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })

	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(base, storage.New()))
	require.NoError(t, f.EnsureTenant(ctx, qrdbsdk.SystemTenantID))

	pub, cert := tenantLoginCA(t, f, qrdbsdk.SystemTenantID)
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(cert.PublicKey))

	// A later boot pass must find the key, not generate it again.
	require.NoError(t, f.EnsureTenant(ctx, qrdbsdk.SystemTenantID))
	again, _ := tenantLoginCA(t, f, qrdbsdk.SystemTenantID)
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(again), "the boot pass replaced the system login CA key")

	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ids, qrdbsdk.SystemTenantID)
}
