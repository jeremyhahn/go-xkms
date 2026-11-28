package server

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newSharedTenantCANodes returns two factories that share one key backend and
// one claims store, like two cluster nodes over the same go-qrdb data.
func newSharedTenantCANodes(t *testing.T) (*tenantCAKeyFactory, *tenantCAKeyFactory, xkms.Backend, storage.Backend) {
	t.Helper()
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })
	claims := storage.New()
	f1 := newTenantCAKeyFactory()
	require.NoError(t, f1.Bind(base, claims))
	f2 := newTenantCAKeyFactory()
	require.NoError(t, f2.Bind(base, claims))
	return f1, f2, base, claims
}

func storedTenantLoginCADER(t *testing.T, base xkms.Backend, tenantID string) []byte {
	t.Helper()
	cert, err := xkms.NewTenantScopedBackend(base, tenantID).GetCert(context.Background(), tenantLoginCAKeyCN)
	require.NoError(t, err)
	require.NotNil(t, cert)
	return cert.Raw
}

// Two passes that both find the certificate missing must end on the
// certificate the first to publish stored: that one may already be in a
// listener's trust snapshot.
func TestTenantCAKeyFactory_ConcurrentCertRepairKeepsFirstPublished(t *testing.T) {
	ctx := context.Background()
	f1, f2, base, _ := newSharedTenantCANodes(t)
	const tenant = "tenant-a"
	require.NoError(t, f1.EnsureTenant(ctx, tenant))
	require.NoError(t, xkms.NewTenantScopedBackend(base, tenant).DeleteCert(ctx, tenantLoginCAKeyCN))

	paused := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	prev := tenantLoginCACertPublishHook
	tenantLoginCACertPublishHook = func(string) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(paused)
			<-release
		}
	}
	t.Cleanup(func() { tenantLoginCACertPublishHook = prev })

	pass1 := make(chan error, 1)
	go func() { pass1 <- f1.EnsureTenant(ctx, tenant) }()
	select {
	case <-paused:
	case <-time.After(30 * time.Second):
		t.Fatal("pass 1 never reached the certificate publish")
	}

	require.NoError(t, f2.EnsureTenant(ctx, tenant))
	firstReturned := storedTenantLoginCADER(t, base, tenant)

	close(release)
	select {
	case err := <-pass1:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("pass 1 did not finish")
	}
	final := storedTenantLoginCADER(t, base, tenant)
	require.True(t, bytes.Equal(firstReturned, final),
		"a later pass replaced the certificate the first pass published")
}
