package server

import (
	"context"
	"crypto"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// RemoveTenant on one node while another node's pass holds the generating
// claim and has made the key but not yet published the certificate: once the
// pass resumes, no key and no certificate may remain, and no other
// provisioner may generate while the pass is still active.
func TestTenantCAKeyFactory_TeardownOverlappingProvisioningLeavesNothing(t *testing.T) {
	ctx := context.Background()
	f1, f2, base, claims := newSharedTenantCANodes(t)
	const tenant = "tenant-a"

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

	passA := make(chan error, 1)
	go func() { passA <- f1.EnsureTenant(ctx, tenant) }()
	select {
	case <-paused:
	case <-time.After(30 * time.Second):
		t.Fatal("pass A never reached the certificate publish")
	}

	require.NoError(t, f2.RemoveTenant(ctx, tenant))

	// A third provisioner while A is still active: refused, nothing made.
	f3 := newTenantCAKeyFactory()
	require.NoError(t, f3.Bind(base, claims))
	require.Error(t, f3.EnsureTenant(ctx, tenant), "a provisioner generated for a removed tenant")

	close(release)
	select {
	case err := <-passA:
		require.Error(t, err, "a pass overlapping teardown must fail")
	case <-time.After(30 * time.Second):
		t.Fatal("pass A did not finish")
	}
	assertNoTenantLoginCA(t, base, tenant)
}

// generateCountingBackend counts the keys generated through it.
type generateCountingBackend struct {
	xkms.Backend
	generated atomic.Int32
}

func (g *generateCountingBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	g.generated.Add(1)
	return g.Backend.GenerateECDSA(ctx, attrs)
}

// A pass that holds the generating claim but has not generated yet when
// teardown runs must not make a key at all: a key made after teardown is
// left behind if the pass then stops before its own cleanup.
func TestTenantCAKeyFactory_TeardownBeforeGenerateFencesTheKey(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		name := "teardown waits for the generate"
		if fenced {
			name = "operator-fenced holder never generates"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			_, f2, base, claims := newSharedTenantCANodes(t)
			const tenant = "tenant-a"
			counting := &generateCountingBackend{Backend: base}
			f1 := newTenantCAKeyFactory()
			require.NoError(t, f1.Bind(counting, claims))

			paused := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			prev := tenantLoginCAGenerateHook
			tenantLoginCAGenerateHook = func(string) {
				first := false
				once.Do(func() { first = true })
				if first {
					close(paused)
					<-release
				}
			}
			t.Cleanup(func() { tenantLoginCAGenerateHook = prev })

			passA := make(chan error, 1)
			go func() { passA <- f1.EnsureTenant(ctx, tenant) }()
			select {
			case <-paused:
			case <-time.After(30 * time.Second):
				t.Fatal("pass A never reached the key generation")
			}

			removed := make(chan error, 1)
			if fenced {
				holder := f2.tenantLoginCAClaimHolder(ctx, tenant)
				require.NotEmpty(t, holder)
				f2.FenceHolders([]string{holder})
				require.NoError(t, f2.RemoveTenant(ctx, tenant))
				close(removed)
			} else {
				go func() { removed <- f2.RemoveTenant(ctx, tenant) }()
				select {
				case err := <-removed:
					t.Fatalf("teardown returned while a generate was in flight: %v", err)
				case <-time.After(200 * time.Millisecond):
				}
			}

			close(release)
			select {
			case err := <-passA:
				require.Error(t, err, "a pass overlapping teardown must fail")
			case <-time.After(30 * time.Second):
				t.Fatal("pass A did not finish")
			}
			if !fenced {
				select {
				case err := <-removed:
					require.NoError(t, err)
				case <-time.After(30 * time.Second):
					t.Fatal("teardown did not finish after the generate returned")
				}
			} else {
				require.Zero(t, counting.generated.Load(), "a fenced pass generated a key after teardown")
			}
			f3 := newTenantCAKeyFactory()
			require.NoError(t, f3.Bind(base, claims))
			require.Error(t, f3.EnsureTenant(ctx, tenant), "a provisioner generated for a removed tenant")
			assertNoTenantLoginCA(t, base, tenant)
		})
	}
}
