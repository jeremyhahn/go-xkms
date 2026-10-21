package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var errCustodyPutRefused = errors.New("storage: put refused")

// putRefusingStorage is a memory backend whose Put fails once refuse is set,
// so a barrier can be initialized over it and then made read-only.
type putRefusingStorage struct {
	storage.Backend
	refuse atomic.Bool
}

func (s *putRefusingStorage) Put(ctx context.Context, key string, value []byte) error {
	if s.refuse.Load() {
		return errCustodyPutRefused
	}
	return s.Backend.Put(ctx, key, value)
}

// newPutRefusingCustodyServer returns a server over an unsealed barrier
// whose storage refuses every write from now on.
func newPutRefusingCustodyServer(t *testing.T) *Server {
	t.Helper()
	base := &putRefusingStorage{Backend: storage.NewMemory()}
	cfg := seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}
	barrier, err := seal.NewBarrier(custodyQuietLogger(), base, cfg, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds, err := seal.CredentialsFor(t.Context(), []byte("test-system-pw"))
	require.NoError(t, err)
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	base.refuse.Store(true)
	return &Server{config: &config.Config{}, logger: custodyQuietLogger(), barrier: barrier}
}

func TestNoiseKeyCustody_BarrierPutErrorWraps(t *testing.T) {
	if !runUnderFIPS140(t, "off") {
		return
	}
	s := newPutRefusingCustodyServer(t)
	if !noiseRunnable() {
		requireNoiseRefused(t, s)
		return
	}

	key, err := s.loadNoiseStaticKey()
	require.Nil(t, key)
	var sealErr *ErrBarrierKeySeal
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, noiseStaticKeyBarrierKey, sealErr.Key)
	assert.ErrorIs(t, err, errCustodyPutRefused)
}

func TestP256KeyCustody_BarrierPutErrorWraps(t *testing.T) {
	s := newPutRefusingCustodyServer(t)

	key, err := s.loadP256StaticKey()
	require.Nil(t, key)
	var sealErr *ErrBarrierKeySeal
	require.ErrorAs(t, err, &sealErr)
	assert.Equal(t, p256StaticKeyBarrierKey, sealErr.Key)
	assert.ErrorIs(t, err, errCustodyPutRefused)
}
