package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strategyFailBackend serves the sealed root key without its ciphertext
// while armed: the record still parses and names its strategy, so the
// failure happens inside the strategy's unseal, where go-qrdb reports it as
// a credential mismatch.
type strategyFailBackend struct {
	xkms.StorageBackend
	armed atomic.Bool
}

func (b *strategyFailBackend) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := b.StorageBackend.Get(ctx, key)
	if err != nil || !b.armed.Load() {
		return value, err
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(value, &record) != nil {
		return value, nil
	}
	if _, sealedRootKey := record["strategy"]; !sealedRootKey {
		return value, nil
	}
	delete(record, "ciphertext")
	return json.Marshal(record)
}

// A failure inside the barrier strategy is not proof that the barrier has
// a password of its own: the PIN change stops, the PIN stays and the
// barrier still opens with it.
func TestPINService_ChangeUserPIN_StrategyFailureAbortsPINChange(t *testing.T) {
	pins := &recordingPINBackend{mockPINBackend: &mockPINBackend{
		strategy:   qrdbsdk.PINStrategySoftware,
		userPINSet: true,
	}}
	svc := newTestPINService(pins)

	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	var store *strategyFailBackend
	barrierSvc.SetBaseBackendFactory(func(dir string) (xkms.StorageBackend, error) {
		base, err := xkms.StorageOpenEngine(xkms.StorageEngineConfig{Kind: xkms.StorageEngineFile, Path: dir})
		if err != nil {
			return nil, err
		}
		store = &strategyFailBackend{StorageBackend: base}
		return store, nil
	})
	require.NoError(t, barrierSvc.Initialize("old-pin", "passphrase"))
	require.NotNil(t, store)
	svc.SetBarrierService(barrierSvc)

	store.armed.Store(true)
	require.Error(t, svc.ChangeUserPIN("old-pin", "new-pin"))
	assert.Empty(t, pins.changes, "no PIN may be committed when the barrier check failed")
	store.armed.Store(false)

	// PIN and barrier stay together on the old PIN.
	bound, err := barrierSvc.PasswordBound("old-pin")
	require.NoError(t, err)
	assert.True(t, bound, "the barrier must still open with the unchanged PIN")
}
