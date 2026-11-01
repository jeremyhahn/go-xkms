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

package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const faultTestPassword = "barrier-fault-test-password"

// faultStorage is a working in-memory storage backend that fails the
// operations a test names, so BarrierService's handling of a broken backend
// is observable without a broken disk. Close never closes the shared memory
// store, so one faultStorage can serve every createBaseBackend call of one or
// more services.
type faultStorage struct {
	xkms.StorageBackend
	existsErr error
	exists    bool
	putErr    error
	closeErr  error
	closes    atomic.Int32
}

func newFaultStorage() *faultStorage {
	return &faultStorage{StorageBackend: xkms.NewStorageMemory()}
}

func (f *faultStorage) Exists(ctx context.Context, key string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	if f.exists {
		return true, nil
	}
	return f.StorageBackend.Exists(ctx, key)
}

func (f *faultStorage) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.StorageBackend.Put(ctx, key, value)
}

func (f *faultStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.putErr != nil {
		return false, f.putErr
	}
	return f.StorageBackend.PutIfAbsent(ctx, key, value)
}

func (f *faultStorage) Close() error {
	f.closes.Add(1)
	return f.closeErr
}

// newFaultBarrierService returns a BarrierService over dataDir whose base
// backend is fs. failOnCall, when positive, makes that createBaseBackend call
// (1-based) fail with factoryErr instead.
func newFaultBarrierService(t *testing.T, dataDir string, fs *faultStorage, failOnCall int32, factoryErr error) *BarrierService {
	t.Helper()
	svc := NewBarrierService(dataDir, slog.Default())
	var calls atomic.Int32
	svc.SetBaseBackendFactory(func(string) (xkms.StorageBackend, error) {
		if calls.Add(1) == failOnCall {
			return nil, factoryErr
		}
		return fs, nil
	})
	return svc
}

// initializedFaultStorage initializes a passphrase barrier over a fresh
// faultStorage in dataDir and seals it, leaving a root key a second service
// on the same dataDir can unseal from.
func initializedFaultStorage(t *testing.T, dataDir string) *faultStorage {
	t.Helper()
	fs := newFaultStorage()
	first := newFaultBarrierService(t, dataDir, fs, 0, nil)
	require.NoError(t, first.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))
	require.NoError(t, first.Seal())
	return fs
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// The existing-directory preflight must refuse to continue when it cannot
// tell whether a root key exists, and still close the backend it opened.
func TestBarrierService_InitializePreflightExistsFailure(t *testing.T) {
	existsErr := errors.New("root key lookup failed")
	fs := newFaultStorage()
	fs.existsErr = existsErr
	fs.closeErr = errors.New("close failed")
	svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
	require.NoError(t, os.MkdirAll(svc.storageDir(), 0o700))

	err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

	require.ErrorIs(t, err, existsErr)
	assert.Equal(t, int32(1), fs.closes.Load())
	assert.False(t, svc.IsUnsealed())
}

// A root key found by the preflight reports ErrBarrierAlreadyInit even when
// closing the probe backend fails.
func TestBarrierService_InitializePreflightFindsRootKey(t *testing.T) {
	fs := newFaultStorage()
	fs.exists = true
	fs.closeErr = errors.New("close failed")
	svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
	require.NoError(t, os.MkdirAll(svc.storageDir(), 0o700))

	err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

	require.ErrorIs(t, err, ErrBarrierAlreadyInit)
	assert.False(t, svc.IsUnsealed())
}

// A failed close of the preflight backend is only a warning: an empty
// existing directory still initializes.
func TestBarrierService_InitializeSurvivesPreflightCloseFailure(t *testing.T) {
	fs := newFaultStorage()
	fs.closeErr = errors.New("close failed")
	svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
	require.NoError(t, os.MkdirAll(svc.storageDir(), 0o700))

	require.NoError(t, svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))

	assert.True(t, svc.IsUnsealed())
	assert.Equal(t, int32(1), fs.closes.Load(), "only the preflight backend is closed")
}

// When the barrier cannot store its root key, Initialize returns the storage
// error and the close error, and the service stays uninitialized. A failing
// audit log takes precedence, so a lost audit record is never hidden.
func TestBarrierService_InitializeRootKeyWriteFailure(t *testing.T) {
	putErr := errors.New("root key write failed")
	closeErr := errors.New("close failed")

	t.Run("returns storage and close errors", func(t *testing.T) {
		fs := newFaultStorage()
		fs.putErr = putErr
		fs.closeErr = closeErr
		rec := &spwRecordingAuditLogger{}
		svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
		svc.SetAuditLogger(rec)

		err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

		require.ErrorIs(t, err, putErr)
		require.ErrorIs(t, err, closeErr)
		assert.False(t, svc.IsUnsealed())
		require.NotEmpty(t, rec.entries)
		last := rec.last()
		assert.Equal(t, audit.OpBarrierInitialized, last.Operation)
		assert.False(t, last.Success)
		assert.NotEmpty(t, last.Error)
	})

	t.Run("audit failure wins", func(t *testing.T) {
		auditErr := errors.New("audit backend unavailable")
		fs := newFaultStorage()
		fs.putErr = putErr
		svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
		svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: auditErr})

		err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

		require.ErrorIs(t, err, auditErr)
		assert.False(t, svc.IsUnsealed())
	})
}

// A cancelled context stops Initialize before any key material is created.
func TestBarrierService_InitializeCanceledContext(t *testing.T) {
	fs := newFaultStorage()
	svc := newFaultBarrierService(t, t.TempDir(), fs, 0, nil)
	svc.SetContext(canceledContext())

	err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, svc.IsUnsealed())
	assert.Equal(t, int32(1), fs.closes.Load())
}

// When the success audit record cannot be written, Initialize reports it and
// skips the post-unseal hook, although the barrier itself is initialized.
func TestBarrierService_InitializeAuditFailureSkipsHook(t *testing.T) {
	auditErr := errors.New("audit backend unavailable")
	svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
	svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: auditErr})
	hookRan := false
	svc.SetPostUnsealHook(func() error {
		hookRan = true
		return nil
	})

	err := svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase))

	require.ErrorIs(t, err, auditErr)
	assert.True(t, svc.IsUnsealed())
	assert.False(t, hookRan)
}

// An external strategy factory that returns no strategy is reported as an
// unavailable strategy, not a nil dereference.
func TestBarrierService_InitializeExternalStrategyMissing(t *testing.T) {
	svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
	svc.SetExternalStrategyFunc(func(string) (xkms.SealingStrategy, error) {
		return nil, nil
	})

	err := svc.Initialize("", string(xkms.StrategyPKCS11))

	var unavailable *ErrBarrierStrategyUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, string(xkms.StrategyPKCS11), unavailable.Strategy)
}

// Re-unsealing the barrier this process sealed honours a cancelled context
// and leaves the barrier sealed.
func TestBarrierService_ReunsealCanceledContext(t *testing.T) {
	svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
	require.NoError(t, svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))
	require.NoError(t, svc.Seal())
	svc.SetContext(canceledContext())

	err := svc.Unseal(faultTestPassword, "")

	require.ErrorIs(t, err, context.Canceled)
	assert.True(t, svc.IsSealed())
}

// Unsealing a root key left by an earlier process: a working unseal runs the
// post-unseal hook, and each failure leaves the service sealed or reports
// what went wrong.
func TestBarrierService_UnsealFromStorage(t *testing.T) {
	t.Run("unseals and tolerates a failing hook", func(t *testing.T) {
		dataDir := t.TempDir()
		fs := initializedFaultStorage(t, dataDir)
		svc := newFaultBarrierService(t, dataDir, fs, 0, nil)
		hookRan := false
		svc.SetPostUnsealHook(func() error {
			hookRan = true
			return errors.New("hook failed")
		})

		require.NoError(t, svc.Unseal(faultTestPassword, string(xkms.StrategyPassphrase)))

		assert.True(t, svc.IsUnsealed())
		assert.True(t, hookRan)
	})

	t.Run("backend open failure", func(t *testing.T) {
		dataDir := t.TempDir()
		fs := initializedFaultStorage(t, dataDir)
		openErr := errors.New("backend open failed")
		// Call 1 is the root key probe; call 2 opens the barrier's backend.
		svc := newFaultBarrierService(t, dataDir, fs, 2, openErr)

		err := svc.Unseal(faultTestPassword, string(xkms.StrategyPassphrase))

		require.ErrorIs(t, err, openErr)
		assert.False(t, svc.IsUnsealed())
	})

	t.Run("cancelled context", func(t *testing.T) {
		dataDir := t.TempDir()
		fs := initializedFaultStorage(t, dataDir)
		svc := newFaultBarrierService(t, dataDir, fs, 0, nil)
		svc.SetContext(canceledContext())

		err := svc.Unseal(faultTestPassword, string(xkms.StrategyPassphrase))

		require.ErrorIs(t, err, context.Canceled)
		assert.False(t, svc.IsUnsealed())
	})

	t.Run("audit failure skips hook", func(t *testing.T) {
		dataDir := t.TempDir()
		fs := initializedFaultStorage(t, dataDir)
		auditErr := errors.New("audit backend unavailable")
		svc := newFaultBarrierService(t, dataDir, fs, 0, nil)
		svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: auditErr})
		hookRan := false
		svc.SetPostUnsealHook(func() error {
			hookRan = true
			return nil
		})

		err := svc.Unseal(faultTestPassword, string(xkms.StrategyPassphrase))

		require.ErrorIs(t, err, auditErr)
		assert.True(t, svc.IsUnsealed())
		assert.False(t, hookRan)
	})
}

// The root key probe treats a backend that cannot answer as uninitialized,
// and a failed close of the probe backend does not change the answer.
func TestBarrierService_IsInitializedProbeFaults(t *testing.T) {
	dataDir := t.TempDir()
	fs := initializedFaultStorage(t, dataDir)
	svc := newFaultBarrierService(t, dataDir, fs, 0, nil)

	fs.closeErr = errors.New("close failed")
	assert.True(t, svc.IsInitialized())

	fs.existsErr = errors.New("root key lookup failed")
	assert.False(t, svc.IsInitialized())
}

// Seal info for an initialized but not yet unsealed barrier reports the last
// strategy by its raw ID when it has no display label.
func TestBarrierService_SealInfoUnlabelledLastStrategy(t *testing.T) {
	dataDir := t.TempDir()
	fs := initializedFaultStorage(t, dataDir)
	svc := newFaultBarrierService(t, dataDir, fs, 0, nil)
	svc.SetLastStrategy("custom-strategy")

	info := svc.GetSealInfo()

	assert.True(t, info.Initialized)
	assert.Equal(t, "custom-strategy", info.Strategy)
	assert.Equal(t, "custom-strategy", info.StrategyLabel)
}

// ChangePassword records a failed change in the audit log and reports a
// failing audit log after a successful change.
func TestBarrierService_ChangePasswordFaults(t *testing.T) {
	t.Run("sealed barrier is refused and audited", func(t *testing.T) {
		rec := &spwRecordingAuditLogger{}
		svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
		require.NoError(t, svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))
		require.NoError(t, svc.Seal())
		svc.SetAuditLogger(rec)

		require.Error(t, svc.ChangePassword("a-new-barrier-password"))

		last := rec.last()
		assert.Equal(t, audit.OpBarrierPasswordChanged, last.Operation)
		assert.False(t, last.Success)
		assert.NotEmpty(t, last.Error)
	})

	t.Run("cancelled context", func(t *testing.T) {
		svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
		require.NoError(t, svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))
		svc.SetContext(canceledContext())

		require.ErrorIs(t, svc.ChangePassword("a-new-barrier-password"), context.Canceled)
	})

	t.Run("audit failure after change", func(t *testing.T) {
		auditErr := errors.New("audit backend unavailable")
		svc := newFaultBarrierService(t, t.TempDir(), newFaultStorage(), 0, nil)
		require.NoError(t, svc.Initialize(faultTestPassword, string(xkms.StrategyPassphrase)))
		svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: auditErr})

		require.ErrorIs(t, svc.ChangePassword("a-new-barrier-password"), auditErr)
	})
}
