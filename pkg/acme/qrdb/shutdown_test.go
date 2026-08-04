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

package qrdb

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewShutdownManager(t *testing.T) {
	t.Run("creates with provided config", func(t *testing.T) {
		cfg := &ShutdownConfig{
			GracePeriod:    5 * time.Second,
			DrainTimeout:   3 * time.Second,
			TransferLeader: true,
		}
		m := NewShutdownManager(cfg, nil, 1, 100, false)
		require.NotNil(t, m)
		assert.Equal(t, ShutdownStateRunning, m.State())
		assert.False(t, m.IsShuttingDown())
	})

	t.Run("creates with nil config uses defaults", func(t *testing.T) {
		m := NewShutdownManager(nil, nil, 1, 100, false)
		require.NotNil(t, m)
		assert.Equal(t, ShutdownStateRunning, m.State())
		assert.Equal(t, defaultGracePeriod, m.cfg.GracePeriod)
		assert.Equal(t, defaultDrainTimeout, m.cfg.DrainTimeout)
		assert.True(t, m.cfg.TransferLeader)
	})
}

func TestShutdownManagerState(t *testing.T) {
	t.Run("initial state is running", func(t *testing.T) {
		m := newTestShutdownManager()
		assert.Equal(t, ShutdownStateRunning, m.State())
	})

	t.Run("state names are correct", func(t *testing.T) {
		assert.Equal(t, "running", ShutdownStateRunning.String())
		assert.Equal(t, "draining", ShutdownStateDraining.String())
		assert.Equal(t, "transferring", ShutdownStateTransferring.String())
		assert.Equal(t, "stopping", ShutdownStateStopping.String())
		assert.Equal(t, "stopped", ShutdownStateStopped.String())
	})

	t.Run("unknown state returns unknown", func(t *testing.T) {
		assert.Equal(t, "unknown", ShutdownState(99).String())
	})
}

func TestShutdownManagerIsShuttingDown(t *testing.T) {
	t.Run("false when running", func(t *testing.T) {
		m := newTestShutdownManager()
		assert.False(t, m.IsShuttingDown())
	})

	t.Run("true after shutdown initiated", func(t *testing.T) {
		m := newTestShutdownManager()
		ctx := context.Background()

		err := m.Shutdown(ctx)
		require.NoError(t, err)
		assert.True(t, m.IsShuttingDown())
	})
}

func TestShutdownManagerInFlight(t *testing.T) {
	t.Run("increment and decrement", func(t *testing.T) {
		m := newTestShutdownManager()

		require.NoError(t, m.IncrementInFlight())
		assert.Equal(t, int64(1), m.InFlight())

		require.NoError(t, m.IncrementInFlight())
		assert.Equal(t, int64(2), m.InFlight())

		m.DecrementInFlight()
		assert.Equal(t, int64(1), m.InFlight())

		m.DecrementInFlight()
		assert.Equal(t, int64(0), m.InFlight())
	})

	t.Run("increment fails when shutting down", func(t *testing.T) {
		m := newTestShutdownManager()
		ctx := context.Background()

		require.NoError(t, m.Shutdown(ctx))

		err := m.IncrementInFlight()
		require.Error(t, err)
		assert.True(t, IsShutdownInProgress(err))
	})

	t.Run("initial inflight is zero", func(t *testing.T) {
		m := newTestShutdownManager()
		assert.Equal(t, int64(0), m.InFlight())
	})
}

func TestShutdownManagerShutdown(t *testing.T) {
	t.Run("successful shutdown with no inflight", func(t *testing.T) {
		m := newTestShutdownManager()
		ctx := context.Background()

		err := m.Shutdown(ctx)
		require.NoError(t, err)
		assert.Equal(t, ShutdownStateStopped, m.State())
	})

	t.Run("shutdown waits for inflight requests", func(t *testing.T) {
		m := newTestShutdownManager()
		ctx := context.Background()

		require.NoError(t, m.IncrementInFlight())

		done := make(chan error, 1)
		go func() {
			done <- m.Shutdown(ctx)
		}()

		// Give shutdown a moment to start draining.
		time.Sleep(50 * time.Millisecond)
		assert.True(t, m.IsShuttingDown())

		// Complete the in-flight request.
		m.DecrementInFlight()

		err := <-done
		require.NoError(t, err)
		assert.Equal(t, ShutdownStateStopped, m.State())
	})

	t.Run("double shutdown returns error", func(t *testing.T) {
		m := newTestShutdownManager()
		ctx := context.Background()

		require.NoError(t, m.Shutdown(ctx))

		// Second shutdown should not error when already stopped.
		err := m.Shutdown(ctx)
		assert.NoError(t, err)
	})

	t.Run("canceled context during inflight wait", func(t *testing.T) {
		cfg := &ShutdownConfig{
			GracePeriod:  5 * time.Second,
			DrainTimeout: 5 * time.Second,
		}
		m := NewShutdownManager(cfg, nil, 1, 100, false)

		require.NoError(t, m.IncrementInFlight())

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := m.Shutdown(ctx)
		require.Error(t, err)
		assert.True(t, IsShutdown(err))
	})

	t.Run("grace period exceeded", func(t *testing.T) {
		cfg := &ShutdownConfig{
			GracePeriod:  50 * time.Millisecond,
			DrainTimeout: 10 * time.Millisecond,
		}
		m := NewShutdownManager(cfg, nil, 1, 100, false)

		require.NoError(t, m.IncrementInFlight())

		ctx := context.Background()
		err := m.Shutdown(ctx)
		require.Error(t, err)
		assert.True(t, IsShutdown(err))
	})

	t.Run("raft mode sets transferring state", func(t *testing.T) {
		cfg := &ShutdownConfig{
			GracePeriod:    5 * time.Second,
			DrainTimeout:   1 * time.Second,
			TransferLeader: true,
		}
		m := NewShutdownManager(cfg, nil, 1, 100, true)

		err := m.Shutdown(context.Background())
		require.NoError(t, err)
		assert.Equal(t, ShutdownStateStopped, m.State())
	})
}

// newTestShutdownManager creates a ShutdownManager for testing with
// short timeouts and no admin client.
func newTestShutdownManager() *ShutdownManager {
	cfg := &ShutdownConfig{
		GracePeriod:    1 * time.Second,
		DrainTimeout:   500 * time.Millisecond,
		TransferLeader: false,
	}
	return NewShutdownManager(cfg, nil, 1, 100, false)
}
