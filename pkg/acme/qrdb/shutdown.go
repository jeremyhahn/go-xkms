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
	"log/slog"
	"sync/atomic"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ShutdownState represents the current phase of the graceful shutdown lifecycle.
type ShutdownState int32

const (
	// ShutdownStateRunning indicates the service is operating normally.
	ShutdownStateRunning ShutdownState = iota
	// ShutdownStateDraining indicates the service is draining in-flight requests.
	ShutdownStateDraining
	// ShutdownStateTransferring indicates Raft leadership is being transferred.
	ShutdownStateTransferring
	// ShutdownStateStopping indicates the service is stopping.
	ShutdownStateStopping
	// ShutdownStateStopped indicates the service has stopped.
	ShutdownStateStopped
)

// shutdownStateNames provides O(1) lookup for state names.
var shutdownStateNames = map[ShutdownState]string{
	ShutdownStateRunning:      "running",
	ShutdownStateDraining:     "draining",
	ShutdownStateTransferring: "transferring",
	ShutdownStateStopping:     "stopping",
	ShutdownStateStopped:      "stopped",
}

// String returns the human-readable name of the shutdown state.
func (s ShutdownState) String() string {
	if name, ok := shutdownStateNames[s]; ok {
		return name
	}
	return "unknown"
}

// ShutdownManager orchestrates graceful shutdown of a QRDB node using
// lock-free atomic operations. It tracks the shutdown lifecycle state
// and in-flight request count, ensuring all requests complete before
// the node is stopped.
type ShutdownManager struct {
	state       atomic.Int32
	inFlight    atomic.Int64
	cfg         *ShutdownConfig
	adminClient db.AdminClient
	nodeID      uint64
	clusterID   uint64
	isRaftMode  bool
}

// NewShutdownManager creates a ShutdownManager for the given node.
func NewShutdownManager(
	cfg *ShutdownConfig,
	adminClient db.AdminClient,
	nodeID, clusterID uint64,
	isRaftMode bool,
) *ShutdownManager {
	if cfg == nil {
		cfg = &ShutdownConfig{
			GracePeriod:    defaultGracePeriod,
			DrainTimeout:   defaultDrainTimeout,
			TransferLeader: true,
		}
	}
	m := &ShutdownManager{
		cfg:         cfg,
		adminClient: adminClient,
		nodeID:      nodeID,
		clusterID:   clusterID,
		isRaftMode:  isRaftMode,
	}
	m.state.Store(int32(ShutdownStateRunning))
	return m
}

// Shutdown initiates graceful shutdown. It transitions through the
// shutdown lifecycle: drain -> transfer leader (if raft) -> stop.
// The provided context controls the overall shutdown deadline.
func (m *ShutdownManager) Shutdown(ctx context.Context) error {
	// Transition from running to draining.
	if !m.state.CompareAndSwap(int32(ShutdownStateRunning), int32(ShutdownStateDraining)) {
		current := ShutdownState(m.state.Load())
		if current == ShutdownStateStopped {
			return nil
		}
		return NewError(ErrorCodeShutdownInProgress, "shutdown already in progress").
			WithContext("state", current.String())
	}

	// Phase 1: Drain - signal QRDB to reject new proposals.
	if m.adminClient != nil {
		drainCtx, drainCancel := context.WithTimeout(ctx, m.cfg.DrainTimeout)
		defer drainCancel()
		// Best effort drain; proceed even on error, but the failure is
		// still reported rather than silently discarded.
		if err := m.adminClient.Drain(drainCtx); err != nil {
			slog.Warn("qrdb shutdown: drain failed; proceeding with shutdown anyway",
				slog.Uint64("nodeID", m.nodeID),
				slog.String("error", err.Error()))
		}
	}

	// Phase 2: Wait for in-flight requests to complete.
	if err := m.waitForInFlight(ctx); err != nil {
		// Force transition to stopped on timeout.
		m.state.Store(int32(ShutdownStateStopped))
		return err
	}

	// Phase 3: Transfer leadership (Raft mode only).
	if m.isRaftMode && m.cfg.TransferLeader {
		m.state.Store(int32(ShutdownStateTransferring))
		// Leadership transfer is handled by the Raft layer during close.
	}

	// Phase 4: Stop.
	m.state.Store(int32(ShutdownStateStopping))
	m.state.Store(int32(ShutdownStateStopped))
	return nil
}

// waitForInFlight waits until all in-flight requests have completed
// or the context deadline is exceeded.
func (m *ShutdownManager) waitForInFlight(ctx context.Context) error {
	deadline := time.After(m.cfg.GracePeriod)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		if m.inFlight.Load() <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return NewError(ErrorCodeShutdown, "shutdown context canceled").
				WithCause(ctx.Err()).
				WithContext("in_flight", m.inFlight.Load())
		case <-deadline:
			return NewError(ErrorCodeShutdown, "grace period exceeded").
				WithContext("in_flight", m.inFlight.Load()).
				WithContext("grace_period", m.cfg.GracePeriod.String())
		case <-ticker.C:
			// Check again.
		}
	}
}

// State returns the current shutdown state.
func (m *ShutdownManager) State() ShutdownState {
	return ShutdownState(m.state.Load())
}

// IsShuttingDown reports whether the shutdown process has been initiated.
func (m *ShutdownManager) IsShuttingDown() bool {
	return ShutdownState(m.state.Load()) != ShutdownStateRunning
}

// IncrementInFlight increments the in-flight request counter.
// Returns an error if the service is shutting down.
func (m *ShutdownManager) IncrementInFlight() error {
	if m.IsShuttingDown() {
		return NewError(ErrorCodeShutdownInProgress, "service is shutting down")
	}
	m.inFlight.Add(1)
	// Double-check after increment to handle race between
	// IsShuttingDown check and Add.
	if m.IsShuttingDown() {
		m.inFlight.Add(-1)
		return NewError(ErrorCodeShutdownInProgress, "service is shutting down")
	}
	return nil
}

// DecrementInFlight decrements the in-flight request counter.
func (m *ShutdownManager) DecrementInFlight() {
	m.inFlight.Add(-1)
}

// InFlight returns the current number of in-flight requests.
func (m *ShutdownManager) InFlight() int64 {
	return m.inFlight.Load()
}
