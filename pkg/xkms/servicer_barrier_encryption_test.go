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

package xkms

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEncryptionMigrator records the scope and options of an EnableEncryption
// call so tests can assert how the servicer mapped the request. It signals done
// once invoked, letting tests synchronize with the servicer's async migration
// goroutine.
type fakeEncryptionMigrator struct {
	mu     sync.Mutex
	called bool
	scope  qrdbsdk.BarrierScope
	opts   qrdbsdk.MigrationOptions
	err    error
	done   chan struct{}
}

func (f *fakeEncryptionMigrator) EnableEncryption(_ context.Context, scope qrdbsdk.BarrierScope, opts qrdbsdk.MigrationOptions) error {
	f.mu.Lock()
	f.called = true
	f.scope = scope
	f.opts = opts
	f.mu.Unlock()
	if f.done != nil {
		close(f.done)
	}
	return f.err
}

func (f *fakeEncryptionMigrator) wasCalled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

// newServiceForMigration returns the singleton service after a clean setup so
// each test starts from a known state.
func newServiceForMigration(t *testing.T) *XKMSService {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// TestBarrierEnableEncryption_NotConfigured verifies that the operation reports
// ErrNotConfigured when no encryption migrator (embedded node) is wired.
func TestBarrierEnableEncryption_NotConfigured(t *testing.T) {
	svc := newServiceForMigration(t)

	_, err := svc.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{
		Strategy: "passphrase",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// TestBarrierEnableEncryption_NilRequest verifies the nil-request guard fires
// even when the migrator is configured.
func TestBarrierEnableEncryption_NilRequest(t *testing.T) {
	svc := newServiceForMigration(t)
	svc.SetEncryptionMigrator(&fakeEncryptionMigrator{})

	_, err := svc.BarrierEnableEncryption(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// TestBarrierEnableEncryption_InvalidStrategy verifies that an invalid target
// strategy is rejected synchronously and the migration goroutine is never
// launched.
func TestBarrierEnableEncryption_InvalidStrategy(t *testing.T) {
	svc := newServiceForMigration(t)
	migrator := &fakeEncryptionMigrator{}
	svc.SetEncryptionMigrator(migrator)

	// Empty strategy is not a valid keyed target.
	resp, err := svc.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{
		Strategy: "",
	})
	require.Error(t, err)
	assert.Nil(t, resp)

	// Validation fails before the async migration is scheduled, so the migrator
	// must not have been invoked.
	time.Sleep(50 * time.Millisecond)
	assert.False(t, migrator.wasCalled(), "migrator must not run when validation fails")
}

// TestBarrierEnableEncryption_SystemScopeSuccess verifies the happy path: an
// empty tenant id maps to the system scope, the response acknowledges the
// start, and the migrator is eventually invoked with the mapped scope and
// defaulted options.
func TestBarrierEnableEncryption_SystemScopeSuccess(t *testing.T) {
	svc := newServiceForMigration(t)
	migrator := &fakeEncryptionMigrator{done: make(chan struct{})}
	svc.SetEncryptionMigrator(migrator)

	resp, err := svc.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{
		Strategy:   "passphrase",
		Passphrase: "hunter2",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "migration_started", resp.Status)
	assert.Equal(t, string(qrdbsdk.ScopeSystem), resp.Scope)

	// Wait for the async migration goroutine to invoke the migrator.
	select {
	case <-migrator.done:
	case <-time.After(3 * time.Second):
		t.Fatal("migrator was not invoked within the timeout")
	}

	assert.Equal(t, qrdbsdk.ScopeSystem, migrator.scope.Kind)
	assert.Empty(t, migrator.scope.TenantID)
	assert.Equal(t, qrdbsdk.StrategyID("passphrase"), migrator.opts.TargetStrategy)
	// Mechanism and availability default when unset in the request.
	assert.Equal(t, qrdbsdk.MechanismSwap, migrator.opts.Mechanism)
	assert.Equal(t, qrdbsdk.AvailabilityQuiesced, migrator.opts.Availability)
	assert.Equal(t, []byte("hunter2"), migrator.opts.Credentials.Secret)
}

// TestBarrierEnableEncryption_SingleFlightPerScope verifies that a second
// migration request for the same barrier scope is rejected while the first is
// still in flight. Two concurrent migrations on one barrier would race on the
// swap/in-place rewrite and corrupt it, so the servicer is single-flight per
// scope.
func TestBarrierEnableEncryption_SingleFlightPerScope(t *testing.T) {
	svc := newServiceForMigration(t)
	migrator := &fakeEncryptionMigrator{done: make(chan struct{})}
	svc.SetEncryptionMigrator(migrator)

	req := &transport.BarrierEnableEncryptionRequest{
		Strategy:   "passphrase",
		Passphrase: "hunter2",
	}

	// First call schedules the migration and marks the system scope in-flight.
	resp1, err := svc.BarrierEnableEncryption(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	assert.Equal(t, "migration_started", resp1.Status)

	// Second call on the same scope, issued before the first migration runs (the
	// goroutine waits migrationStartGrace before invoking the migrator), must be
	// rejected rather than racing the first.
	resp2, err := svc.BarrierEnableEncryption(context.Background(), req)
	require.Error(t, err)
	assert.Nil(t, resp2)
	assert.True(t, errors.Is(err, ErrMigrationInProgress))

	// Let the first migration complete so the goroutine does not outlive the test.
	select {
	case <-migrator.done:
	case <-time.After(3 * time.Second):
		t.Fatal("first migration was not invoked within the timeout")
	}
}

// TestBarrierEnableEncryption_TenantScope verifies that a non-empty tenant id
// maps to the tenant scope in both the response and the migrator invocation.
func TestBarrierEnableEncryption_TenantScope(t *testing.T) {
	svc := newServiceForMigration(t)
	migrator := &fakeEncryptionMigrator{done: make(chan struct{})}
	svc.SetEncryptionMigrator(migrator)

	resp, err := svc.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{
		TenantID:     "acme",
		Strategy:     "passphrase",
		Passphrase:   "s3cret",
		Mechanism:    string(qrdbsdk.MechanismInPlace),
		Availability: string(qrdbsdk.AvailabilityOnline),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, string(qrdbsdk.ScopeTenant), resp.Scope)

	select {
	case <-migrator.done:
	case <-time.After(3 * time.Second):
		t.Fatal("migrator was not invoked within the timeout")
	}

	assert.Equal(t, qrdbsdk.ScopeTenant, migrator.scope.Kind)
	assert.Equal(t, "acme", migrator.scope.TenantID)
	// Explicit mechanism/availability are honored.
	assert.Equal(t, qrdbsdk.MechanismInPlace, migrator.opts.Mechanism)
	assert.Equal(t, qrdbsdk.AvailabilityOnline, migrator.opts.Availability)
}
