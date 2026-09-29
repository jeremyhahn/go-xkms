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

package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRenewalOrchestrator verifies the constructor returns a non-nil orchestrator.
func TestNewRenewalOrchestrator(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())

	ro := NewRenewalOrchestrator(cfg, cm, testLogger())
	require.NotNil(t, ro)
	assert.False(t, ro.Running())
}

// TestRenewalOrchestrator_StartStop verifies the start/stop lifecycle.
func TestRenewalOrchestrator_StartStop(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	ctx := context.Background()

	err := ro.Start(ctx)
	require.NoError(t, err)
	assert.True(t, ro.Running())

	err = ro.Stop()
	require.NoError(t, err)
	assert.False(t, ro.Running())
}

// TestRenewalOrchestrator_StartAlreadyRunning verifies that starting an
// already-running orchestrator returns an ErrValidation.
func TestRenewalOrchestrator_StartAlreadyRunning(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	ctx := context.Background()

	err := ro.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = ro.Stop() }()

	err = ro.Start(ctx)
	require.Error(t, err)

	var validErr *ErrValidation
	assert.True(t, errors.As(err, &validErr))
	assert.Equal(t, "orchestrator", validErr.Field)
}

// TestRenewalOrchestrator_StopWhenNotRunning verifies that Stop is idempotent.
func TestRenewalOrchestrator_StopWhenNotRunning(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	err := ro.Stop()
	require.NoError(t, err)
	assert.False(t, ro.Running())
}

// TestRenewalOrchestrator_ConcurrentStop is a regression test for #1271: Stop
// used to gate the close(ro.stopChan) call on running.Load(), so two
// goroutines calling Stop() at the same time could both observe running ==
// true and both reach close(ro.stopChan), panicking with "close of closed
// channel". Stop now gates the close on running.CompareAndSwap(true, false),
// so only one caller ever closes the channel. Run with -race; on the old
// Load()-gated code this reliably panics within a handful of iterations.
func TestRenewalOrchestrator_ConcurrentStop(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())

	for i := 0; i < 20; i++ {
		ro := NewRenewalOrchestrator(cfg, cm, testLogger())

		require.NoError(t, ro.Start(context.Background()))

		const concurrentStops = 8
		var wg sync.WaitGroup
		wg.Add(concurrentStops)
		for g := 0; g < concurrentStops; g++ {
			go func() {
				defer wg.Done()
				assert.NoError(t, ro.Stop())
			}()
		}
		wg.Wait()

		assert.False(t, ro.Running())
	}
}

// TestRenewalOrchestrator_StopOnContextCancel verifies the orchestrator stops
// when its context is cancelled.
func TestRenewalOrchestrator_StopOnContextCancel(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	ctx, cancel := context.WithCancel(context.Background())

	err := ro.Start(ctx)
	require.NoError(t, err)
	assert.True(t, ro.Running())

	cancel()
	// Give the goroutine time to notice the cancellation
	time.Sleep(50 * time.Millisecond)
	// The goroutine has exited but running flag is still true until Stop() is called.
	// Stop should still work cleanly.
	err = ro.Stop()
	require.NoError(t, err)
}

// TestRenewalOrchestrator_CheckAndRenew_NoCerts verifies CheckAndRenew returns
// no results when there are no certificates configured.
func TestRenewalOrchestrator_CheckAndRenew_NoCerts(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	results := ro.CheckAndRenew(context.Background())
	assert.Empty(t, results)
}

// TestRenewalOrchestrator_CheckAndRenew_NoAutoRenew verifies CheckAndRenew
// skips certificates without auto-renewal enabled.
func TestRenewalOrchestrator_CheckAndRenew_NoAutoRenew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
		// No Renewal config
	}
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	results := ro.CheckAndRenew(context.Background())
	assert.Empty(t, results)
}

// TestRenewalOrchestrator_CheckAndRenew_AutoFalse verifies CheckAndRenew
// skips certificates with Renewal.Auto set to false.
func TestRenewalOrchestrator_CheckAndRenew_AutoFalse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
		Renewal:   &CertRenewalConfig{Auto: false, DaysBefore: 30},
	}
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	results := ro.CheckAndRenew(context.Background())
	assert.Empty(t, results)
}

// TestRenewalOrchestrator_CheckAndRenew_AutoTrue_NotManaged verifies that
// CheckAndRenew attempts renewal for auto-renew certs that aren't yet managed.
// The renewal will fail (no ACME server) but we verify it attempts the operation.
func TestRenewalOrchestrator_CheckAndRenew_AutoTrue_NotManaged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
		Renewal:   &CertRenewalConfig{Auto: true, DaysBefore: 30},
	}
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	results := ro.CheckAndRenew(context.Background())
	require.Len(t, results, 1)
	assert.Equal(t, "web", results[0].Name)
	assert.False(t, results[0].Renewed)
	// Renewal fails because there's no real ACME server - but it was attempted
	assert.Error(t, results[0].Error)
}

// TestRenewalOrchestrator_Running verifies the Running method reflects state.
func TestRenewalOrchestrator_Running(t *testing.T) {
	cfg := DefaultConfig()
	am := NewAccountManager(cfg, testLogger())
	deployer := NewDeployer(testLogger())
	cm := NewCertificateManager(cfg, am, deployer, testLogger())
	ro := NewRenewalOrchestrator(cfg, cm, testLogger())

	assert.False(t, ro.Running())

	err := ro.Start(context.Background())
	require.NoError(t, err)
	assert.True(t, ro.Running())

	err = ro.Stop()
	require.NoError(t, err)
	assert.False(t, ro.Running())
}
