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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitBarrier_Success verifies that when Initialize succeeds on
// the first call, initBarrier returns (true, strategyID) and does not
// modify the result's Success or Errors fields.
func TestInitBarrier_Success(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier("test-password-123", "software", result)

	assert.True(t, ok, "initBarrier should return true on successful initialization")
	assert.Equal(t, "software", strategy, "returned strategy should match the requested strategy")
	assert.True(t, result.Success, "result.Success should remain true")
	assert.Empty(t, result.Errors, "no errors should be appended on success")
	assert.Empty(t, result.Warnings, "no warnings should be appended on first-attempt success")
}

// TestInitBarrier_AlreadyInit_UnsealSucceeds verifies that when
// Initialize returns ErrBarrierAlreadyInit and the subsequent Unseal
// succeeds, initBarrier returns (true, strategyID).
func TestInitBarrier_AlreadyInit_UnsealSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	password := "already-init-password"

	// Pre-initialize the barrier so the second call gets ErrBarrierAlreadyInit.
	preInit := NewBarrierService(tmpDir, slog.Default())
	err := preInit.Initialize(password, "software")
	require.NoError(t, err)

	// Create a fresh BarrierService pointing at the same directory.
	// The root key exists on disk, so Initialize will return ErrBarrierAlreadyInit
	// and initBarrier will fall through to Unseal.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier(password, "software", result)

	assert.True(t, ok, "initBarrier should return true when unseal succeeds after ErrBarrierAlreadyInit")
	assert.Equal(t, "software", strategy, "returned strategy should match the requested strategy")
	assert.True(t, result.Success, "result.Success should remain true")
	assert.Empty(t, result.Errors, "no errors should be appended when unseal succeeds")
}

// TestInitBarrier_AlreadyInit_UnsealFails verifies that when
// Initialize returns ErrBarrierAlreadyInit and the subsequent Unseal
// fails (e.g., wrong password), initBarrier returns (false, ""), sets
// result.Success to false, and appends an error mentioning "barrier unseal failed".
func TestInitBarrier_AlreadyInit_UnsealFails(t *testing.T) {
	tmpDir := t.TempDir()
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	// Pre-initialize with the correct password.
	preInit := NewBarrierService(tmpDir, slog.Default())
	err := preInit.Initialize(correctPassword, "software")
	require.NoError(t, err)

	// Create a fresh BarrierService pointing at the same directory.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier(wrongPassword, "software", result)

	assert.False(t, ok, "initBarrier should return false when unseal fails")
	assert.Empty(t, strategy, "returned strategy should be empty on failure")
	assert.False(t, result.Success, "result.Success should be set to false")
	require.NotEmpty(t, result.Errors, "result.Errors should contain the unseal failure")
	assert.True(t, containsSubstring(result.Errors, "barrier unseal failed"),
		"error message should mention 'barrier unseal failed', got: %v", result.Errors)
}

// TestInitBarrier_TPM2Fails_ReturnsError verifies that when Initialize
// with a non-software strategy (e.g., "tpm2") fails, initBarrier returns
// an error instead of silently falling back to software. The user must
// go back and explicitly select a different strategy.
func TestInitBarrier_TPM2Fails_ReturnsError(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	// No TPM sealer function set, so "tpm2" strategy will fail with
	// ErrBarrierStrategyUnavailable.
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier("test-password-123", "tpm2", result)

	assert.False(t, ok, "initBarrier should return false when strategy is unavailable")
	assert.Empty(t, strategy, "returned strategy should be empty on failure")
	assert.False(t, result.Success, "result.Success should be set to false")
	require.NotEmpty(t, result.Errors, "result.Errors should contain the initialization failure")
	assert.True(t, containsSubstring(result.Errors, "tpm2"),
		"error should mention the strategy 'tpm2', got: %v", result.Errors)
	assert.Empty(t, result.Warnings, "no warnings should be appended — failure is an error, not a warning")
}

// TestInitBarrier_TPM2Fails_NoSilentFallback verifies that when the
// requested strategy fails, initBarrier does NOT silently fall back to
// software and instead surfaces the error to the user.
func TestInitBarrier_TPM2Fails_NoSilentFallback(t *testing.T) {
	tw := newTestSetupWizard(&GUIConfigData{})
	barrierSvc := NewBarrierService(t.TempDir(), slog.Default())
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier("", "tpm2", result)

	assert.False(t, ok, "initBarrier should return false when strategy fails")
	assert.Empty(t, strategy, "returned strategy should be empty on failure")
	assert.False(t, result.Success, "result.Success should be set to false")
	require.NotEmpty(t, result.Errors, "result.Errors should contain the failure")
	// Must NOT have fallen back to software.
	assert.NotEqual(t, "software", strategy,
		"must not silently fall back to software")
}

// TestInitBarrier_TPM2AlreadyInit_UnsealFails_NoFallbackToSoftware verifies
// that when Initialize returns ErrBarrierAlreadyInit (even for a non-software
// strategy like "tpm2") and Unseal fails, initBarrier does NOT fall back to
// software. ErrBarrierAlreadyInit is a different code path from strategy
// unavailable - it means the barrier data exists but cannot be unsealed.
func TestInitBarrier_TPM2AlreadyInit_UnsealFails_NoFallbackToSoftware(t *testing.T) {
	tmpDir := t.TempDir()
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	// Pre-initialize with software strategy and the correct password.
	preInit := NewBarrierService(tmpDir, slog.Default())
	err := preInit.Initialize(correctPassword, "software")
	require.NoError(t, err)

	// Create a fresh BarrierService pointing at the same directory.
	// Even though we pass "tpm2" as the strategy, Initialize will see the
	// existing root key and return ErrBarrierAlreadyInit before checking
	// strategy availability. The subsequent Unseal("tpm2") will fail because
	// no TPM sealer is configured.
	barrierSvc := NewBarrierService(tmpDir, slog.Default())
	tw := newTestSetupWizard(&GUIConfigData{})
	tw.svc.SetBarrierService(barrierSvc)

	result := &SetupResult{Success: true}
	ok, strategy := tw.svc.initBarrier(wrongPassword, "tpm2", result)

	assert.False(t, ok, "initBarrier should return false when unseal fails")
	assert.Empty(t, strategy, "returned strategy should be empty on failure")
	assert.False(t, result.Success, "result.Success should be set to false")
	require.NotEmpty(t, result.Errors, "result.Errors should contain the unseal failure")
	assert.True(t, containsSubstring(result.Errors, "barrier unseal failed"),
		"error should mention 'barrier unseal failed', got: %v", result.Errors)
	// Crucially, no fallback warning should appear because ErrBarrierAlreadyInit
	// does not trigger the software fallback path.
	assert.Empty(t, result.Warnings,
		"no fallback warnings should appear for ErrBarrierAlreadyInit path")
}
