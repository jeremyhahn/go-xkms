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
	"sync"
	"testing"
	"time"

	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTPM is a minimal mock that satisfies the TrustedPlatformModule interface
// for TPMAccessor tests. It embeds the interface so that all methods are
// provided (they will panic if called, but the accessor never calls TPM
// methods directly -- it only returns the reference).
type stubTPM struct {
	tpm2pkg.TrustedPlatformModule
}

func TestTPMAccessor_Acquire_Success(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	tpm, err := acc.Acquire()
	require.NoError(t, err)
	assert.Equal(t, stub, tpm)
	acc.Release()
}

func TestTPMAccessor_Acquire_NilFunc(t *testing.T) {
	acc := NewTPMAccessor(nil)

	tpm, err := acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMAccessor_Acquire_NilTPM(t *testing.T) {
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return nil })

	tpm, err := acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMNotAvailable)
}

func TestTPMAccessor_Shutdown_RejectsNew(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	acc.Shutdown()

	tpm, err := acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMShuttingDown)
}

func TestTPMAccessor_Shutdown_WaitsForInflight(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	// Acquire the TPM (simulates an in-flight operation).
	tpm, err := acc.Acquire()
	require.NoError(t, err)
	require.NotNil(t, tpm)

	// Start shutdown in a goroutine -- it should block until Release.
	shutdownDone := make(chan struct{})
	go func() {
		acc.Shutdown()
		close(shutdownDone)
	}()

	// Give the shutdown goroutine time to start and block on the mutex.
	time.Sleep(50 * time.Millisecond)

	// Verify shutdown has not completed yet.
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown completed while TPM was still acquired")
	default:
		// Expected: shutdown is blocked waiting for in-flight release.
	}

	// Release the TPM so that shutdown can proceed.
	acc.Release()

	// Shutdown should complete quickly now.
	select {
	case <-shutdownDone:
		// Expected: shutdown completed after release.
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete after TPM release")
	}

	// New acquire should fail with shutting down error.
	tpm, err = acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMShuttingDown)
}

func TestTPMAccessor_Shutdown_Idempotent(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	acc.Shutdown()
	acc.Shutdown() // Must not panic or deadlock.

	tpm, err := acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMShuttingDown)
}

func TestTPMAccessor_ConcurrentAcquire(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tpm, err := acc.Acquire()
			if err == nil {
				assert.NotNil(t, tpm)
				time.Sleep(time.Millisecond)
				acc.Release()
			}
		}()
	}
	wg.Wait()
}

func TestTPMAccessor_ConcurrentAcquireDuringShutdown(t *testing.T) {
	stub := &stubTPM{}
	acc := NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return stub })

	var wg sync.WaitGroup

	// Start several concurrent acquires.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tpm, err := acc.Acquire()
			if err == nil {
				assert.NotNil(t, tpm)
				time.Sleep(5 * time.Millisecond)
				acc.Release()
			} else {
				// After shutdown, only ErrTPMShuttingDown is expected.
				assert.ErrorIs(t, err, ErrTPMShuttingDown)
			}
		}()
	}

	// Trigger shutdown while acquires may be in-flight.
	time.Sleep(2 * time.Millisecond)
	acc.Shutdown()

	wg.Wait()

	// After shutdown, all acquires must fail.
	tpm, err := acc.Acquire()
	assert.Nil(t, tpm)
	assert.ErrorIs(t, err, ErrTPMShuttingDown)
}
