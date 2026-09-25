// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tpm2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlushSessionWithRetry_SucceedsFirstAttempt proves the common case never
// pays the retry delay: a close that succeeds on the first call returns nil
// immediately, and is invoked exactly once.
func TestFlushSessionWithRetry_SucceedsFirstAttempt(t *testing.T) {
	calls := 0
	err := flushSessionWithRetry(func() error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
}

// TestFlushSessionWithRetry_SucceedsAfterTransientFailures proves the retry
// loop absorbs a close that fails on its first attempts but recovers within
// flushRetryAttempts tries -- the "lost a race for the device" case the
// function exists to cover.
func TestFlushSessionWithRetry_SucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	transient := errors.New("device or resource busy")
	err := flushSessionWithRetry(func() error {
		calls++
		if calls < flushRetryAttempts {
			return transient
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, flushRetryAttempts, calls)
}

// TestFlushSessionWithRetry_AllAttemptsFail proves that when close fails on
// every attempt, flushSessionWithRetry gives up after exactly
// flushRetryAttempts tries and returns ErrAuthSessionFlushFailed joined with
// the last underlying error, so a caller with errors.Is can classify the
// failure and the original cause is never discarded.
func TestFlushSessionWithRetry_AllAttemptsFail(t *testing.T) {
	calls := 0
	persistent := errors.New("tpm: simulated persistent flush failure")
	err := flushSessionWithRetry(func() error {
		calls++
		return persistent
	})
	require.Error(t, err)
	assert.Equal(t, flushRetryAttempts, calls)
	assert.ErrorIs(t, err, ErrAuthSessionFlushFailed)
	assert.ErrorIs(t, err, persistent)
}
