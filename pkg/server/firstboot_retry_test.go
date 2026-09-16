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

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swapFirstBootInitialize substitutes the SDK initialize function for the
// test and restores it afterwards.
func swapFirstBootInitialize(t *testing.T, fn func(context.Context, qrdbsdk.FirstBootDependencies) (*qrdbsdk.FirstBootResult, error)) {
	t.Helper()
	prev := firstBootInitialize
	firstBootInitialize = fn
	t.Cleanup(func() { firstBootInitialize = prev })
}

func newRetryTestServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestFirstBootWithLeaderRetry_RetriesNotLeaderThenSucceeds proves transient
// not-leader failures during the initial election are retried until the
// leader settles.
func TestFirstBootWithLeaderRetry_RetriesNotLeaderThenSucceeds(t *testing.T) {
	calls := 0
	swapFirstBootInitialize(t, func(context.Context, qrdbsdk.FirstBootDependencies) (*qrdbsdk.FirstBootResult, error) {
		calls++
		if calls < 3 {
			return nil, &qrdbsdk.NotLeaderError{ShardID: 1}
		}
		return &qrdbsdk.FirstBootResult{}, nil
	})

	result, err := newRetryTestServer().firstBootWithLeaderRetry(
		context.Background(), qrdbsdk.FirstBootDependencies{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 3, calls)
}

// TestFirstBootWithLeaderRetry_NonLeaderErrorFailsImmediately proves other
// errors are never retried.
func TestFirstBootWithLeaderRetry_NonLeaderErrorFailsImmediately(t *testing.T) {
	calls := 0
	boom := errors.New("storage exploded")
	swapFirstBootInitialize(t, func(context.Context, qrdbsdk.FirstBootDependencies) (*qrdbsdk.FirstBootResult, error) {
		calls++
		return nil, boom
	})

	_, err := newRetryTestServer().firstBootWithLeaderRetry(
		context.Background(), qrdbsdk.FirstBootDependencies{})
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, calls)
}

// TestFirstBootWithLeaderRetry_ContextCancelStopsWaiting proves cancellation
// interrupts the backoff wait.
func TestFirstBootWithLeaderRetry_ContextCancelStopsWaiting(t *testing.T) {
	swapFirstBootInitialize(t, func(context.Context, qrdbsdk.FirstBootDependencies) (*qrdbsdk.FirstBootResult, error) {
		return nil, &qrdbsdk.NotLeaderError{ShardID: 1}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newRetryTestServer().firstBootWithLeaderRetry(ctx, qrdbsdk.FirstBootDependencies{})
	require.ErrorIs(t, err, context.Canceled)
}

// TestIsNotLeaderErr proves classification through wrapped chains.
func TestIsNotLeaderErr(t *testing.T) {
	wrapped := &FirstBootError{Op: "x", Cause: &qrdbsdk.NotLeaderError{ShardID: 2}}
	assert.True(t, isNotLeaderErr(wrapped))
	assert.False(t, isNotLeaderErr(errors.New("other")))
	assert.False(t, isNotLeaderErr(nil))
}
