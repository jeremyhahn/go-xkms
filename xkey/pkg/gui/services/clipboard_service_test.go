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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClipboardService(t *testing.T) {
	svc := NewClipboardService()
	require.NotNil(t, svc)
	assert.Equal(t, DefaultClipboardTimeout, svc.GetTimeout())
}

func TestClipboardService_SetContext(t *testing.T) {
	svc := NewClipboardService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestClipboardService_SetTimeout(t *testing.T) {
	svc := NewClipboardService()

	svc.SetTimeout(60)
	assert.Equal(t, 60, svc.GetTimeout())

	svc.SetTimeout(0)
	assert.Equal(t, 0, svc.GetTimeout())
}

func TestClipboardService_SetTimeout_Negative(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(-5)
	assert.Equal(t, 0, svc.GetTimeout())
}

func TestClipboardService_GetTimeout_Default(t *testing.T) {
	svc := NewClipboardService()
	assert.Equal(t, DefaultClipboardTimeout, svc.GetTimeout())
}

func TestClipboardService_CopyWithClear_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	err := svc.CopyWithClear("secret")
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

func TestClipboardService_Copy_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	err := svc.Copy("text")
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

func TestClipboardService_ClearClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	err := svc.ClearClipboard()
	assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
}

func TestClipboardService_ClearClipboard_CancelsPending(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	// Set up a pending cancel function.
	cancelled := false
	svc.clearMu.Lock()
	svc.cancelFn = func() { cancelled = true }
	svc.clearMu.Unlock()

	// ClearClipboard should cancel the pending timer even if tool is unavailable.
	_ = svc.ClearClipboard()
	assert.True(t, cancelled)
}

func TestDetectClipboardTool(t *testing.T) {
	// This test verifies the function runs without error.
	// The result depends on the system, so we just verify it returns
	// a valid value.
	tool := detectClipboardTool()
	assert.True(t, tool >= clipToolNone && tool <= clipToolWlCopy)
}

func TestClipboardService_CopyWithClear_DisabledTimeout(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(0)

	// With timeout disabled, CopyWithClear should behave like Copy
	// (no auto-clear scheduled). If no tool available, it returns error.
	if svc.tool == clipToolNone {
		err := svc.CopyWithClear("test")
		assert.True(t, errors.Is(err, ErrClipboardToolUnavailable))
	}
}

// --- writeClipboard tests ---

func TestClipboardService_WriteClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	err := svc.writeClipboard("some text")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestClipboardService_WriteClipboard_InvalidXclipBinary(t *testing.T) {
	// Force clipToolXclip but on a system where the binary does not exist
	// or returns an error. This exercises the cmd.Run() failure path.
	svc := NewClipboardService()
	svc.tool = clipToolXclip

	// If xclip is actually installed, it may succeed. The test validates
	// writeClipboard does not panic and returns either nil or
	// ErrClipboardWriteFailed.
	err := svc.writeClipboard("test-write")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

func TestClipboardService_WriteClipboard_InvalidXselBinary(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolXsel

	err := svc.writeClipboard("test-write")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

func TestClipboardService_WriteClipboard_InvalidWlCopyBinary(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolWlCopy

	err := svc.writeClipboard("test-write")
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardWriteFailed)
	}
}

// --- readClipboard tests ---

func TestClipboardService_ReadClipboard_NoTool(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	result, err := svc.readClipboard()
	assert.Empty(t, result)
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

func TestClipboardService_ReadClipboard_XclipPath(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolXclip

	// Exercises the xclip branch in readClipboard. On systems without
	// xclip or without a display, cmd.Output() fails and we get
	// ErrClipboardReadFailed.
	result, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
		assert.Empty(t, result)
	}
}

func TestClipboardService_ReadClipboard_XselPath(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolXsel

	result, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
		assert.Empty(t, result)
	}
}

func TestClipboardService_ReadClipboard_WlCopyPath(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolWlCopy

	result, err := svc.readClipboard()
	if err != nil {
		assert.ErrorIs(t, err, ErrClipboardReadFailed)
		assert.Empty(t, result)
	}
}

// --- scheduleClear tests ---

func TestClipboardService_ScheduleClear_CancelsPrevious(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone // Prevent actual clipboard operations.

	// Set up a cancel function to track that it gets cancelled.
	previousCancelled := false
	svc.clearMu.Lock()
	svc.cancelFn = func() { previousCancelled = true }
	svc.clearMu.Unlock()

	// scheduleClear should cancel the previous pending clear.
	svc.scheduleClear("test", 1*time.Hour)
	assert.True(t, previousCancelled, "previous cancel function must be invoked")

	// A new cancelFn should be set.
	svc.clearMu.Lock()
	assert.NotNil(t, svc.cancelFn, "new cancelFn must be set")
	// Cancel it to clean up the goroutine.
	svc.cancelFn()
	svc.clearMu.Unlock()
}

func TestClipboardService_ScheduleClear_GoroutineCancellation(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	// Schedule a clear with a long delay and immediately cancel it.
	svc.scheduleClear("test-data", 10*time.Second)

	svc.clearMu.Lock()
	require.NotNil(t, svc.cancelFn)
	svc.cancelFn()
	svc.clearMu.Unlock()

	// Give the goroutine a moment to exit via ctx.Done().
	time.Sleep(50 * time.Millisecond)

	// The goroutine should have exited without performing any clipboard
	// operations. No panic or hang means success.
}

// --- CopyWithClear with timeout disabled (writeClipboard fails) ---

func TestClipboardService_CopyWithClear_TimeoutDisabled_NoSchedule(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(0)
	svc.tool = clipToolNone

	err := svc.CopyWithClear("secret")
	// Should fail on writeClipboard before reaching scheduleClear.
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)

	// Verify no cancelFn was set (scheduleClear was not called).
	svc.clearMu.Lock()
	assert.Nil(t, svc.cancelFn, "cancelFn should not be set when tool is unavailable")
	svc.clearMu.Unlock()
}

// --- CopyWithClear with negative timeout ---

func TestClipboardService_CopyWithClear_NegativeTimeout(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(-10)
	svc.tool = clipToolNone

	err := svc.CopyWithClear("secret")
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}

// --- clipboardTool constants ---

func TestClipboardToolConstants(t *testing.T) {
	assert.Equal(t, clipboardTool(0), clipToolNone)
	assert.Equal(t, clipboardTool(1), clipToolXclip)
	assert.Equal(t, clipboardTool(2), clipToolXsel)
	assert.Equal(t, clipboardTool(3), clipToolWlCopy)
}

// --- DefaultClipboardTimeout constant ---

func TestDefaultClipboardTimeoutConstant(t *testing.T) {
	assert.Equal(t, 30, DefaultClipboardTimeout)
}

// --- Multiple ClearClipboard calls ---

func TestClipboardService_ClearClipboard_MultipleCalls(t *testing.T) {
	svc := NewClipboardService()
	svc.tool = clipToolNone

	// First call with a cancelFn.
	callCount := 0
	svc.clearMu.Lock()
	svc.cancelFn = func() { callCount++ }
	svc.clearMu.Unlock()

	_ = svc.ClearClipboard()
	assert.Equal(t, 1, callCount, "first ClearClipboard should cancel once")

	// Second call without a cancelFn set.
	_ = svc.ClearClipboard()
	// Should not panic when cancelFn is nil.
	assert.Equal(t, 1, callCount, "second ClearClipboard should not increment count")
}

// --- Copy with each tool type (error paths) ---

func TestClipboardService_Copy_AllToolTypes_ErrorPaths(t *testing.T) {
	tools := []struct {
		name string
		tool clipboardTool
	}{
		{"xclip", clipToolXclip},
		{"xsel", clipToolXsel},
		{"wl-copy", clipToolWlCopy},
	}

	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewClipboardService()
			svc.tool = tc.tool

			err := svc.Copy("test data")
			// On systems without these tools installed, the write
			// will fail with ErrClipboardWriteFailed. On systems
			// with the tool but no display, same result.
			if err != nil {
				assert.ErrorIs(t, err, ErrClipboardWriteFailed)
			}
		})
	}
}

// --- SetTimeout boundary values ---

func TestClipboardService_SetTimeout_LargeValue(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(3600) // 1 hour
	assert.Equal(t, 3600, svc.GetTimeout())
}

func TestClipboardService_SetTimeout_MaxInt32(t *testing.T) {
	svc := NewClipboardService()
	svc.SetTimeout(2147483647)
	assert.Equal(t, 2147483647, svc.GetTimeout())
}
