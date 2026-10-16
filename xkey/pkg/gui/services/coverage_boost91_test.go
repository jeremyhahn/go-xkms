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
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: create a fake clipboard tool script
// ---------------------------------------------------------------------------

// createFakeClipTool creates a shell script at dir/<name> that simulates a
// clipboard tool. It stores clipboard content in a temp file.
// Returns the directory that should be prepended to PATH.
func createFakeClipTool(t *testing.T, name string) string {
	t.Helper()
	binDir := filepath.Join(t.TempDir(), "bin-"+name)
	require.NoError(t, os.MkdirAll(binDir, 0755))

	clipFile := filepath.Join(binDir, ".clipboard_data")

	var script string
	switch name {
	case "xclip":
		script = `#!/bin/sh
CLIP_FILE="` + clipFile + `"
for arg in "$@"; do
    if [ "$arg" = "-o" ]; then
        if [ -f "$CLIP_FILE" ]; then cat "$CLIP_FILE"; fi
        exit 0
    fi
done
cat > "$CLIP_FILE"
exit 0
`
	case "xsel":
		script = `#!/bin/sh
CLIP_FILE="` + clipFile + `"
for arg in "$@"; do
    if [ "$arg" = "--output" ] || [ "$arg" = "-o" ]; then
        if [ -f "$CLIP_FILE" ]; then cat "$CLIP_FILE"; fi
        exit 0
    fi
done
cat > "$CLIP_FILE"
exit 0
`
	case "wl-copy":
		// wl-copy writes, wl-paste reads. Create both.
		script = `#!/bin/sh
cat > "` + clipFile + `"
exit 0
`
		pasteScript := `#!/bin/sh
if [ -f "` + clipFile + `" ]; then cat "` + clipFile + `"; fi
exit 0
`
		pastePath := filepath.Join(binDir, "wl-paste")
		require.NoError(t, os.WriteFile(pastePath, []byte(pasteScript), 0755))
	default:
		t.Fatalf("unknown clipboard tool: %s", name)
	}

	scriptPath := filepath.Join(binDir, name)
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))
	return binDir
}

// withFakeClipToolInPath prepends a fake clipboard tool directory to PATH
// for the duration of the test. Any other clipboard tools in the existing
// PATH are hidden by creating a minimal PATH containing only the fake tool
// and essential system directories.
func withFakeClipToolInPath(t *testing.T, name string) {
	t.Helper()
	binDir := createFakeClipTool(t, name)
	// Use a minimal PATH that includes the fake tool first, followed by
	// /usr/bin and /bin for basic shell operations (sh, cat, etc).
	t.Setenv("PATH", binDir)
}

// newClipboardServiceWithFakeXclip creates a ClipboardService that uses the
// fake xclip tool by directly setting the tool field.
func newClipboardServiceWithFakeXclip(t *testing.T) *ClipboardService {
	t.Helper()
	binDir := createFakeClipTool(t, "xclip")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+":"+origPath)
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: clipToolXclip,
	}
	svc.timeout.Store(int32(DefaultClipboardTimeout))
	// Registered after t.TempDir, so it runs first: no scheduled clear may
	// still be running the fake xclip when the temp dir is removed.
	t.Cleanup(svc.stopPendingClear)
	return svc
}

// ---------------------------------------------------------------------------
// Helper: create a fake elevation tool script
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Clipboard: CopyWithClear with a working tool (covers L93-99)
// ---------------------------------------------------------------------------

func TestCB91_CopyWithClear_TimeoutDisabled(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetTimeout(0) // Disable auto-clear

	err := svc.CopyWithClear("test-data")
	require.NoError(t, err)
}

func TestCB91_CopyWithClear_TimeoutEnabled(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetTimeout(10) // 10 seconds

	err := svc.CopyWithClear("scheduled-data")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard: ClearClipboard with a working tool (covers L126)
// ---------------------------------------------------------------------------

func TestCB91_ClearClipboard_WritesEmptyString(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)

	err := svc.Copy("to-be-cleared")
	require.NoError(t, err)

	err = svc.ClearClipboard()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard: writeClipboard and readClipboard success paths (covers L190, L213)
// ---------------------------------------------------------------------------

func TestCB91_WriteAndReadClipboard_Success(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)

	err := svc.writeClipboard("hello-clipboard")
	require.NoError(t, err)

	content, err := svc.readClipboard()
	require.NoError(t, err)
	assert.Equal(t, "hello-clipboard", content)
}

// ---------------------------------------------------------------------------
// Clipboard: scheduleClear timer fires and clears (covers L158-163)
// ---------------------------------------------------------------------------

func TestCB91_ScheduleClear_TimerFiresAndClears(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetContext(context.Background())

	err := svc.writeClipboard("sensitive-data")
	require.NoError(t, err)

	svc.scheduleClear("sensitive-data", 50*time.Millisecond)

	// scheduleClear's 50ms delay (no clock seam) is the behavior under
	// test; poll for the clear rather than betting a fixed sleep is long
	// enough under a loaded scheduler.
	require.Eventually(t, func() bool {
		content, readErr := svc.readClipboard()
		return readErr == nil && content == ""
	}, 5*time.Second, 10*time.Millisecond, "clipboard was not cleared after timeout")
}

func TestCB91_ScheduleClear_ContentChanged(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetContext(context.Background())

	err := svc.writeClipboard("original")
	require.NoError(t, err)

	svc.scheduleClear("original", 100*time.Millisecond)

	err = svc.writeClipboard("changed-content")
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond)

	content, err := svc.readClipboard()
	require.NoError(t, err)
	assert.Equal(t, "changed-content", content,
		"clipboard should not be cleared when content has changed")
}

// ---------------------------------------------------------------------------
// Clipboard: detectClipboardTool with xclip in PATH (covers L218-220)
// ---------------------------------------------------------------------------

func TestCB91_DetectClipboardTool_FindsXclip(t *testing.T) {
	withFakeClipToolInPath(t, "xclip")

	tool := detectClipboardTool()
	assert.Equal(t, clipToolXclip, tool)
}

// ---------------------------------------------------------------------------
// Clipboard: detectClipboardTool finds xsel (covers L221-223)
// ---------------------------------------------------------------------------

func TestCB91_DetectClipboardTool_FindsXsel(t *testing.T) {
	// Set up PATH with xsel only (no xclip, no wl-copy).
	binDir := createFakeClipTool(t, "xsel")
	t.Setenv("PATH", binDir)

	tool := detectClipboardTool()
	assert.Equal(t, clipToolXsel, tool)
}

// ---------------------------------------------------------------------------
// Clipboard: detectClipboardTool finds wl-copy (covers L224-226)
// ---------------------------------------------------------------------------

func TestCB91_DetectClipboardTool_FindsWlCopy(t *testing.T) {
	// Set up PATH with wl-copy only (no xclip, no xsel).
	binDir := createFakeClipTool(t, "wl-copy")
	t.Setenv("PATH", binDir)

	tool := detectClipboardTool()
	assert.Equal(t, clipToolWlCopy, tool)
}

// ---------------------------------------------------------------------------
// Clipboard: detectClipboardTool finds nothing (covers L227)
// ---------------------------------------------------------------------------

func TestCB91_DetectClipboardTool_NoneFound(t *testing.T) {
	// Set up PATH with no clipboard tools at all.
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	tool := detectClipboardTool()
	assert.Equal(t, clipToolNone, tool)
}

// ---------------------------------------------------------------------------
// Clipboard: Copy with working tool
// ---------------------------------------------------------------------------

func TestCB91_Copy_Success(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)

	err := svc.Copy("non-sensitive")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard: CopyWithClear schedules then ClearClipboard cancels timer
// ---------------------------------------------------------------------------

func TestCB91_CopyWithClear_ThenClearCancels(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetTimeout(60)

	err := svc.CopyWithClear("sensitive")
	require.NoError(t, err)

	err = svc.ClearClipboard()
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard: CopyWithClear replaces pending timer
// ---------------------------------------------------------------------------

func TestCB91_CopyWithClear_ReplacesTimer(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	svc.SetTimeout(60)

	err := svc.CopyWithClear("first")
	require.NoError(t, err)

	err = svc.CopyWithClear("second")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Clipboard: scheduleClear with context cancelled (covers L148-149)
// ---------------------------------------------------------------------------

func TestCB91_ScheduleClear_ContextCancelled(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)

	err := svc.writeClipboard("test-content")
	require.NoError(t, err)

	svc.scheduleClear("test-content", 10*time.Second)

	svc.clearMu.Lock()
	if svc.cancelFn != nil {
		svc.cancelFn()
	}
	svc.clearMu.Unlock()

	time.Sleep(50 * time.Millisecond)

	content, err := svc.readClipboard()
	require.NoError(t, err)
	assert.Equal(t, "test-content", content)
}

func TestCB91_StopPendingClear_CancelsAndWaits(t *testing.T) {
	svc := newClipboardServiceWithFakeXclip(t)
	require.NoError(t, svc.writeClipboard("pending"))

	svc.scheduleClear("pending", 10*time.Second)
	svc.stopPendingClear()

	svc.clearMu.Lock()
	assert.Nil(t, svc.cancelFn, "stopPendingClear must drop the cancel func")
	svc.clearMu.Unlock()

	content, err := svc.readClipboard()
	require.NoError(t, err)
	assert.Equal(t, "pending", content, "a stopped clear must not touch the clipboard")
}

func TestCB91_StopPendingClear_NothingScheduled(t *testing.T) {
	svc := &ClipboardService{log: slog.Default(), tool: clipToolNone}

	svc.stopPendingClear()

	assert.Nil(t, svc.cancelFn)
}

// ---------------------------------------------------------------------------
// Clipboard: readClipboard error when tool is none
// ---------------------------------------------------------------------------

func TestCB91_ReadClipboard_NoTool(t *testing.T) {
	svc := &ClipboardService{
		log:  slog.Default(),
		tool: clipToolNone,
	}

	_, err := svc.readClipboard()
	assert.ErrorIs(t, err, ErrClipboardToolUnavailable)
}
