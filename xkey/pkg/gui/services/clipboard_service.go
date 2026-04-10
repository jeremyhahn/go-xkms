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
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultClipboardTimeout is the default number of seconds before the
// clipboard is cleared after a sensitive copy operation.
const DefaultClipboardTimeout = 30

// clipboardTool identifies which clipboard command line tool to use.
type clipboardTool int

const (
	clipToolNone clipboardTool = iota
	clipToolXclip
	clipToolXsel
	clipToolWlCopy
)

// ClipboardService manages clipboard operations with automatic clearing
// of sensitive data. It is bound to the Wails runtime so every exported
// method is callable from the frontend.
type ClipboardService struct {
	ctx      context.Context
	log      *slog.Logger
	timeout  atomic.Int32
	clearMu  sync.Mutex
	cancelFn context.CancelFunc
	tool     clipboardTool
}

// NewClipboardService creates a new ClipboardService with the default timeout.
func NewClipboardService() *ClipboardService {
	svc := &ClipboardService{
		log:  slog.Default().With("service", "clipboard"),
		tool: detectClipboardTool(),
	}
	svc.timeout.Store(int32(DefaultClipboardTimeout))
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *ClipboardService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetTimeout sets the clipboard auto-clear timeout in seconds. A value of
// 0 disables automatic clearing.
func (s *ClipboardService) SetTimeout(seconds int) {
	if seconds < 0 {
		seconds = 0
	}
	s.timeout.Store(int32(seconds))
}

// GetTimeout returns the current auto-clear timeout in seconds.
func (s *ClipboardService) GetTimeout() int {
	return int(s.timeout.Load())
}

// CopyWithClear copies text to the clipboard and schedules automatic
// clearing after the configured timeout. Any previously pending clear
// timer is cancelled. The text is copied into a mutable byte slice and
// zeroized after the clipboard write completes, reducing the window
// during which sensitive data is resident in memory.
func (s *ClipboardService) CopyWithClear(text string) error {
	if s.tool == clipToolNone {
		return ErrClipboardToolUnavailable
	}

	// Copy text into a mutable byte slice so we can zeroize it after use.
	sensitive := []byte(text)
	defer zeroBytes(sensitive)

	if err := s.writeClipboardBytes(sensitive); err != nil {
		return err
	}

	timeout := int(s.timeout.Load())
	if timeout <= 0 {
		return nil
	}

	s.scheduleClear(text, time.Duration(timeout)*time.Second)
	return nil
}

// Copy copies text to the clipboard without scheduling auto-clear.
// Use this for non-sensitive data.
func (s *ClipboardService) Copy(text string) error {
	if s.tool == clipToolNone {
		return ErrClipboardToolUnavailable
	}
	return s.writeClipboard(text)
}

// ClearClipboard clears the clipboard immediately. It always cancels any
// pending auto-clear timer, even if the clipboard tool is unavailable.
// The clipboard is first overwritten with a space character before being
// cleared to ensure the clipboard tool's internal buffer is overwritten,
// reducing the chance of data remnants.
func (s *ClipboardService) ClearClipboard() error {
	// Always cancel pending auto-clear timers first.
	s.clearMu.Lock()
	if s.cancelFn != nil {
		s.cancelFn()
		s.cancelFn = nil
	}
	s.clearMu.Unlock()

	if s.tool == clipToolNone {
		return ErrClipboardToolUnavailable
	}

	// Overwrite clipboard with a single space first, then clear.
	// This ensures the clipboard tool's internal buffer is overwritten
	// before being cleared, reducing the chance of data remnants.
	_ = s.writeClipboard(" ")
	return s.writeClipboard("")
}

// scheduleClear starts a goroutine that clears the clipboard after the
// given duration, but only if the clipboard still contains the same text.
// The expected text is held as a byte slice and zeroized after use.
func (s *ClipboardService) scheduleClear(expectedText string, delay time.Duration) {
	s.clearMu.Lock()
	defer s.clearMu.Unlock()

	// Cancel previous pending clear.
	if s.cancelFn != nil {
		s.cancelFn()
	}

	// Keep a copy of the expected text for comparison.
	// This will be zeroized after the clear operation.
	expected := []byte(expectedText)

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFn = cancel

	go func() {
		defer zeroBytes(expected)

		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Check if clipboard still has the same content.
			current, err := s.readClipboard()
			if err != nil {
				s.log.Debug("failed to read clipboard for clear check", "error", err)
				return
			}

			if strings.TrimSpace(current) == strings.TrimSpace(string(expected)) {
				// Overwrite first, then clear.
				_ = s.writeClipboard(" ")
				if err := s.writeClipboard(""); err != nil {
					s.log.Debug("failed to clear clipboard", "error", err)
				} else {
					s.log.Debug("clipboard cleared after timeout")
				}
			}
		}
	}()
}

// writeClipboard writes text to the system clipboard.
func (s *ClipboardService) writeClipboard(text string) error {
	return s.writeClipboardBytes([]byte(text))
}

// writeClipboardBytes writes data to the system clipboard from a byte slice.
func (s *ClipboardService) writeClipboardBytes(data []byte) error {
	var cmd *exec.Cmd

	switch s.tool {
	case clipToolXclip:
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case clipToolXsel:
		cmd = exec.Command("xsel", "--clipboard", "--input")
	case clipToolWlCopy:
		cmd = exec.Command("wl-copy")
	default:
		return ErrClipboardToolUnavailable
	}

	cmd.Stdin = bytes.NewReader(data)

	if err := cmd.Run(); err != nil {
		return ErrClipboardWriteFailed
	}

	return nil
}

// readClipboard reads text from the system clipboard.
func (s *ClipboardService) readClipboard() (string, error) {
	var cmd *exec.Cmd

	switch s.tool {
	case clipToolXclip:
		cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
	case clipToolXsel:
		cmd = exec.Command("xsel", "--clipboard", "--output")
	case clipToolWlCopy:
		cmd = exec.Command("wl-paste", "--no-newline")
	default:
		return "", ErrClipboardToolUnavailable
	}

	out, err := cmd.Output()
	if err != nil {
		return "", ErrClipboardReadFailed
	}

	return string(out), nil
}

// detectClipboardTool finds the first available clipboard tool on the system.
func detectClipboardTool() clipboardTool {
	if _, err := exec.LookPath("xclip"); err == nil {
		return clipToolXclip
	}
	if _, err := exec.LookPath("xsel"); err == nil {
		return clipToolXsel
	}
	if _, err := exec.LookPath("wl-copy"); err == nil {
		return clipToolWlCopy
	}
	return clipToolNone
}
