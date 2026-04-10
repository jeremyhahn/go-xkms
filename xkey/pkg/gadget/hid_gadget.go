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

package gadget

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

const (
	// hidReportSize is the standard HID report size for FIDO2 CTAP-HID.
	hidReportSize = 64

	// hidReadTimeout is the polling timeout for context-aware reads.
	hidReadTimeout = 200 * time.Millisecond

	// defaultHIDGadgetPath is the default HID gadget device path.
	defaultHIDGadgetPath = "/dev/hidg0"
)

// HIDGadgetTransport implements Transport over a /dev/hidgN device file
// created by the kernel f_hid USB gadget function. This is used for
// FIDO2/CTAP-HID where the kernel handles HID class protocol and
// exposes a simple character device for report exchange.
type HIDGadgetTransport struct {
	devPath string
	file    *os.File
	closed  atomic.Bool
	logger  *slog.Logger
}

// Compile-time interface check.
var _ Transport = (*HIDGadgetTransport)(nil)

// NewHIDGadgetTransport creates a new HID gadget transport for the given
// device path. The device file is opened immediately. If devPath is empty,
// the default path /dev/hidg0 is used.
func NewHIDGadgetTransport(devPath string, logger *slog.Logger) (*HIDGadgetTransport, error) {
	if logger == nil {
		return nil, ErrNilLogger
	}
	if devPath == "" {
		devPath = defaultHIDGadgetPath
	}
	file, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		return nil, NewGadgetError("OpenHIDGadget", fmt.Errorf("%w: %v", ErrEndpointOpenFailed, err))
	}
	logger.Info("opened HID gadget device", "path", devPath)
	return &HIDGadgetTransport{
		devPath: devPath,
		file:    file,
		logger:  logger,
	}, nil
}

// Read blocks until a HID OUT report is available from the host or the
// context is cancelled. The blocking read runs in a goroutine so that
// context cancellation remains responsive. The goroutine exits when
// Close closes the underlying file descriptor.
func (t *HIDGadgetTransport) Read(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrTransportClosed
	}

	type readResult struct {
		data []byte
		err  error
	}

	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, hidReportSize)
		n, err := t.file.Read(buf)
		if err != nil {
			ch <- readResult{nil, err}
			return
		}
		ch <- readResult{buf[:n], nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		if result.err != nil {
			return nil, NewGadgetError("Read", fmt.Errorf("%w: %v", ErrEndpointIOFailed, result.err))
		}
		return result.data, nil
	}
}

// Write sends a HID IN report to the host via the gadget device file.
// Returns ErrTransportClosed if the transport has been closed.
func (t *HIDGadgetTransport) Write(data []byte) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}
	_, err := t.file.Write(data)
	if err != nil {
		return NewGadgetError("Write", fmt.Errorf("%w: %v", ErrEndpointIOFailed, err))
	}
	return nil
}

// Close releases the transport by closing the underlying device file.
// Close is idempotent; calling it more than once returns nil.
func (t *HIDGadgetTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.logger.Info("closing HID gadget transport", "path", t.devPath)
	return t.file.Close()
}

// DevicePath returns the device file path used by this transport.
func (t *HIDGadgetTransport) DevicePath() string {
	return t.devPath
}
