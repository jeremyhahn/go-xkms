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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// ffsPollInterval is the timeout set on each FunctionFS read cycle. Between
// cycles the transport checks for context cancellation, giving the caller
// responsive shutdown behaviour without busy-spinning.
const ffsPollInterval = 200 * time.Millisecond

// functionFSEvent is the kernel usb_functionfs_event structure read from ep0.
type functionFSEvent struct {
	// Type is the FunctionFS event type.
	Type byte
	_    [3]byte // padding
}

// FunctionFS event types from linux/usb/functionfs.h.
const (
	ffsEventBind    byte = 0
	ffsEventUnbind  byte = 1
	ffsEventEnable  byte = 2
	ffsEventDisable byte = 3
	ffsEventSetup   byte = 4
	ffsEventSuspend byte = 5
	ffsEventResume  byte = 6
)

// ffsEventNames maps event types to human-readable names for logging.
var ffsEventNames = map[byte]string{
	ffsEventBind:    "BIND",
	ffsEventUnbind:  "UNBIND",
	ffsEventEnable:  "ENABLE",
	ffsEventDisable: "DISABLE",
	ffsEventSetup:   "SETUP",
	ffsEventSuspend: "SUSPEND",
	ffsEventResume:  "RESUME",
}

// FunctionFSTransport implements Transport over a FunctionFS endpoint pair.
// It is used for the CCID function where true USB class support is needed
// (bInterfaceClass=0x0B rather than HID wrapping).
type FunctionFSTransport struct {
	mountDir string
	fs       FileSystem
	ep0      *os.File // control endpoint (descriptors + USB events)
	epOut    *os.File // bulk OUT: host -> device
	epIn     *os.File // bulk IN: device -> host
	running  atomic.Bool
	closed   atomic.Bool
	logger   *slog.Logger
}

// Compile-time interface check.
var _ Transport = (*FunctionFSTransport)(nil)

// NewFunctionFSTransport creates a new FunctionFS transport. The mountDir must
// be an existing FunctionFS mount point (e.g., /dev/ffs-ccid). The fs parameter
// is used for filesystem operations. Endpoints are not opened until Initialize
// is called.
func NewFunctionFSTransport(mountDir string, fs FileSystem, logger *slog.Logger) (*FunctionFSTransport, error) {
	if mountDir == "" {
		return nil, NewGadgetError("NewFunctionFSTransport", ErrFunctionFSMountFailed)
	}
	if fs == nil {
		return nil, NewGadgetError("NewFunctionFSTransport", ErrNilTransport)
	}
	if logger == nil {
		return nil, NewGadgetError("NewFunctionFSTransport", ErrNilLogger)
	}
	return &FunctionFSTransport{
		mountDir: mountDir,
		fs:       fs,
		logger:   logger,
	}, nil
}

// Initialize opens the FunctionFS control endpoint, writes USB descriptors
// and string descriptors, then opens the data endpoints. It starts a
// background goroutine to monitor FunctionFS lifecycle events on ep0.
func (t *FunctionFSTransport) Initialize(ctx context.Context) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}

	ep0Path := filepath.Join(t.mountDir, "ep0")
	ep0, err := os.OpenFile(ep0Path, os.O_RDWR, 0)
	if err != nil {
		return NewGadgetError("Initialize",
			fmt.Errorf("%w: %v", ErrEndpointOpenFailed, err))
	}
	t.ep0 = ep0

	// Write USB descriptors to ep0.
	descs := BuildCCIDDescriptors()
	if _, err := t.ep0.Write(descs); err != nil {
		t.ep0.Close()
		t.ep0 = nil
		return NewGadgetError("Initialize",
			fmt.Errorf("%w: %v", ErrDescriptorWriteFailed, err))
	}

	// Write string descriptors to ep0.
	strings := BuildFunctionFSStrings()
	if _, err := t.ep0.Write(strings); err != nil {
		t.ep0.Close()
		t.ep0 = nil
		return NewGadgetError("Initialize",
			fmt.Errorf("%w: %v", ErrDescriptorWriteFailed, err))
	}

	// Open bulk OUT endpoint (host -> device).
	epOutPath := filepath.Join(t.mountDir, "ep1")
	epOut, err := os.OpenFile(epOutPath, os.O_RDONLY, 0)
	if err != nil {
		t.ep0.Close()
		t.ep0 = nil
		return NewGadgetError("Initialize",
			fmt.Errorf("%w: ep1: %v", ErrEndpointOpenFailed, err))
	}
	t.epOut = epOut

	// Open bulk IN endpoint (device -> host).
	epInPath := filepath.Join(t.mountDir, "ep2")
	epIn, err := os.OpenFile(epInPath, os.O_WRONLY, 0)
	if err != nil {
		t.epOut.Close()
		t.epOut = nil
		t.ep0.Close()
		t.ep0 = nil
		return NewGadgetError("Initialize",
			fmt.Errorf("%w: ep2: %v", ErrEndpointOpenFailed, err))
	}
	t.epIn = epIn

	t.running.Store(true)
	t.logger.Info("FunctionFS transport initialized", "mount_dir", t.mountDir)

	// Start background event monitor.
	go t.monitorEvents(ctx)

	return nil
}

// Read blocks until a message is available from the host or the context
// is cancelled. It reads from the bulk OUT endpoint using a polling loop
// with short read deadlines to allow responsive context cancellation.
func (t *FunctionFSTransport) Read(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrTransportClosed
	}

	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if t.closed.Load() {
			return nil, ErrTransportClosed
		}

		// Set a short deadline so we can check for context cancellation.
		deadline := time.Now().Add(ffsPollInterval)
		t.epOut.SetReadDeadline(deadline)

		n, err := t.epOut.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			return nil, NewGadgetError("Read",
				fmt.Errorf("%w: %v", ErrEndpointIOFailed, err))
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		return data, nil
	}
}

// Write sends a response message to the host via the bulk IN endpoint.
// Returns ErrTransportClosed if the transport has been closed.
func (t *FunctionFSTransport) Write(data []byte) error {
	if t.closed.Load() {
		return ErrTransportClosed
	}

	if _, err := t.epIn.Write(data); err != nil {
		return NewGadgetError("Write",
			fmt.Errorf("%w: %v", ErrEndpointIOFailed, err))
	}
	return nil
}

// Close releases the FunctionFS transport by closing all endpoint file
// descriptors. Close is idempotent; calling it more than once returns nil.
func (t *FunctionFSTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	t.running.Store(false)
	t.logger.Info("closing FunctionFS transport")

	var firstErr error

	if t.epIn != nil {
		if err := t.epIn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.epIn = nil
	}
	if t.epOut != nil {
		if err := t.epOut.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.epOut = nil
	}
	if t.ep0 != nil {
		if err := t.ep0.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		t.ep0 = nil
	}

	if firstErr != nil {
		return NewGadgetError("Close", firstErr)
	}
	return nil
}

// MountDir returns the FunctionFS mount directory path.
func (t *FunctionFSTransport) MountDir() string {
	return t.mountDir
}

// monitorEvents reads FunctionFS lifecycle events from ep0 and logs them.
// It exits when the context is cancelled or ep0 is closed.
func (t *FunctionFSTransport) monitorEvents(ctx context.Context) {
	t.logger.Info("FunctionFS event monitor started")
	defer t.logger.Info("FunctionFS event monitor stopped")

	eventBuf := make([]byte, 4) // sizeof(functionFSEvent)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if t.closed.Load() || t.ep0 == nil {
			return
		}

		// Set a short deadline to allow checking context/closed state.
		t.ep0.SetReadDeadline(time.Now().Add(ffsPollInterval))

		n, err := t.ep0.Read(eventBuf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			if t.closed.Load() {
				return
			}
			// EOF or other error means ep0 was closed.
			if err == io.EOF {
				return
			}
			t.logger.Error("FunctionFS event read error", "error", err)
			return
		}

		if n < 4 {
			continue
		}

		var evt functionFSEvent
		evt.Type = eventBuf[0]

		name, ok := ffsEventNames[evt.Type]
		if !ok {
			name = fmt.Sprintf("UNKNOWN(%d)", evt.Type)
		}
		t.logger.Info("FunctionFS event", "event", name, "type", evt.Type)
	}
}
