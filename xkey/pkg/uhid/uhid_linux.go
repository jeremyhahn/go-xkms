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

//go:build linux

package uhid

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Device represents a UHID virtual HID device.
// All methods are safe for concurrent use.
type Device struct {
	file        *os.File
	created     atomic.Bool
	closed      atomic.Bool
	readTimeout time.Duration
	mu          sync.Mutex
}

// Open opens the UHID device at /dev/uhid.
// The caller must call Close when done with the device.
func Open() (*Device, error) {
	return openAt(UHIDDevicePath)
}

// openAt opens a UHID character device at the given path. Open delegates
// here so tests can exercise the not-available and permission-denied
// branches against a controlled path instead of depending on whether the
// host happens to expose /dev/uhid.
func openAt(path string) (*Device, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUHIDNotAvailable
		}
		return nil, &SentinelCauseError{Sentinel: ErrUHIDNotAvailable, Cause: err}
	}

	return &Device{
		file: file,
	}, nil
}

// Create creates a new virtual HID device with the given configuration.
// If cfg is nil, DefaultCreateConfig() is used.
func (d *Device) Create(cfg *CreateConfig) error {
	if d.closed.Load() {
		return ErrDeviceNotOpen
	}

	if d.created.Load() {
		return ErrDeviceAlreadyCreated
	}

	if cfg == nil {
		cfg = DefaultCreateConfig()
	}

	// Build the UHID_CREATE2 request with the shared codec so the bytes on
	// the wire are exactly the ones serialize.go's cross-platform tests
	// assert.
	buf := SerializeCreate2Request(cfg)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrDeviceNotOpen
	}

	n, err := d.file.Write(buf)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrDeviceCreationFailed, Cause: err}
	}
	if n != len(buf) {
		return &DetailError{Err: ErrDeviceCreationFailed, Detail: fmt.Sprintf(": short write (%d/%d)", n, len(buf))}
	}

	d.created.Store(true)
	return nil
}

// ReadOutput reads a UHID_OUTPUT event and returns the 64-byte HID report.
// This blocks until data is available or the read timeout expires.
// Returns ErrTimeout if a timeout is set and expires.
func (d *Device) ReadOutput() ([]byte, error) {
	if d.closed.Load() {
		return nil, ErrDeviceNotOpen
	}

	d.mu.Lock()
	if d.file == nil {
		d.mu.Unlock()
		return nil, ErrDeviceNotOpen
	}
	file := d.file
	timeout := d.readTimeout
	d.mu.Unlock()

	// Set read deadline if timeout is configured
	if timeout > 0 {
		if err := file.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, &DetailError{Err: ErrReadFailed, Detail: fmt.Sprintf(": failed to set deadline: %v", err)}
		}
	}

	// Read the event header + maximum possible data
	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)

	n, err := file.Read(buf)
	if err != nil {
		if os.IsTimeout(err) {
			return nil, ErrTimeout
		}
		return nil, &SentinelCauseError{Sentinel: ErrReadFailed, Cause: err}
	}

	if n < uhidEventHeaderSize {
		return nil, &DetailError{Err: ErrInvalidPacket, Detail: fmt.Sprintf(": short read (%d bytes)", n)}
	}

	// Parse event type
	eventType := binary.LittleEndian.Uint32(buf[0:4])

	// Debug log for event tracking
	// fmt.Printf("[UHID DEBUG] Read %d bytes, event type: %d\n", n, eventType)

	// Handle different event types
	switch eventType {
	case UHID_START, UHID_STOP, UHID_OPEN, UHID_CLOSE:
		// These are informational events, recursively read for actual data
		// fmt.Printf("[UHID DEBUG] Informational event type %d, reading next...\n", eventType)
		return d.ReadOutput()

	case UHID_OUTPUT:
		// Parsing lives in the shared codec (serialize.go) so the device
		// path and ParseOutputEvent can never drift apart. buf[:n] is
		// passed so a short read is reported as a malformed packet rather
		// than reading uninitialised tail bytes.
		return ParseOutputEvent(buf[:n])

	default:
		// Unknown event type, try reading again
		return d.ReadOutput()
	}
}

// WriteInput sends a HID input report (device to host) via UHID_INPUT2.
// The data should be a 64-byte HID packet for FIDO2 devices.
// Note: For UHID_INPUT2, we send raw report data WITHOUT the Report ID prefix.
// The kernel will add the appropriate Report ID when delivering to userspace
// applications reading from the hidraw device.
func (d *Device) WriteInput(data []byte) error {
	if d.closed.Load() {
		return ErrDeviceNotOpen
	}

	if len(data) > MaxReportDescriptorSize {
		return &DetailError{Err: ErrInvalidPacket, Detail: fmt.Sprintf(": data too large (%d bytes)", len(data))}
	}

	// Raw report data WITHOUT a report ID prefix: the kernel adds the
	// appropriate one when delivering to the hidraw reader.
	buf := SerializeInput2Request(data)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrDeviceNotOpen
	}

	n, err := d.file.Write(buf)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrWriteFailed, Cause: err}
	}
	if n != len(buf) {
		return &DetailError{Err: ErrWriteFailed, Detail: fmt.Sprintf(": short write (%d/%d)", n, len(buf))}
	}

	return nil
}

// Close destroys the UHID device and closes the file handle.
func (d *Device) Close() error {
	if d.closed.Swap(true) {
		return nil // Already closed
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return nil
	}

	// Send UHID_DESTROY if device was created. Best effort: the fd is
	// closed immediately below regardless, so a failed notification here
	// changes nothing about teardown, but it is logged since the kernel
	// would otherwise be left believing the device still exists.
	if d.created.Load() {
		buf := make([]byte, uhidEventHeaderSize)
		binary.LittleEndian.PutUint32(buf[0:4], UHID_DESTROY)
		if _, werr := d.file.Write(buf); werr != nil {
			slog.Debug("uhid: failed to send UHID_DESTROY during close", "error", werr)
		}
	}

	err := d.file.Close()
	d.file = nil
	return err
}

// SetReadTimeout sets the timeout for ReadOutput operations.
// A zero or negative duration means no timeout (blocking reads).
func (d *Device) SetReadTimeout(timeout time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.readTimeout = timeout
}

// SetNonBlocking sets the device file descriptor to non-blocking mode.
// This is useful for polling-based event loops.
func (d *Device) SetNonBlocking(nonBlocking bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrDeviceNotOpen
	}

	fd := d.file.Fd()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	if errno != 0 {
		return &WrappedError{Msg: "failed to get file flags", Err: errno}
	}

	if nonBlocking {
		flags |= syscall.O_NONBLOCK
	} else {
		flags &^= syscall.O_NONBLOCK
	}

	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFL, flags)
	if errno != 0 {
		return &WrappedError{Msg: "failed to set file flags", Err: errno}
	}

	return nil
}

// IsCreated returns true if the device has been created via Create().
func (d *Device) IsCreated() bool {
	return d.created.Load()
}

// IsClosed returns true if the device has been closed.
func (d *Device) IsClosed() bool {
	return d.closed.Load()
}

// Fd returns the file descriptor for the UHID device.
// This can be used for poll/epoll operations.
// Returns -1 if the device is not open.
func (d *Device) Fd() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return -1
	}

	return int(d.file.Fd())
}
