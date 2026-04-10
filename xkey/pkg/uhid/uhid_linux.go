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
	file, err := os.OpenFile(UHIDDevicePath, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUHIDNotAvailable
		}
		return nil, fmt.Errorf("%w: %v", ErrUHIDNotAvailable, err)
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

	// Build the UHID_CREATE2 request
	buf := make([]byte, uhidEventHeaderSize+uhidCreate2ReqSize)

	// Event type
	binary.LittleEndian.PutUint32(buf[0:4], UHID_CREATE2)

	offset := uhidEventHeaderSize

	// Copy name (max 127 chars + null terminator)
	nameBytes := []byte(cfg.Name)
	if len(nameBytes) > 127 {
		nameBytes = nameBytes[:127]
	}
	copy(buf[offset:offset+128], nameBytes)
	offset += 128

	// Copy phys (max 63 chars + null terminator)
	physBytes := []byte(cfg.Phys)
	if len(physBytes) > 63 {
		physBytes = physBytes[:63]
	}
	copy(buf[offset:offset+64], physBytes)
	offset += 64

	// Copy uniq (max 63 chars + null terminator)
	uniqBytes := []byte(cfg.Uniq)
	if len(uniqBytes) > 63 {
		uniqBytes = uniqBytes[:63]
	}
	copy(buf[offset:offset+64], uniqBytes)
	offset += 64

	// Report descriptor
	rdesc := cfg.ReportDescriptor
	if rdesc == nil {
		rdesc = FIDO2HIDReportDescriptor
	}
	if len(rdesc) > MaxReportDescriptorSize {
		rdesc = rdesc[:MaxReportDescriptorSize]
	}

	// rd_size (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(rdesc)))
	offset += 2

	// bus (2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:offset+2], BUS_USB)
	offset += 2

	// vendor (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.VendorID))
	offset += 4

	// product (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.ProductID))
	offset += 4

	// version (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.Version))
	offset += 4

	// country (4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0)
	offset += 4

	// rd_data
	copy(buf[offset:], rdesc)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrDeviceNotOpen
	}

	n, err := d.file.Write(buf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceCreationFailed, err)
	}
	if n != len(buf) {
		return fmt.Errorf("%w: short write (%d/%d)", ErrDeviceCreationFailed, n, len(buf))
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
			return nil, fmt.Errorf("%w: failed to set deadline: %v", ErrReadFailed, err)
		}
	}

	// Read the event header + maximum possible data
	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)

	n, err := file.Read(buf)
	if err != nil {
		if os.IsTimeout(err) {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrReadFailed, err)
	}

	if n < uhidEventHeaderSize {
		return nil, fmt.Errorf("%w: short read (%d bytes)", ErrInvalidPacket, n)
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
		// Parse the output event
		// Linux kernel uhid_output_req structure (packed):
		//   __u8 data[UHID_DATA_MAX];  // 4096 bytes
		//   __u16 size;                // 2 bytes
		//   __u8 rtype;                // 1 byte
		// Total: 4099 bytes after event header

		// We need at least the header + size field location
		minLen := uhidEventHeaderSize + MaxReportDescriptorSize + 2
		if n < minLen {
			return nil, fmt.Errorf("%w: output event too short (%d bytes, need %d)", ErrInvalidPacket, n, minLen)
		}

		// Size is at offset 4096 (after data array)
		sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
		dataSize := binary.LittleEndian.Uint16(buf[sizeOffset : sizeOffset+2])
		// rtype := buf[sizeOffset+2] // Report type (not used for basic HID)

		if dataSize > MaxReportDescriptorSize {
			return nil, fmt.Errorf("%w: data size too large (%d)", ErrInvalidPacket, dataSize)
		}

		if dataSize == 0 {
			return nil, fmt.Errorf("%w: zero data size", ErrInvalidPacket)
		}

		// Data is at the beginning of the payload (after event header)
		// Note: When the HID report descriptor doesn't define explicit Report IDs,
		// the kernel prepends a Report ID byte (0x00) to the output data.
		// For FIDO2 HID, we expect 65 bytes (1 byte Report ID + 64 bytes HID packet).
		// We need to skip the Report ID byte to get the actual HID packet.
		dataStart := uhidEventHeaderSize
		actualSize := int(dataSize)

		// Check if there's a Report ID prefix (65 bytes instead of 64)
		if dataSize == HIDReportSize+1 {
			// Skip the Report ID byte (first byte)
			dataStart++
			actualSize = HIDReportSize
		}

		data := make([]byte, actualSize)
		copy(data, buf[dataStart:dataStart+actualSize])
		return data, nil

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
		return fmt.Errorf("%w: data too large (%d bytes)", ErrInvalidPacket, len(data))
	}

	// Build the UHID_INPUT2 request
	buf := make([]byte, uhidEventHeaderSize+uhidInput2ReqSize)

	// Event type
	binary.LittleEndian.PutUint32(buf[0:4], UHID_INPUT2)

	// Size (2 bytes)
	binary.LittleEndian.PutUint16(buf[uhidEventHeaderSize:uhidEventHeaderSize+2], uint16(len(data)))

	// Data (raw HID report without Report ID)
	copy(buf[uhidEventHeaderSize+2:], data)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrDeviceNotOpen
	}

	n, err := d.file.Write(buf)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	if n != len(buf) {
		return fmt.Errorf("%w: short write (%d/%d)", ErrWriteFailed, n, len(buf))
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

	// Send UHID_DESTROY if device was created
	if d.created.Load() {
		buf := make([]byte, uhidEventHeaderSize)
		binary.LittleEndian.PutUint32(buf[0:4], UHID_DESTROY)
		// Best effort - ignore errors during cleanup
		_, _ = d.file.Write(buf)
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
		return fmt.Errorf("failed to get file flags: %w", errno)
	}

	if nonBlocking {
		flags |= syscall.O_NONBLOCK
	} else {
		flags &^= syscall.O_NONBLOCK
	}

	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFL, flags)
	if errno != 0 {
		return fmt.Errorf("failed to set file flags: %w", errno)
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

// SerializeCreate2Request serializes a CreateConfig into a UHID_CREATE2 request buffer.
// This is useful for testing and debugging.
func SerializeCreate2Request(cfg *CreateConfig) []byte {
	if cfg == nil {
		cfg = DefaultCreateConfig()
	}

	buf := make([]byte, uhidEventHeaderSize+uhidCreate2ReqSize)

	// Event type
	binary.LittleEndian.PutUint32(buf[0:4], UHID_CREATE2)

	offset := uhidEventHeaderSize

	// Copy name
	nameBytes := []byte(cfg.Name)
	if len(nameBytes) > 127 {
		nameBytes = nameBytes[:127]
	}
	copy(buf[offset:offset+128], nameBytes)
	offset += 128

	// Copy phys
	physBytes := []byte(cfg.Phys)
	if len(physBytes) > 63 {
		physBytes = physBytes[:63]
	}
	copy(buf[offset:offset+64], physBytes)
	offset += 64

	// Copy uniq
	uniqBytes := []byte(cfg.Uniq)
	if len(uniqBytes) > 63 {
		uniqBytes = uniqBytes[:63]
	}
	copy(buf[offset:offset+64], uniqBytes)
	offset += 64

	// Report descriptor
	rdesc := cfg.ReportDescriptor
	if rdesc == nil {
		rdesc = FIDO2HIDReportDescriptor
	}
	if len(rdesc) > MaxReportDescriptorSize {
		rdesc = rdesc[:MaxReportDescriptorSize]
	}

	binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(len(rdesc)))
	offset += 2

	binary.LittleEndian.PutUint16(buf[offset:offset+2], BUS_USB)
	offset += 2

	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.VendorID))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.ProductID))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(cfg.Version))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:offset+4], 0) // country
	offset += 4

	copy(buf[offset:], rdesc)

	return buf
}

// SerializeInput2Request serializes data into a UHID_INPUT2 request buffer.
// This is useful for testing and debugging.
func SerializeInput2Request(data []byte) []byte {
	buf := make([]byte, uhidEventHeaderSize+uhidInput2ReqSize)

	binary.LittleEndian.PutUint32(buf[0:4], UHID_INPUT2)
	binary.LittleEndian.PutUint16(buf[uhidEventHeaderSize:uhidEventHeaderSize+2], uint16(len(data)))
	copy(buf[uhidEventHeaderSize+2:], data)

	return buf
}

// ParseOutputEvent parses a raw UHID_OUTPUT event buffer and returns the HID report data.
// This is useful for testing and debugging.
// Linux kernel uhid_output_req structure (packed):
//
//	__u8 data[UHID_DATA_MAX];  // 4096 bytes - data comes FIRST
//	__u16 size;                // 2 bytes - actual size of data
//	__u8 rtype;                // 1 byte - report type
//
// Note: When the HID report descriptor doesn't define explicit Report IDs,
// the kernel prepends a Report ID byte (0x00) to the output data.
// For FIDO2 HID, we expect 65 bytes (1 byte Report ID + 64 bytes HID packet).
// This function strips the Report ID byte and returns the raw 64-byte HID packet.
func ParseOutputEvent(buf []byte) ([]byte, error) {
	if len(buf) < uhidEventHeaderSize {
		return nil, fmt.Errorf("%w: buffer too short", ErrInvalidPacket)
	}

	eventType := binary.LittleEndian.Uint32(buf[0:4])
	if eventType != UHID_OUTPUT {
		return nil, fmt.Errorf("%w: not an output event (type=%d)", ErrInvalidPacket, eventType)
	}

	// Need header + data[4096] + size[2]
	minLen := uhidEventHeaderSize + MaxReportDescriptorSize + 2
	if len(buf) < minLen {
		return nil, fmt.Errorf("%w: output event too short (%d, need %d)", ErrInvalidPacket, len(buf), minLen)
	}

	// Size is at offset 4096 after the data array
	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	dataSize := binary.LittleEndian.Uint16(buf[sizeOffset : sizeOffset+2])
	if dataSize > MaxReportDescriptorSize {
		return nil, fmt.Errorf("%w: data size too large (%d)", ErrInvalidPacket, dataSize)
	}

	if dataSize == 0 {
		return nil, fmt.Errorf("%w: zero data size", ErrInvalidPacket)
	}

	// Data is at the beginning of the payload (after event header)
	// Check if there's a Report ID prefix (65 bytes instead of 64)
	dataStart := uhidEventHeaderSize
	actualSize := int(dataSize)

	if dataSize == HIDReportSize+1 {
		// Skip the Report ID byte (first byte)
		dataStart++
		actualSize = HIDReportSize
	}

	data := make([]byte, actualSize)
	copy(data, buf[dataStart:dataStart+actualSize])
	return data, nil
}
