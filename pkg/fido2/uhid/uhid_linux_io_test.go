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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSocketDevice creates a Device backed by one end of an AF_UNIX
// SOCK_DGRAM socketpair, with the other end returned for the test to drive
// as the "kernel" side. SOCK_DGRAM, unlike a pipe or a regular file,
// preserves write boundaries: each Write on the peer arrives as exactly one
// Read on the device side, the same framing /dev/uhid gives a real reader.
// This lets the informational-event and short-read branches of ReadOutput be
// exercised deterministically without a real UHID node.
func newSocketDevice(t *testing.T) (*Device, *os.File) {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	require.NoError(t, err)

	deviceEnd := os.NewFile(uintptr(fds[0]), "uhid-test-device")
	peerEnd := os.NewFile(uintptr(fds[1]), "uhid-test-peer")
	t.Cleanup(func() {
		_ = deviceEnd.Close()
		_ = peerEnd.Close()
	})

	return &Device{file: deviceEnd}, peerEnd
}

// encodeOutputEvent builds a raw UHID_OUTPUT event buffer of exactly
// uhidEventHeaderSize+uhidOutputEventSize bytes, matching what ParseOutputEvent
// expects, carrying the given report bytes.
func encodeOutputEvent(t *testing.T, report []byte) []byte {
	t.Helper()
	require.LessOrEqual(t, len(report), MaxReportDescriptorSize)

	buf := make([]byte, uhidEventHeaderSize+uhidOutputEventSize)
	binary.LittleEndian.PutUint32(buf[0:4], UHID_OUTPUT)
	copy(buf[uhidEventHeaderSize:], report)
	sizeOffset := uhidEventHeaderSize + MaxReportDescriptorSize
	binary.LittleEndian.PutUint16(buf[sizeOffset:sizeOffset+2], uint16(len(report)))
	return buf
}

func TestOpenAt_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-uhid")
	require.NoError(t, os.WriteFile(path, nil, 0600))

	device, err := openAt(path)
	require.NoError(t, err)
	require.NotNil(t, device)
	defer func() { _ = device.Close() }()

	assert.NotEqual(t, -1, device.Fd())
}

// TestOpen exercises Open() itself. Its behavior depends on whether the test
// host exposes /dev/uhid: either it opens successfully (root, uhid module
// loaded) or it returns the typed unavailable error. Both are the two
// legitimate outcomes of the one-line delegation to openAt.
func TestOpen(t *testing.T) {
	device, err := Open()
	if err == nil {
		require.NotNil(t, device)
		_ = device.Close()
		return
	}
	assert.True(t, errors.Is(err, ErrUHIDNotAvailable), "Open() error = %v, want ErrUHIDNotAvailable", err)
}

func TestDevice_Create_Success(t *testing.T) {
	device, peer := newSocketDevice(t)

	err := device.Create(DefaultCreateConfig())
	require.NoError(t, err)
	assert.True(t, device.IsCreated())

	buf := make([]byte, uhidEventHeaderSize+uhidCreate2ReqSize)
	n, err := peer.Read(buf)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
	assert.Equal(t, UHID_CREATE2, binary.LittleEndian.Uint32(buf[0:4]))
}

// TestDevice_ReadOutput_SkipsInformationalEvents proves ReadOutput
// recursively skips UHID_START/STOP/OPEN/CLOSE and returns the first
// UHID_OUTPUT event that follows, rather than reporting the informational
// event as data or an error.
func TestDevice_ReadOutput_SkipsInformationalEvents(t *testing.T) {
	device, peer := newSocketDevice(t)

	informational := make([]byte, uhidEventHeaderSize)
	binary.LittleEndian.PutUint32(informational, UHID_START)

	report := []byte{0xAA, 0xBB, 0xCC}

	go func() {
		_, _ = peer.Write(informational)
		_, _ = peer.Write(encodeOutputEvent(t, report))
	}()

	got, err := device.ReadOutput()
	require.NoError(t, err)
	assert.Equal(t, report, got)
}

// TestDevice_ReadOutput_SkipsUnknownEventType proves an event type outside
// the known set is treated the same as an informational event: skipped, not
// surfaced as an error.
func TestDevice_ReadOutput_SkipsUnknownEventType(t *testing.T) {
	device, peer := newSocketDevice(t)

	unknown := make([]byte, uhidEventHeaderSize)
	binary.LittleEndian.PutUint32(unknown, 0xDEAD)

	report := []byte{0x01}

	go func() {
		_, _ = peer.Write(unknown)
		_, _ = peer.Write(encodeOutputEvent(t, report))
	}()

	got, err := device.ReadOutput()
	require.NoError(t, err)
	assert.Equal(t, report, got)
}

// TestDevice_ReadOutput_ShortRead proves a datagram shorter than the event
// header is reported as a malformed packet rather than panicking on the
// header parse.
func TestDevice_ReadOutput_ShortRead(t *testing.T) {
	device, peer := newSocketDevice(t)

	go func() {
		_, _ = peer.Write([]byte{0x01, 0x02})
	}()

	_, err := device.ReadOutput()
	require.Error(t, err)

	var detail *DetailError
	require.ErrorAs(t, err, &detail)
	assert.ErrorIs(t, detail, ErrInvalidPacket)
	assert.Contains(t, err.Error(), "short read")
}

// TestDevice_ReadOutput_Timeout proves a configured read timeout surfaces as
// ErrTimeout rather than a generic read failure when no event arrives. It
// uses an os.Pipe rather than the socketpair helper: pipes are the one *os.File
// kind that reliably supports SetReadDeadline in every Go/kernel combination
// this package runs on, so the deadline itself (not its plumbing) is what
// gets exercised.
func TestDevice_ReadOutput_Timeout(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	device := &Device{file: r}
	device.SetReadTimeout(20 * time.Millisecond)

	_, err = device.ReadOutput()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTimeout), "ReadOutput() error = %v, want ErrTimeout", err)
}

// TestDevice_ReadOutput_SetDeadlineFails proves a file kind that rejects
// SetReadDeadline (the AF_UNIX socketpair used elsewhere in this file, which
// Go's runtime poller does not register for deadline support) is reported as
// a typed read failure naming the cause, not a panic or a silent block.
func TestDevice_ReadOutput_SetDeadlineFails(t *testing.T) {
	device, _ := newSocketDevice(t)
	device.SetReadTimeout(20 * time.Millisecond)

	_, err := device.ReadOutput()
	require.Error(t, err)

	var detail *DetailError
	require.ErrorAs(t, err, &detail)
	assert.ErrorIs(t, detail, ErrReadFailed)
	assert.Contains(t, err.Error(), "failed to set deadline")
}

// TestDevice_ReadOutput_ReadFailsAfterClose proves that reading from a
// device whose underlying fd was torn down out from under it (never done by
// Close, which always nils the field first) is reported as a typed read
// failure rather than panicking.
func TestDevice_ReadOutput_ReadFailsAfterClose(t *testing.T) {
	device, peer := newSocketDevice(t)
	_ = peer.Close()
	_ = device.file.Close()

	_, err := device.ReadOutput()
	require.Error(t, err)

	var sentinel *SentinelCauseError
	require.ErrorAs(t, err, &sentinel)
	assert.ErrorIs(t, sentinel, ErrReadFailed)
}

func TestDevice_WriteInput_Success(t *testing.T) {
	device, peer := newSocketDevice(t)

	report := make([]byte, HIDReportSize)
	for i := range report {
		report[i] = byte(255 - i)
	}

	require.NoError(t, device.WriteInput(report))

	buf := make([]byte, uhidEventHeaderSize+uhidInput2ReqSize)
	n, err := peer.Read(buf)
	require.NoError(t, err)
	require.Equal(t, len(buf), n)
	assert.Equal(t, UHID_INPUT2, binary.LittleEndian.Uint32(buf[0:4]))
	size := binary.LittleEndian.Uint16(buf[uhidEventHeaderSize : uhidEventHeaderSize+2])
	assert.Equal(t, uint16(len(report)), size)
	assert.Equal(t, report, buf[uhidEventHeaderSize+2:uhidEventHeaderSize+2+len(report)])
}

func TestDevice_Close_SendsDestroyWhenCreated(t *testing.T) {
	device, peer := newSocketDevice(t)
	device.created.Store(true)

	require.NoError(t, device.Close())
	assert.True(t, device.IsClosed())

	buf := make([]byte, uhidEventHeaderSize)
	n, err := peer.Read(buf)
	require.NoError(t, err)
	require.Equal(t, uhidEventHeaderSize, n)
	assert.Equal(t, UHID_DESTROY, binary.LittleEndian.Uint32(buf[0:4]))
}

// TestDevice_Close_ReportsCloseError proves a failure closing the underlying
// file descriptor is surfaced to the caller rather than silently swallowed.
func TestDevice_Close_ReportsCloseError(t *testing.T) {
	device, peer := newSocketDevice(t)
	_ = peer.Close()

	// Close the raw fd out from under the *os.File so the subsequent
	// Device.Close() -> file.Close() fails with EBADF instead of succeeding.
	require.NoError(t, syscall.Close(int(device.file.Fd())))

	err := device.Close()
	assert.Error(t, err)
	assert.True(t, device.IsClosed())
}

func TestDevice_Fd_Open(t *testing.T) {
	device, _ := newSocketDevice(t)

	fd := device.Fd()
	assert.NotEqual(t, -1, fd)
	assert.Equal(t, int(device.file.Fd()), fd)
}

func TestDevice_SetNonBlocking(t *testing.T) {
	device, _ := newSocketDevice(t)

	require.NoError(t, device.SetNonBlocking(true))
	require.NoError(t, device.SetNonBlocking(false))
}

// TestDevice_SetNonBlocking_FcntlFails proves a failing fcntl (bad fd) is
// reported as a typed WrappedError rather than an unchecked errno.
func TestDevice_SetNonBlocking_FcntlFails(t *testing.T) {
	device, peer := newSocketDevice(t)
	_ = peer.Close()
	require.NoError(t, syscall.Close(int(device.file.Fd())))

	err := device.SetNonBlocking(true)
	require.Error(t, err)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to get file flags", wrapped.Msg)
}
