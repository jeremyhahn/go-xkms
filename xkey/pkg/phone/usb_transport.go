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

package phone

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gousb"
)

// USB transport constants.
const (
	// DefaultUSBOperationTimeout is the default timeout for individual
	// send/receive operations over USB. Set to 60 seconds to account
	// for biometric verification on the phone.
	DefaultUSBOperationTimeout = 60 * time.Second

	// MaxUSBMessageSize is the maximum message payload size (1 MB),
	// matching the Android UsbAccessoryServer framing.
	MaxUSBMessageSize = 1024 * 1024

	// usbFrameHeaderSize is the size of the 4-byte big-endian length prefix.
	usbFrameHeaderSize = 4

	// usbBulkTransferSize is the maximum size for a single USB bulk transfer.
	usbBulkTransferSize = 16384
)

// Compile-time interface check.
var _ Transport = (*USBTransport)(nil)

// USBTransportConfig configures the USB transport for phone communication.
type USBTransportConfig struct {
	// OperationTimeout is the timeout for individual send/receive operations.
	OperationTimeout time.Duration

	// Logger is the structured logger.
	Logger *slog.Logger
}

// DefaultUSBTransportConfig returns default configuration values.
func DefaultUSBTransportConfig() *USBTransportConfig {
	return &USBTransportConfig{
		OperationTimeout: DefaultUSBOperationTimeout,
		Logger:           slog.Default(),
	}
}

// USBTransport implements Transport over USB Accessory Mode (AOA).
// It uses 4-byte big-endian length-prefixed framing for message boundaries,
// matching the Android UsbAccessoryServer protocol.
type USBTransport struct {
	cfg *USBTransportConfig
	log *slog.Logger

	mu     sync.Mutex
	usbCtx *gousb.Context
	device *gousb.Device
	intf   *gousb.Interface
	inEP   *gousb.InEndpoint
	outEP  *gousb.OutEndpoint

	connected atomic.Bool
	closed    atomic.Bool
}

// NewUSBTransport creates a new USB transport with the given configuration.
// The transport is created in a disconnected state; call Connect to establish
// a connection to the phone.
func NewUSBTransport(cfg *USBTransportConfig) (*USBTransport, error) {
	if cfg == nil {
		cfg = DefaultUSBTransportConfig()
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = DefaultUSBOperationTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &USBTransport{
		cfg: cfg,
		log: cfg.Logger.With("component", "usb_transport"),
	}, nil
}

// Connect enumerates USB devices, triggers AOA mode if necessary, and
// opens the bulk endpoints for communication.
func (t *USBTransport) Connect(ctx context.Context) error {
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if t.connected.Load() {
		return nil
	}

	t.log.Debug("connecting to phone via USB AOA")

	usbCtx := gousb.NewContext()

	// First, look for a device already in AOA mode.
	dev, err := t.findAOADevice(usbCtx)
	if err != nil {
		// No AOA device found — try to switch an Android device into AOA mode.
		t.log.Debug("no AOA device found, attempting AOA switchover")
		if switchErr := t.switchToAOA(usbCtx); switchErr != nil {
			usbCtx.Close()
			t.log.Error("AOA switchover failed", "error", switchErr)
			return ErrConnectionFailed
		}

		// Wait for the device to re-enumerate in AOA mode.
		time.Sleep(2 * time.Second)

		// Re-open the USB context after switchover.
		usbCtx.Close()
		usbCtx = gousb.NewContext()

		dev, err = t.findAOADevice(usbCtx)
		if err != nil {
			usbCtx.Close()
			t.log.Error("AOA device not found after switchover", "error", err)
			return ErrConnectionFailed
		}
	}

	// Set auto-detach kernel driver so we can claim the interface.
	dev.SetAutoDetach(true)

	// Open the default configuration and claim interface 0.
	cfg, err := dev.Config(1)
	if err != nil {
		dev.Close()
		usbCtx.Close()
		t.log.Error("failed to get USB config", "error", err)
		return ErrConnectionFailed
	}

	intf, err := cfg.Interface(0, 0)
	if err != nil {
		cfg.Close()
		dev.Close()
		usbCtx.Close()
		t.log.Error("failed to claim USB interface", "error", err)
		return ErrConnectionFailed
	}

	// Find bulk IN and OUT endpoints.
	var inEP *gousb.InEndpoint
	var outEP *gousb.OutEndpoint

	for _, ep := range intf.Setting.Endpoints {
		if ep.Direction == gousb.EndpointDirectionIn {
			inEP, err = intf.InEndpoint(ep.Number)
			if err != nil {
				t.log.Error("failed to open IN endpoint", "error", err)
				continue
			}
		} else {
			outEP, err = intf.OutEndpoint(ep.Number)
			if err != nil {
				t.log.Error("failed to open OUT endpoint", "error", err)
				continue
			}
		}
	}

	if inEP == nil || outEP == nil {
		intf.Close()
		cfg.Close()
		dev.Close()
		usbCtx.Close()
		t.log.Error("USB AOA device missing bulk endpoints")
		return ErrConnectionFailed
	}

	t.mu.Lock()
	t.usbCtx = usbCtx
	t.device = dev
	t.intf = intf
	t.inEP = inEP
	t.outEP = outEP
	t.mu.Unlock()

	t.connected.Store(true)
	t.log.Info("connected to phone via USB AOA")
	return nil
}

// findAOADevice searches for a USB device already in AOA accessory mode.
func (t *USBTransport) findAOADevice(usbCtx *gousb.Context) (*gousb.Device, error) {
	devs, err := usbCtx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return IsAOADevice(uint16(desc.Vendor), uint16(desc.Product))
	})
	if err != nil {
		return nil, err
	}

	if len(devs) == 0 {
		return nil, fmt.Errorf("no AOA device found")
	}

	// Use the first matching device, close extras.
	for i := 1; i < len(devs); i++ {
		devs[i].Close()
	}

	return devs[0], nil
}

// switchToAOA finds the first Android device and sends AOA control transfers
// to switch it into accessory mode.
func (t *USBTransport) switchToAOA(usbCtx *gousb.Context) error {
	// Open all USB devices to find an Android phone.
	devs, err := usbCtx.OpenDevices(func(_ *gousb.DeviceDesc) bool {
		return true // Open all devices, filter below
	})
	if err != nil {
		return fmt.Errorf("failed to enumerate USB devices: %w", err)
	}

	defer func() {
		for _, d := range devs {
			d.Close()
		}
	}()

	for _, dev := range devs {
		// Try to get AOA protocol version.
		buf := make([]byte, 2)
		n, err := dev.Control(
			gousb.ControlIn|gousb.ControlVendor|gousb.ControlDevice,
			AOARequestGetProtocol, 0, 0, buf,
		)
		if err != nil || n < 2 {
			continue // Not an AOA-capable device
		}

		version := binary.LittleEndian.Uint16(buf[:2])
		if version < 1 {
			continue
		}

		t.log.Debug("found AOA-capable device", "version", version)

		// Send accessory identification strings.
		strings := []struct {
			index uint16
			value string
		}{
			{AOAStringManufacturer, XKeyAOAManufacturer},
			{AOAStringModel, XKeyAOAModel},
			{AOAStringDescription, XKeyAOADescription},
			{AOAStringVersion, XKeyAOAVersion},
		}

		for _, s := range strings {
			data := append([]byte(s.value), 0) // null-terminated
			_, err := dev.Control(
				gousb.ControlOut|gousb.ControlVendor|gousb.ControlDevice,
				AOARequestSendString, 0, s.index, data,
			)
			if err != nil {
				return fmt.Errorf("failed to send AOA string %d: %w", s.index, err)
			}
		}

		// Start accessory mode.
		_, err = dev.Control(
			gousb.ControlOut|gousb.ControlVendor|gousb.ControlDevice,
			AOARequestStart, 0, 0, nil,
		)
		if err != nil {
			return fmt.Errorf("failed to start AOA mode: %w", err)
		}

		t.log.Info("AOA switchover initiated")
		return nil
	}

	return ErrDeviceNotFound
}

// Send transmits a length-prefixed message to the connected phone.
func (t *USBTransport) Send(ctx context.Context, message []byte) error {
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if !t.connected.Load() {
		return ErrNotConnected
	}
	if len(message) > MaxUSBMessageSize {
		return ErrProtocolError
	}

	t.mu.Lock()
	outEP := t.outEP
	t.mu.Unlock()

	if outEP == nil {
		return ErrNotConnected
	}

	// Build the framed message: [4-byte big-endian length][payload]
	frame := make([]byte, usbFrameHeaderSize+len(message))
	binary.BigEndian.PutUint32(frame[:usbFrameHeaderSize], uint32(len(message)))
	copy(frame[usbFrameHeaderSize:], message)

	// Write in chunks matching bulk transfer size.
	for offset := 0; offset < len(frame); {
		end := offset + usbBulkTransferSize
		if end > len(frame) {
			end = len(frame)
		}
		n, err := outEP.WriteContext(ctx, frame[offset:end])
		if err != nil {
			t.handleWriteError(err)
			return ErrConnectionFailed
		}
		offset += n
	}

	t.log.Debug("sent USB message", "size", len(message))
	return nil
}

// Receive reads a complete length-prefixed message from the phone.
func (t *USBTransport) Receive(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !t.connected.Load() {
		return nil, ErrNotConnected
	}

	t.mu.Lock()
	inEP := t.inEP
	t.mu.Unlock()

	if inEP == nil {
		return nil, ErrNotConnected
	}

	// Read the 4-byte length header.
	header := make([]byte, usbFrameHeaderSize)
	if err := t.readFull(ctx, inEP, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return []byte{}, nil
	}
	if length > MaxUSBMessageSize {
		t.log.Error("USB message too large", "size", length)
		return nil, ErrProtocolError
	}

	// Read the payload.
	payload := make([]byte, length)
	if err := t.readFull(ctx, inEP, payload); err != nil {
		return nil, err
	}

	t.log.Debug("received USB message", "size", length)
	return payload, nil
}

// readFull reads exactly len(buf) bytes from the USB IN endpoint.
func (t *USBTransport) readFull(ctx context.Context, inEP *gousb.InEndpoint, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		n, err := inEP.ReadContext(ctx, buf[offset:])
		if err != nil {
			if err == io.EOF {
				t.connected.Store(false)
				return ErrNotConnected
			}
			t.connected.Store(false)
			return ErrConnectionFailed
		}
		offset += n
	}
	return nil
}

// SendAndReceive sends a message and waits for the response.
func (t *USBTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := t.Send(ctx, message); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

// IsConnected returns true if the transport is currently connected.
func (t *USBTransport) IsConnected() bool {
	return t.connected.Load() && !t.closed.Load()
}

// Close closes the transport permanently and releases all resources.
// After Close, the transport cannot be reconnected.
func (t *USBTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	t.log.Debug("closing USB transport")
	t.connected.Store(false)

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.intf != nil {
		t.intf.Close()
		t.intf = nil
	}

	if t.device != nil {
		t.device.Close()
		t.device = nil
	}

	if t.usbCtx != nil {
		t.usbCtx.Close()
		t.usbCtx = nil
	}

	t.inEP = nil
	t.outEP = nil

	return nil
}

// handleWriteError updates connection state on write failures.
func (t *USBTransport) handleWriteError(err error) {
	t.log.Error("USB write error", "error", err)
	t.connected.Store(false)
}
