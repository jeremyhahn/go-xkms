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

// Package keyboard provides a virtual USB HID keyboard device using Linux UHID.
// It emulates USB keyboard input for typing static passwords and other text
// sequences through the standard USB Boot Protocol keyboard interface.
package keyboard

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/uhid"
)

const (
	// VendorIDKeyboard is the USB vendor ID for the virtual keyboard.
	VendorIDKeyboard uint16 = 0xF1D0

	// ProductIDKeyboard is the USB product ID for the virtual keyboard.
	ProductIDKeyboard uint16 = 0x0004

	// KeystrokeDelay is the delay between keystrokes to prevent OS input buffer issues.
	KeystrokeDelay = 5 * time.Millisecond

	// KeyboardReportSize is the size of a keyboard HID report in bytes.
	// Format: [modifier, reserved, keycode1, keycode2, keycode3, keycode4, keycode5, keycode6]
	KeyboardReportSize = 8

	// ModifierLeftShift is the Left Shift modifier bit in the modifier byte.
	ModifierLeftShift byte = 0x02
)

// DeviceWriter abstracts the UHID device for testability.
type DeviceWriter interface {
	// WriteInput sends a HID input report (device to host).
	WriteInput(data []byte) error

	// Close destroys the device and releases resources.
	Close() error
}

// UHIDDevice extends DeviceWriter with the Create method required for device initialization.
type UHIDDevice interface {
	DeviceWriter

	// Create creates the HID device with the given configuration.
	Create(cfg *uhid.CreateConfig) error
}

// UHIDOpener is a function that opens a UHID device.
// This is used for dependency injection in tests.
type UHIDOpener func() (UHIDDevice, error)

// defaultUHIDOpener is the production UHID opener that calls uhid.Open().
func defaultUHIDOpener() (UHIDDevice, error) {
	return uhid.Open()
}

// uhidOpener is the package-level UHID opener function.
// Tests can replace this to inject mock devices.
var uhidOpener UHIDOpener = defaultUHIDOpener

// Keyboard manages a virtual USB HID keyboard device via UHID.
// All methods are safe for concurrent use.
type Keyboard struct {
	device DeviceWriter
	closed atomic.Bool
	mu     sync.Mutex // serializes typing operations
	logger *slog.Logger
}

// New creates a new virtual keyboard by opening a UHID device and registering
// a USB Boot Protocol keyboard with the Linux kernel. The caller must call
// Close when the keyboard is no longer needed.
func New(logger *slog.Logger) (*Keyboard, error) {
	device, err := uhidOpener()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyboardOpenFailed, err)
	}

	cfg := &uhid.CreateConfig{
		Name:             "xKey Keyboard",
		Phys:             "xkey-keyboard",
		Uniq:             fmt.Sprintf("FK-KB-%d", time.Now().UnixNano()),
		VendorID:         VendorIDKeyboard,
		ProductID:        ProductIDKeyboard,
		Version:          0x0100,
		ReportDescriptor: BootKeyboardReportDescriptor,
	}

	if err := device.Create(cfg); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("%w: %v", ErrKeyboardCreateFailed, err)
	}

	logger.Info("virtual keyboard created",
		slog.String("name", cfg.Name),
		slog.String("uniq", cfg.Uniq))

	return &Keyboard{
		device: device,
		logger: logger,
	}, nil
}

// NewWithDevice creates a Keyboard backed by the given DeviceWriter.
// This constructor is intended for testing where a mock device replaces the
// real UHID subsystem.
func NewWithDevice(device DeviceWriter, logger *slog.Logger) *Keyboard {
	return &Keyboard{
		device: device,
		logger: logger,
	}
}

// TypeString types each character of the string as sequential keystrokes.
// Each character is looked up in the US keyboard scancode map, pressed, and
// released with a short delay between keystrokes to avoid OS input buffer
// saturation.
func (k *Keyboard) TypeString(s string) error {
	if len(s) == 0 {
		return ErrEmptyString
	}

	if k.closed.Load() {
		return ErrKeyboardClosed
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	for i, r := range s {
		mapping, ok := LookupScancode(r)
		if !ok {
			return fmt.Errorf("%w: %q (U+%04X) at position %d",
				ErrUnsupportedChar, string(r), r, i)
		}

		if err := k.typeKey(mapping.Scancode, mapping.Shift); err != nil {
			return fmt.Errorf("%w: %v", ErrTypeFailed, err)
		}

		// Delay between keystrokes to prevent host input buffer overrun.
		// Skip delay after the last character.
		if i < len([]rune(s))-1 {
			time.Sleep(KeystrokeDelay)
		}
	}

	return nil
}

// TypeKey sends a complete key press and release sequence for a single key.
// If shift is true, the Left Shift modifier is held during the key press.
func (k *Keyboard) TypeKey(scancode byte, shift bool) error {
	if k.closed.Load() {
		return ErrKeyboardClosed
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	return k.typeKey(scancode, shift)
}

// typeKey is the internal implementation that sends the key-down and key-up
// HID reports. The caller must hold k.mu.
func (k *Keyboard) typeKey(scancode byte, shift bool) error {
	// Build key-down report: [modifier, reserved, scancode, 0, 0, 0, 0, 0]
	report := make([]byte, KeyboardReportSize)
	if shift {
		report[0] = ModifierLeftShift
	}
	report[2] = scancode

	// Send key-down
	if err := k.device.WriteInput(report); err != nil {
		return err
	}

	// Send key-up (all zeros releases all keys)
	release := make([]byte, KeyboardReportSize)
	if err := k.device.WriteInput(release); err != nil {
		return err
	}

	return nil
}

// Close destroys the virtual keyboard device and releases all resources.
// Close is idempotent; calling it multiple times is safe and returns nil
// on subsequent calls.
func (k *Keyboard) Close() error {
	if k.closed.Swap(true) {
		return nil
	}

	k.logger.Info("closing virtual keyboard")
	return k.device.Close()
}
