// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend/software"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/uhid"
)

// Device lifecycle errors.
var (
	// ErrDeviceAlreadyRunning indicates the device event loop is already running.
	ErrDeviceAlreadyRunning = errors.New("vfido2: device already running")

	// ErrDeviceNotRunning indicates the device event loop is not running.
	ErrDeviceNotRunning = errors.New("vfido2: device not running")

	// ErrStorageCreationFailed indicates the storage backend could not be created.
	ErrStorageCreationFailed = errors.New("vfido2: storage creation failed")

	// ErrAuthenticatorCreationFailed indicates the authenticator could not be created.
	ErrAuthenticatorCreationFailed = errors.New("vfido2: authenticator creation failed")

	// ErrUHIDOpenFailed indicates the UHID device could not be opened.
	ErrUHIDOpenFailed = errors.New("vfido2: UHID open failed")

	// ErrUHIDCreateFailed indicates the virtual HID device could not be created.
	ErrUHIDCreateFailed = errors.New("vfido2: UHID create failed")

	// ErrPINSetFailed indicates the initial PIN could not be set.
	ErrPINSetFailed = errors.New("vfido2: PIN set failed")
)

// VirtualFIDO2Device manages the virtual FIDO2 USB device.
// It bridges UHID to the FIDO2 authenticator, handling HID packet
// framing and CTAP2 command processing.
//
// All methods are safe for concurrent use.
type VirtualFIDO2Device struct {
	cfg        *Config
	logger     *slog.Logger
	uhidDevice *uhid.Device
	auth       *authenticator.Authenticator
	hidHandler *authenticator.CTAPHIDHandler
	storage    authenticator.StatefulCredentialStorage
	keyBackend keybackend.FIDO2KeyBackend
	running    atomic.Bool
}

// NewVirtualFIDO2Device creates a new virtual FIDO2 device with the given configuration.
// The device is not started until Run is called.
//
// Creates storage based on cfg.StorageType:
//   - StorageTypeMemory: in-memory storage (volatile)
//   - StorageTypeFile: file-based storage at cfg.StoragePath (persistent)
//
// If cfg.EnablePIN is true and cfg.PIN is set, the initial PIN is configured.
func NewVirtualFIDO2Device(cfg *Config, logger *slog.Logger) (*VirtualFIDO2Device, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create the appropriate storage backend
	storage, err := createStorage(cfg)
	if err != nil {
		return nil, errors.Join(ErrStorageCreationFailed, err)
	}

	// Create user presence handler
	upHandler, err := createUserPresenceHandler(cfg, logger)
	if err != nil {
		_ = storage.Close()
		return nil, errors.Join(ErrAuthenticatorCreationFailed, err)
	}

	// Create key backend
	keyBackend, err := createKeyBackend(cfg, logger)
	if err != nil {
		_ = storage.Close()
		return nil, errors.Join(ErrAuthenticatorCreationFailed, err)
	}

	// Create authenticator configuration
	authConfig := &authenticator.Config{
		EnablePIN:                  cfg.EnablePIN,
		EnableResidentKey:          true,
		EnableCredentialManagement: true,
		EnableHMACSecret:           true,
		Storage:                    storage,
		UserPresenceHandler:        upHandler,
		UserPresenceTimeout:        cfg.UserPresenceTimeout,
		KeyBackend:                 keyBackend,
		AttestationFormat:          cfg.AttestationFormat,
	}

	// Create the authenticator
	auth, err := authenticator.NewAuthenticator(authConfig)
	if err != nil {
		// Close resources on failure
		_ = keyBackend.Close()
		_ = storage.Close()
		return nil, errors.Join(ErrAuthenticatorCreationFailed, err)
	}

	// Set initial PIN if configured
	if cfg.EnablePIN && cfg.PIN != "" {
		if err := auth.SetPINForTesting(cfg.PIN); err != nil {
			// Close resources on failure
			_ = auth.Close()
			return nil, errors.Join(ErrPINSetFailed, err)
		}
		logger.Info("initial PIN configured")
	}

	// Create CTAP-HID handler
	hidHandler := authenticator.NewCTAPHIDHandler(auth)

	device := &VirtualFIDO2Device{
		cfg:        cfg,
		logger:     logger,
		auth:       auth,
		hidHandler: hidHandler,
		storage:    storage,
		keyBackend: keyBackend,
	}

	return device, nil
}

// Run starts the virtual FIDO2 device event loop.
// It opens the UHID device, creates the virtual HID device, and processes
// incoming HID packets until the context is cancelled.
//
// Returns when the context is cancelled or an error occurs.
// Run is blocking and should be called in a separate goroutine if needed.
func (d *VirtualFIDO2Device) Run(ctx context.Context) error {
	if d.running.Swap(true) {
		return ErrDeviceAlreadyRunning
	}
	defer d.running.Store(false)

	// Open UHID device
	uhidDev, err := uhid.Open()
	if err != nil {
		return errors.Join(ErrUHIDOpenFailed, err)
	}
	d.uhidDevice = uhidDev

	// Create the virtual HID device with FIDO2 descriptor
	createCfg := &uhid.CreateConfig{
		Name:             d.cfg.DeviceName,
		Uniq:             d.cfg.SerialNumber,
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	if err := uhidDev.Create(createCfg); err != nil {
		_ = uhidDev.Close()
		d.uhidDevice = nil
		return errors.Join(ErrUHIDCreateFailed, err)
	}

	d.logger.Info("virtual FIDO2 device created",
		slog.String("name", d.cfg.DeviceName),
		slog.String("serial", d.cfg.SerialNumber),
		slog.String("vendor_id", "0xF1D0"),
		slog.String("product_id", "0x0003"),
	)

	// Set response handler to write HID packets back to UHID
	d.hidHandler.SetResponseHandler(func(packet []byte) {
		d.logger.Debug("sending HID response",
			slog.Int("length", len(packet)),
			slog.String("cid", fmt.Sprintf("0x%08X", uint32(packet[0])<<24|uint32(packet[1])<<16|uint32(packet[2])<<8|uint32(packet[3]))),
			slog.String("cmd", fmt.Sprintf("0x%02X", packet[4])),
		)
		if err := d.uhidDevice.WriteInput(packet); err != nil {
			d.logger.Error("failed to write HID response",
				slog.String("error", err.Error()),
			)
		}
	})

	// Set read timeout for interruptibility
	uhidDev.SetReadTimeout(100 * time.Millisecond)

	// Run the event loop
	return d.eventLoop(ctx)
}

// eventLoop processes incoming HID packets until the context is cancelled.
func (d *VirtualFIDO2Device) eventLoop(ctx context.Context) error {
	d.logger.Info("starting FIDO2 HID event loop")

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("context cancelled, stopping event loop")
			return ctx.Err()
		default:
			// Read 64-byte HID packet from UHID
			packet, err := d.uhidDevice.ReadOutput()
			if err != nil {
				// Handle timeout - this is expected for polling
				if errors.Is(err, uhid.ErrTimeout) {
					continue
				}

				// Handle device closed
				if errors.Is(err, uhid.ErrDeviceNotOpen) {
					d.logger.Info("UHID device closed, stopping event loop")
					return nil
				}

				d.logger.Error("failed to read HID packet",
					slog.String("error", err.Error()),
				)
				continue
			}

			// Ensure we have a complete HID packet (64 bytes)
			if len(packet) < authenticator.HIDPacketSize {
				d.logger.Warn("received incomplete HID packet",
					slog.Int("length", len(packet)),
					slog.Int("expected", authenticator.HIDPacketSize),
				)
				continue
			}

			// Log received packet for debugging
			d.logger.Debug("received HID packet",
				slog.Int("length", len(packet)),
				slog.String("cid", fmt.Sprintf("0x%08X", uint32(packet[0])<<24|uint32(packet[1])<<16|uint32(packet[2])<<8|uint32(packet[3]))),
				slog.String("cmd_or_seq", fmt.Sprintf("0x%02X", packet[4])),
			)

			// Process the HID packet through the CTAP-HID handler
			// Responses are sent via the response handler callback
			d.hidHandler.HandleMessage(packet)
		}
	}
}

// Close stops the device and releases all resources.
// It is safe to call Close multiple times.
func (d *VirtualFIDO2Device) Close() error {
	var errs []error

	// Close the CTAP-HID handler
	if d.hidHandler != nil {
		if err := d.hidHandler.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Close the UHID device
	if d.uhidDevice != nil {
		d.logger.Info("closing UHID device")
		if err := d.uhidDevice.Close(); err != nil {
			errs = append(errs, err)
		}
		d.uhidDevice = nil
	}

	// Close the authenticator (also saves state and closes key backend)
	if d.auth != nil {
		d.logger.Info("closing authenticator")
		if err := d.auth.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// IsRunning returns true if the device event loop is currently running.
func (d *VirtualFIDO2Device) IsRunning() bool {
	return d.running.Load()
}

// Authenticator returns the underlying FIDO2 authenticator.
// This can be used for advanced operations like credential management.
func (d *VirtualFIDO2Device) Authenticator() *authenticator.Authenticator {
	return d.auth
}

// createStorage creates the appropriate storage backend based on configuration.
func createStorage(cfg *Config) (authenticator.StatefulCredentialStorage, error) {
	switch cfg.StorageType {
	case StorageTypeMemory:
		return authenticator.NewMemoryStorage(), nil

	case StorageTypeFile:
		// Create file backend
		backend, err := file.New(cfg.StoragePath)
		if err != nil {
			return nil, err
		}

		// Create stateful storage with namespace prefix
		storage, err := authenticator.NewBackendStorage(backend, "vfido2/")
		if err != nil {
			_ = backend.Close()
			return nil, err
		}

		return storage, nil

	default:
		return nil, ErrInvalidStorageType
	}
}

// createUserPresenceHandler creates the appropriate user presence handler based on config.
func createUserPresenceHandler(cfg *Config, logger *slog.Logger) (authenticator.UserPresenceHandler, error) {
	if cfg.Interactive {
		logger.Info("using interactive user presence handler")
		handler, err := authenticator.NewInteractiveHandler()
		if err != nil {
			return nil, err
		}
		return handler, nil
	}

	// Default to auto-grant (non-interactive mode)
	logger.Info("using auto-grant user presence handler")
	if cfg.EnablePIN && cfg.PIN != "" {
		return authenticator.NewAutoGrantHandlerWithPIN(cfg.PIN), nil
	}
	return authenticator.NewAutoGrantHandler(), nil
}

// createKeyBackend creates the appropriate key backend based on config.
func createKeyBackend(cfg *Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	switch cfg.Backend {
	case "tpm2":
		// Note: TPM2 backend would be created here when implemented
		// For now, fall through to software
		logger.Warn("TPM2 backend not yet fully integrated, using software backend")
		fallthrough
	case "software":
		fallthrough
	default:
		logger.Info("using software key backend")
		return software.NewSoftwareKeyBackend(), nil
	}
}
