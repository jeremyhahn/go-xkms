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
	"path/filepath"
	"sync/atomic"
)

const (
	// defaultFunctionFSMountDir is the default FunctionFS mount point for CCID.
	defaultFunctionFSMountDir = "/dev/ffs-ccid"
)

// fido2HIDReportDescriptor is the HID report descriptor for FIDO2 CTAP-HID.
// Usage Page 0xF1D0 (FIDO Alliance), Usage 0x01 (U2F Authenticator Device).
// 64-byte input and output reports.
var fido2HIDReportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (U2F Authenticator Device)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Input Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Var, Abs)
	0x09, 0x21, //   Usage (Output Report Data)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Var, Abs)
	0xC0, // End Collection
}

// Gadget manages a USB composite gadget with optional CCID and HID functions.
// It coordinates ConfigFS setup, FunctionFS mounting, and transport lifecycle.
type Gadget struct {
	configFS   *ConfigFS
	config     *GadgetConfig
	fs         FileSystem
	ccid       *FunctionFSTransport
	hid        *HIDGadgetTransport
	hidDevPath string
	bound      atomic.Bool
	logger     *slog.Logger
}

// Option configures a Gadget.
type Option func(*Gadget)

// WithFileSystem sets the FileSystem implementation. Defaults to OSFileSystem.
func WithFileSystem(fs FileSystem) Option {
	return func(g *Gadget) {
		g.fs = fs
	}
}

// WithHIDDevicePath sets the HID gadget device path. Defaults to /dev/hidg0.
func WithHIDDevicePath(path string) Option {
	return func(g *Gadget) {
		g.hidDevPath = path
	}
}

// New creates a new Gadget with the given configuration and options.
// The gadget is not started until Start is called.
func New(config *GadgetConfig, logger *slog.Logger, opts ...Option) (*Gadget, error) {
	if config == nil {
		return nil, NewGadgetError("New", ErrConfigFSNotAvailable)
	}
	if logger == nil {
		return nil, NewGadgetError("New", ErrNilLogger)
	}

	g := &Gadget{
		config:     config,
		fs:         &OSFileSystem{},
		hidDevPath: defaultHIDGadgetPath,
		logger:     logger,
	}

	for _, opt := range opts {
		opt(g)
	}

	cfs, err := NewConfigFS(config, g.fs, logger)
	if err != nil {
		return nil, err
	}
	g.configFS = cfs

	return g, nil
}

// Start creates the USB composite gadget and initializes all transports.
// The sequence is: create ConfigFS tree, mount FunctionFS and write
// descriptors for CCID, write HID report descriptor, bind to UDC, then
// open the HID gadget device.
func (g *Gadget) Start(ctx context.Context) error {
	if err := g.configFS.Create(ctx); err != nil {
		return err
	}

	// Pre-bind setup for each function.
	for i := range g.config.Functions {
		fn := &g.config.Functions[i]

		switch fn.Type {
		case FunctionCCID:
			if err := g.initCCID(ctx, fn); err != nil {
				return err
			}
		case FunctionHID:
			if err := g.writeHIDReportDescriptor(); err != nil {
				return err
			}
		}
	}

	// Bind to UDC. After this, /dev/hidg0 becomes available.
	if err := g.configFS.Bind(ctx); err != nil {
		return err
	}

	// Post-bind setup: open HID gadget device.
	for _, fn := range g.config.Functions {
		if fn.Type == FunctionHID {
			hid, err := NewHIDGadgetTransport(g.hidDevPath, g.logger)
			if err != nil {
				return NewGadgetError("Start",
					fmt.Errorf("hid transport: %w", err))
			}
			g.hid = hid
		}
	}

	g.bound.Store(true)
	g.logger.Info("USB composite gadget started",
		"name", g.config.Name,
		"ccid", g.ccid != nil,
		"hid", g.hid != nil)

	return nil
}

// Stop shuts down all transports and tears down the ConfigFS gadget.
func (g *Gadget) Stop() error {
	g.logger.Info("stopping USB composite gadget", "name", g.config.Name)

	var firstErr error

	if g.hid != nil {
		if err := g.hid.Close(); err != nil && firstErr == nil {
			firstErr = NewGadgetError("Stop", fmt.Errorf("hid close: %w", err))
		}
		g.hid = nil
	}

	if g.ccid != nil {
		if err := g.ccid.Close(); err != nil && firstErr == nil {
			firstErr = NewGadgetError("Stop", fmt.Errorf("ccid close: %w", err))
		}
		g.ccid = nil
	}

	// Unmount FunctionFS for CCID functions.
	for _, fn := range g.config.Functions {
		if fn.Type == FunctionCCID {
			mountDir := fn.MountDir
			if mountDir == "" {
				mountDir = defaultFunctionFSMountDir
			}
			if err := g.fs.Unmount(mountDir, 0); err != nil && firstErr == nil {
				firstErr = NewGadgetError("Stop",
					fmt.Errorf("unmount %s: %w", mountDir, err))
			}
		}
	}

	if err := g.configFS.Destroy(); err != nil && firstErr == nil {
		firstErr = err
	}

	g.bound.Store(false)
	g.logger.Info("USB composite gadget stopped", "name", g.config.Name)

	return firstErr
}

// CCIDTransport returns the CCID FunctionFS transport, or nil if CCID
// is not configured.
func (g *Gadget) CCIDTransport() Transport {
	if g.ccid == nil {
		return nil
	}
	return g.ccid
}

// HIDTransport returns the HID gadget transport, or nil if HID
// is not configured.
func (g *Gadget) HIDTransport() Transport {
	if g.hid == nil {
		return nil
	}
	return g.hid
}

// IsBound returns true if the gadget is bound to a UDC.
func (g *Gadget) IsBound() bool {
	return g.bound.Load()
}

// initCCID mounts FunctionFS, creates the transport, and initializes it.
func (g *Gadget) initCCID(ctx context.Context, fn *FunctionConfig) error {
	mountDir := fn.MountDir
	if mountDir == "" {
		mountDir = defaultFunctionFSMountDir
		fn.MountDir = mountDir
	}

	if err := g.fs.MkdirAll(mountDir, 0755); err != nil {
		return NewGadgetError("Start",
			fmt.Errorf("mkdir %s: %w", mountDir, err))
	}

	if err := g.fs.Mount(funcNameCCID, mountDir, "functionfs", 0, ""); err != nil {
		return NewGadgetError("Start",
			fmt.Errorf("%w: %v", ErrFunctionFSMountFailed, err))
	}

	transport, err := NewFunctionFSTransport(mountDir, g.fs, g.logger)
	if err != nil {
		return err
	}

	if err := transport.Initialize(ctx); err != nil {
		return err
	}

	g.ccid = transport
	return nil
}

// writeHIDReportDescriptor writes the FIDO2 HID report descriptor to the
// ConfigFS function directory. This must be done before UDC binding.
func (g *Gadget) writeHIDReportDescriptor() error {
	reportDescPath := filepath.Join(
		g.configFS.GadgetDir(), "functions", funcNameHID, "report_desc")

	if err := g.fs.WriteFile(reportDescPath, fido2HIDReportDescriptor, 0644); err != nil {
		return NewGadgetError("Start",
			fmt.Errorf("write report_desc: %w", err))
	}

	g.logger.Info("wrote HID report descriptor",
		"path", reportDescPath,
		"size", len(fido2HIDReportDescriptor))

	return nil
}
