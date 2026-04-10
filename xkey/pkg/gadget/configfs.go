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

// FunctionType identifies the type of USB function.
type FunctionType string

const (
	// FunctionCCID is a CCID smartcard function (FunctionFS).
	FunctionCCID FunctionType = "ccid"

	// FunctionHID is a HID function (kernel f_hid).
	FunctionHID FunctionType = "hid"

	// defaultConfigFSPath is the standard ConfigFS mount point for USB gadgets.
	defaultConfigFSPath = "/sys/kernel/config/usb_gadget"

	// defaultGadgetName is the default gadget name in ConfigFS.
	defaultGadgetName = "xkey"

	// defaultMaxPower is the default maximum power draw in milliamps.
	defaultMaxPower = 100

	// defaultVendorID is the default USB vendor ID.
	defaultVendorID = 0xF1D0

	// defaultProductID is the default USB product ID.
	defaultProductID = 0x0001

	// defaultDeviceVersion is the default bcdDevice value.
	defaultDeviceVersion = 0x0100

	// langEnUS is the English (US) language ID directory name.
	langEnUS = "0x0409"

	// configName is the first configuration directory name.
	configName = "c.1"

	// configDescription is the USB configuration string descriptor.
	configDescription = "xKey Composite Device"

	// funcNameCCID is the ConfigFS function directory for FunctionFS CCID.
	funcNameCCID = "ffs.ccid"

	// funcNameHID is the ConfigFS function directory for kernel f_hid.
	funcNameHID = "hid.usb0"

	// udcSysPath is the sysfs path where available UDCs are listed.
	udcSysPath = "/sys/class/udc"
)

// FunctionConfig describes one USB function in the composite gadget.
type FunctionConfig struct {
	// Type is the function type (CCID or HID).
	Type FunctionType

	// MountDir is the FunctionFS mount point (e.g., /dev/ffs-ccid).
	// Only used for FunctionFS-based functions (CCID).
	MountDir string
}

// GadgetConfig holds USB gadget identification and function configuration.
type GadgetConfig struct {
	// Name is the gadget name in ConfigFS (default: "xkey").
	Name string

	// VendorID is the USB vendor ID.
	VendorID uint16

	// ProductID is the USB product ID.
	ProductID uint16

	// DeviceVersion is the device version (bcdDevice).
	DeviceVersion uint16

	// SerialNumber is the device serial number string.
	SerialNumber string

	// Manufacturer is the manufacturer string descriptor.
	Manufacturer string

	// Product is the product string descriptor.
	Product string

	// ConfigFSPath is the ConfigFS mount point (default: /sys/kernel/config/usb_gadget).
	ConfigFSPath string

	// UDC is the UDC controller name. If empty, auto-detected.
	UDC string

	// MaxPower is the maximum power in mA (default: 100).
	MaxPower uint16

	// Functions lists the USB functions to create.
	Functions []FunctionConfig
}

// DefaultGadgetConfig returns a GadgetConfig with sensible defaults for an
// xKey composite device with both CCID and HID functions.
func DefaultGadgetConfig() *GadgetConfig {
	return &GadgetConfig{
		Name:          defaultGadgetName,
		VendorID:      defaultVendorID,
		ProductID:     defaultProductID,
		DeviceVersion: defaultDeviceVersion,
		SerialNumber:  "XKEY001",
		Manufacturer:  "Automate The Things",
		Product:       "xKey OTP+FIDO+CCID",
		ConfigFSPath:  defaultConfigFSPath,
		MaxPower:      defaultMaxPower,
	}
}

// ConfigFS manages the USB gadget directory tree under ConfigFS.
// It handles creating the gadget structure, binding to a UDC,
// and tearing down cleanly.
type ConfigFS struct {
	fs      FileSystem
	config  *GadgetConfig
	gadgDir string
	bound   atomic.Bool
	logger  *slog.Logger
}

// NewConfigFS creates a new ConfigFS manager. The config and fs parameters
// must not be nil. The logger parameter must not be nil.
func NewConfigFS(config *GadgetConfig, fs FileSystem, logger *slog.Logger) (*ConfigFS, error) {
	if config == nil {
		return nil, NewGadgetError("NewConfigFS", ErrConfigFSNotAvailable)
	}
	if fs == nil {
		return nil, NewGadgetError("NewConfigFS", ErrNilTransport)
	}
	if logger == nil {
		return nil, NewGadgetError("NewConfigFS", ErrNilLogger)
	}
	gadgDir := filepath.Join(config.ConfigFSPath, config.Name)
	return &ConfigFS{
		fs:      fs,
		config:  config,
		gadgDir: gadgDir,
		logger:  logger,
	}, nil
}

// Create builds the full USB gadget directory tree in ConfigFS. It writes
// all device attributes, string descriptors, configuration descriptors, and
// creates function directories with symlinks. Returns ErrGadgetAlreadyExists
// if the gadget directory already exists.
func (c *ConfigFS) Create(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return NewGadgetError("Create", ctx.Err())
	default:
	}

	if err := c.checkNotExists(); err != nil {
		return err
	}

	c.logger.Info("creating USB gadget", "name", c.config.Name, "dir", c.gadgDir)

	if err := c.createGadgetDir(); err != nil {
		return err
	}
	if err := c.writeDeviceAttributes(); err != nil {
		return err
	}
	if err := c.writeStringDescriptors(); err != nil {
		return err
	}
	if err := c.writeConfigDescriptors(); err != nil {
		return err
	}
	if err := c.createFunctions(); err != nil {
		return err
	}

	c.logger.Info("USB gadget created", "name", c.config.Name)
	return nil
}

// Bind attaches the gadget to a USB Device Controller. If the GadgetConfig
// UDC field is empty, the controller is auto-detected from /sys/class/udc/.
func (c *ConfigFS) Bind(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return NewGadgetError("Bind", ctx.Err())
	default:
	}

	udc := c.config.UDC
	if udc == "" {
		detected, err := c.detectUDC()
		if err != nil {
			return NewGadgetError("Bind", err)
		}
		udc = detected
	}

	c.logger.Info("binding gadget to UDC", "udc", udc)

	udcPath := filepath.Join(c.gadgDir, "UDC")
	if err := c.fs.WriteFile(udcPath, []byte(udc), 0644); err != nil {
		return NewGadgetError("Bind", fmt.Errorf("%w: %v", ErrConfigFSNotAvailable, err))
	}

	c.bound.Store(true)
	c.logger.Info("gadget bound to UDC", "udc", udc)
	return nil
}

// Unbind detaches the gadget from the UDC by writing an empty string to
// the UDC attribute. If the gadget is not bound, Unbind returns nil.
func (c *ConfigFS) Unbind() error {
	if !c.bound.Load() {
		return nil
	}

	c.logger.Info("unbinding gadget from UDC")

	udcPath := filepath.Join(c.gadgDir, "UDC")
	if err := c.fs.WriteFile(udcPath, []byte("\n"), 0644); err != nil {
		return NewGadgetError("Unbind", err)
	}

	c.bound.Store(false)
	c.logger.Info("gadget unbound from UDC")
	return nil
}

// Destroy tears down the gadget in the correct order required by ConfigFS:
// unbind from UDC, remove function symlinks, remove configuration, remove
// functions, remove strings, and finally remove the gadget directory.
func (c *ConfigFS) Destroy() error {
	c.logger.Info("destroying USB gadget", "name", c.config.Name)

	if err := c.Unbind(); err != nil {
		return NewGadgetError("Destroy", err)
	}

	// Remove function symlinks from configuration.
	for _, fn := range c.config.Functions {
		name := functionDirName(fn.Type)
		linkPath := filepath.Join(c.gadgDir, "configs", configName, name)
		if err := c.fs.RemoveAll(linkPath); err != nil {
			return NewGadgetError("Destroy", err)
		}
	}

	// Remove config strings directory.
	configStringsDir := filepath.Join(c.gadgDir, "configs", configName, "strings", langEnUS)
	if err := c.fs.RemoveAll(configStringsDir); err != nil {
		return NewGadgetError("Destroy", err)
	}

	// Remove config directory.
	configDir := filepath.Join(c.gadgDir, "configs", configName)
	if err := c.fs.RemoveAll(configDir); err != nil {
		return NewGadgetError("Destroy", err)
	}

	// Remove function directories.
	for _, fn := range c.config.Functions {
		name := functionDirName(fn.Type)
		funcDir := filepath.Join(c.gadgDir, "functions", name)
		if err := c.fs.RemoveAll(funcDir); err != nil {
			return NewGadgetError("Destroy", err)
		}
	}

	// Remove strings directory.
	stringsDir := filepath.Join(c.gadgDir, "strings", langEnUS)
	if err := c.fs.RemoveAll(stringsDir); err != nil {
		return NewGadgetError("Destroy", err)
	}

	// Remove gadget directory.
	if err := c.fs.RemoveAll(c.gadgDir); err != nil {
		return NewGadgetError("Destroy", err)
	}

	c.logger.Info("USB gadget destroyed", "name", c.config.Name)
	return nil
}

// GadgetDir returns the full path to the gadget directory in ConfigFS.
func (c *ConfigFS) GadgetDir() string {
	return c.gadgDir
}

// IsBound returns true if the gadget is currently bound to a UDC.
func (c *ConfigFS) IsBound() bool {
	return c.bound.Load()
}

// checkNotExists verifies the gadget directory does not already exist.
func (c *ConfigFS) checkNotExists() error {
	entries, err := c.fs.ReadDir(c.config.ConfigFSPath)
	if err != nil {
		return NewGadgetError("Create", fmt.Errorf("%w: %v", ErrConfigFSNotAvailable, err))
	}
	for _, entry := range entries {
		if entry.Name() == c.config.Name {
			return NewGadgetError("Create", ErrGadgetAlreadyExists)
		}
	}
	return nil
}

// createGadgetDir creates the top-level gadget directory.
func (c *ConfigFS) createGadgetDir() error {
	if err := c.fs.MkdirAll(c.gadgDir, 0755); err != nil {
		return NewGadgetError("Create", err)
	}
	return nil
}

// writeDeviceAttributes writes USB device descriptor attributes to ConfigFS.
func (c *ConfigFS) writeDeviceAttributes() error {
	attrs := []struct {
		name  string
		value string
	}{
		{"idVendor", fmt.Sprintf("0x%04x", c.config.VendorID)},
		{"idProduct", fmt.Sprintf("0x%04x", c.config.ProductID)},
		{"bcdDevice", fmt.Sprintf("0x%04x", c.config.DeviceVersion)},
		{"bcdUSB", "0x0210"},
		{"bDeviceClass", "0xef"},
		{"bDeviceSubClass", "0x02"},
		{"bDeviceProtocol", "0x01"},
	}
	for _, attr := range attrs {
		path := filepath.Join(c.gadgDir, attr.name)
		if err := c.fs.WriteFile(path, []byte(attr.value), 0644); err != nil {
			return NewGadgetError("Create", err)
		}
	}
	return nil
}

// writeStringDescriptors creates the strings directory and writes the
// serial number, manufacturer, and product descriptors.
func (c *ConfigFS) writeStringDescriptors() error {
	stringsDir := filepath.Join(c.gadgDir, "strings", langEnUS)
	if err := c.fs.MkdirAll(stringsDir, 0755); err != nil {
		return NewGadgetError("Create", err)
	}
	strings := []struct {
		name  string
		value string
	}{
		{"serialnumber", c.config.SerialNumber},
		{"manufacturer", c.config.Manufacturer},
		{"product", c.config.Product},
	}
	for _, s := range strings {
		path := filepath.Join(stringsDir, s.name)
		if err := c.fs.WriteFile(path, []byte(s.value), 0644); err != nil {
			return NewGadgetError("Create", err)
		}
	}
	return nil
}

// writeConfigDescriptors creates the configuration directory, sets MaxPower,
// and writes the configuration string descriptor.
func (c *ConfigFS) writeConfigDescriptors() error {
	configDir := filepath.Join(c.gadgDir, "configs", configName)
	if err := c.fs.MkdirAll(configDir, 0755); err != nil {
		return NewGadgetError("Create", err)
	}

	maxPowerPath := filepath.Join(configDir, "MaxPower")
	if err := c.fs.WriteFile(maxPowerPath, []byte(fmt.Sprintf("%d", c.config.MaxPower)), 0644); err != nil {
		return NewGadgetError("Create", err)
	}

	configStringsDir := filepath.Join(configDir, "strings", langEnUS)
	if err := c.fs.MkdirAll(configStringsDir, 0755); err != nil {
		return NewGadgetError("Create", err)
	}

	configPath := filepath.Join(configStringsDir, "configuration")
	if err := c.fs.WriteFile(configPath, []byte(configDescription), 0644); err != nil {
		return NewGadgetError("Create", err)
	}

	return nil
}

// createFunctions creates function directories and symlinks them into the
// configuration. CCID functions use FunctionFS (ffs.ccid), HID functions
// use the kernel f_hid driver (hid.usb0).
func (c *ConfigFS) createFunctions() error {
	for _, fn := range c.config.Functions {
		name := functionDirName(fn.Type)
		funcDir := filepath.Join(c.gadgDir, "functions", name)

		if err := c.fs.MkdirAll(funcDir, 0755); err != nil {
			return NewGadgetError("Create", err)
		}

		if fn.Type == FunctionHID {
			if err := c.writeHIDAttributes(funcDir); err != nil {
				return err
			}
		}

		linkPath := filepath.Join(c.gadgDir, "configs", configName, name)
		if err := c.fs.Symlink(funcDir, linkPath); err != nil {
			return NewGadgetError("Create", err)
		}

		c.logger.Info("created USB function", "type", fn.Type, "dir", funcDir)
	}
	return nil
}

// writeHIDAttributes writes the HID function attributes (protocol, subclass,
// report_length) to the function directory. The report descriptor is written
// later by the HID transport during initialization.
func (c *ConfigFS) writeHIDAttributes(funcDir string) error {
	attrs := []struct {
		name  string
		value string
	}{
		{"protocol", "0"},
		{"subclass", "0"},
		{"report_length", "64"},
	}
	for _, attr := range attrs {
		path := filepath.Join(funcDir, attr.name)
		if err := c.fs.WriteFile(path, []byte(attr.value), 0644); err != nil {
			return NewGadgetError("Create", err)
		}
	}
	return nil
}

// detectUDC reads /sys/class/udc/ and returns the name of the first available
// USB Device Controller. Returns ErrUDCNotFound if no controllers are present.
func (c *ConfigFS) detectUDC() (string, error) {
	entries, err := c.fs.ReadDir(udcSysPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUDCNotFound, err)
	}
	if len(entries) == 0 {
		return "", ErrUDCNotFound
	}
	udc := entries[0].Name()
	c.logger.Info("auto-detected UDC", "udc", udc)
	return udc, nil
}

// functionDirName returns the ConfigFS directory name for a function type.
func functionDirName(ft FunctionType) string {
	switch ft {
	case FunctionCCID:
		return funcNameCCID
	case FunctionHID:
		return funcNameHID
	default:
		return string(ft)
	}
}

// Compile-time interface satisfaction check.
var _ FileSystem = (*OSFileSystem)(nil)
