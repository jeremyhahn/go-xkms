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

//go:build linux

package fido2

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// LinuxHIDDevice implements HIDDevice for Linux using raw HID access
type LinuxHIDDevice struct {
	path         string
	file         *os.File
	vendorID     uint16
	productID    uint16
	manufacturer string
	product      string
	serialNumber string
}

// LinuxHIDDeviceEnumerator implements HIDDeviceEnumerator for Linux
type LinuxHIDDeviceEnumerator struct{}

// NewLinuxHIDDeviceEnumerator creates a new Linux HID device enumerator
func NewLinuxHIDDeviceEnumerator() *LinuxHIDDeviceEnumerator {
	return &LinuxHIDDeviceEnumerator{}
}

// NewDefaultEnumerator returns the default HID device enumerator for the platform
func NewDefaultEnumerator() HIDDeviceEnumerator {
	return NewLinuxHIDDeviceEnumerator()
}

// Enumerate finds all HID devices, optionally filtered by vendor and product ID
func (e *LinuxHIDDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	var devices []HIDDevice

	// Look for hidraw devices
	hidrawPath := "/sys/class/hidraw"
	entries, err := os.ReadDir(hidrawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read hidraw devices: %w", err)
	}

	for _, entry := range entries {
		devicePath := filepath.Join("/dev", entry.Name())

		// Read device info from sysfs
		sysPath := filepath.Join(hidrawPath, entry.Name(), "device")

		vid, pid := readVendorProductID(sysPath)
		if vid == 0 && pid == 0 {
			continue
		}

		// Apply vendor/product filter if specified
		if vendorID != 0 && vid != vendorID {
			continue
		}
		if productID != 0 && pid != productID {
			continue
		}

		// Check if this is a FIDO device by looking at the HID usage page
		if !isFIDODevice(sysPath) {
			continue
		}

		manufacturer := readSysfsString(sysPath, "manufacturer")
		product := readSysfsString(sysPath, "product")
		serial := readSysfsString(sysPath, "serial")

		device := &LinuxHIDDevice{
			path:         devicePath,
			vendorID:     vid,
			productID:    pid,
			manufacturer: manufacturer,
			product:      product,
			serialNumber: serial,
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// Open opens a specific HID device by path
func (e *LinuxHIDDeviceEnumerator) Open(path string) (HIDDevice, error) {
	// Get device info from sysfs
	deviceName := filepath.Base(path)
	sysPath := filepath.Join("/sys/class/hidraw", deviceName, "device")

	vid, pid := readVendorProductID(sysPath)
	manufacturer := readSysfsString(sysPath, "manufacturer")
	product := readSysfsString(sysPath, "product")
	serial := readSysfsString(sysPath, "serial")

	// Open the device
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open HID device %s: %w", path, err)
	}

	return &LinuxHIDDevice{
		path:         path,
		file:         file,
		vendorID:     vid,
		productID:    pid,
		manufacturer: manufacturer,
		product:      product,
		serialNumber: serial,
	}, nil
}

// Write sends data to the HID device
func (d *LinuxHIDDevice) Write(data []byte) (int, error) {
	if d.file == nil {
		return 0, fmt.Errorf("device not open")
	}
	return d.file.Write(data)
}

// Read reads data from the HID device
func (d *LinuxHIDDevice) Read(data []byte) (int, error) {
	if d.file == nil {
		return 0, fmt.Errorf("device not open")
	}
	return d.file.Read(data)
}

// Close closes the HID device
func (d *LinuxHIDDevice) Close() error {
	if d.file != nil {
		err := d.file.Close()
		d.file = nil
		return err
	}
	return nil
}

// Path returns the device path
func (d *LinuxHIDDevice) Path() string {
	return d.path
}

// ProductID returns the product ID
func (d *LinuxHIDDevice) ProductID() uint16 {
	return d.productID
}

// VendorID returns the vendor ID
func (d *LinuxHIDDevice) VendorID() uint16 {
	return d.vendorID
}

// Product returns the product name
func (d *LinuxHIDDevice) Product() string {
	return d.product
}

// Manufacturer returns the manufacturer name
func (d *LinuxHIDDevice) Manufacturer() string {
	return d.manufacturer
}

// SerialNumber returns the serial number
func (d *LinuxHIDDevice) SerialNumber() string {
	return d.serialNumber
}

// Helper functions

func readSysfsString(basePath, name string) string {
	// Try direct path first
	data, err := os.ReadFile(filepath.Join(basePath, name))
	if err == nil {
		return strings.TrimSpace(string(data))
	}

	// Try uevent file
	ueventPath := filepath.Join(basePath, "uevent")
	data, err = os.ReadFile(ueventPath)
	if err != nil {
		return ""
	}

	prefix := strings.ToUpper(name) + "="
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}

	return ""
}

func readVendorProductID(sysPath string) (uint16, uint16) {
	// Try to read from uevent
	ueventPath := filepath.Join(sysPath, "uevent")
	data, err := os.ReadFile(ueventPath)
	if err != nil {
		// Try parent HID device path
		hidPath := filepath.Join(sysPath, "..", "uevent")
		data, err = os.ReadFile(hidPath)
		if err != nil {
			return 0, 0
		}
	}

	var vid, pid uint32
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "HID_ID=") {
			// Format: HID_ID=0003:00001050:00000407
			// where the second field is vendor ID (8 hex chars) and third is product ID (8 hex chars)
			parts := strings.Split(strings.TrimPrefix(line, "HID_ID="), ":")
			if len(parts) >= 3 {
				n, err := fmt.Sscanf(parts[1], "%08X", &vid)
				if err != nil || n != 1 {
					log.Printf("failed to parse vendor ID from '%s': %v", parts[1], err)
				}
				n, err = fmt.Sscanf(parts[2], "%08X", &pid)
				if err != nil || n != 1 {
					log.Printf("failed to parse product ID from '%s': %v", parts[2], err)
				}
			}
		}
	}

	return uint16(vid), uint16(pid)
}

func isFIDODevice(sysPath string) bool {
	// Check the HID report descriptor for FIDO usage page (0xF1D0)
	// The usage page is typically in the first few bytes of the descriptor

	// First try to read the report descriptor
	rdescPath := filepath.Join(sysPath, "report_descriptor")
	rdesc, err := os.ReadFile(rdescPath)
	if err != nil {
		// If we can't read the descriptor, try the parent path
		rdescPath = filepath.Join(sysPath, "..", "report_descriptor")
		rdesc, err = os.ReadFile(rdescPath)
		if err != nil {
			// Fall back to checking modalias for FIDO devices
			return checkModaliasFIDO(sysPath)
		}
	}

	// Parse HID report descriptor looking for usage page 0xF1D0
	// Usage page format: 0x06 (usage page tag) followed by 2 bytes
	for i := 0; i < len(rdesc)-2; i++ {
		if rdesc[i] == 0x06 { // Usage page tag (2 bytes)
			usagePage := uint16(rdesc[i+1]) | uint16(rdesc[i+2])<<8
			if usagePage == HIDUsagePage {
				return true
			}
		}
	}

	return false
}

func checkModaliasFIDO(sysPath string) bool {
	// Check modalias for USB interface class (0x03 for HID)
	// and FIDO-compatible devices typically have specific patterns
	modaliasPath := filepath.Join(sysPath, "modalias")
	data, err := os.ReadFile(modaliasPath)
	if err != nil {
		return false
	}

	modalias := string(data)

	// Known FIDO device vendor IDs
	fidoVendors := []string{
		"1050:", // Yubico
		"096E:", // Feitian
		"20A0:", // Nitrokey
		"F1D0:", // FIDO Alliance VID
		"2581:", // Plug-up
		"24DC:", // Token2
	}

	for _, vendor := range fidoVendors {
		if strings.Contains(strings.ToUpper(modalias), vendor) {
			return true
		}
	}

	return false
}

// SetNonBlocking sets the device to non-blocking mode
func (d *LinuxHIDDevice) SetNonBlocking(nonBlocking bool) error {
	if d.file == nil {
		return fmt.Errorf("device not open")
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

// IOCTL constants for HID
const (
	HIDIOCGRAWINFO    = 0x80084803
	HIDIOCGRAWNAME128 = 0x81804804
	HIDIOCGRAWPHYS128 = 0x81804805
	HIDIOCGFEATURE    = 0xC0014807
	HIDIOCSFEATURE    = 0xC0014806
	HIDIOCGRDESCSIZE  = 0x80044801
	HIDIOCGRDESC      = 0x90044802
)

type hidrawDevInfo struct {
	bustype uint32
	vendor  int16
	product int16
}

// GetRawInfo gets the raw HID device info using ioctl
func (d *LinuxHIDDevice) GetRawInfo() (bustype uint32, vendor, product int16, err error) {
	if d.file == nil {
		return 0, 0, 0, fmt.Errorf("device not open")
	}

	var info hidrawDevInfo
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		d.file.Fd(),
		HIDIOCGRAWINFO,
		uintptr(unsafe.Pointer(&info)),
	)
	if errno != 0 {
		return 0, 0, 0, fmt.Errorf("ioctl HIDIOCGRAWINFO failed: %w", errno)
	}

	return info.bustype, info.vendor, info.product, nil
}
