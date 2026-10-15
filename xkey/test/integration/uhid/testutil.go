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

//go:build integration && linux

package uhid

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/uhid"
)

// deviceCounter ensures unique device names across tests.
var deviceCounter atomic.Uint64

// requireUHID fails the test if /dev/uhid is not available or not
// accessible. The integration container loads the uhid module and runs with
// access to the device, so an unusable device is an environment fault.
func requireUHID(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(uhid.UHIDDevicePath); os.IsNotExist(err) {
		t.Fatalf("UHID not available at %s; run this suite via the devcontainer, "+
			"which loads the uhid module", uhid.UHIDDevicePath)
	}

	// Also check that we have permission to open the device.
	file, err := os.OpenFile(uhid.UHIDDevicePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("cannot open %s: %v; the integration container must run with "+
			"access to the uhid device", uhid.UHIDDevicePath, err)
	}
	file.Close()
}

// createTestDevice creates a UHID device for testing and returns it along with a cleanup function.
// The device is created with a unique name to avoid conflicts between parallel tests.
func createTestDevice(t *testing.T, namePrefix string) (*uhid.Device, func()) {
	t.Helper()
	requireUHID(t)

	device, err := uhid.Open()
	if err != nil {
		t.Fatalf("Failed to open UHID: %v", err)
	}

	// Generate unique device name
	counter := deviceCounter.Add(1)
	uniqueName := fmt.Sprintf("%s-%d", namePrefix, counter)

	cfg := &uhid.CreateConfig{
		Name:             uniqueName,
		Phys:             fmt.Sprintf("test-phys-%d", counter),
		Uniq:             fmt.Sprintf("TEST%04d", counter),
		VendorID:         uhid.VendorIDVirtualFIDO,
		ProductID:        uhid.ProductIDVirtualFIDO,
		Version:          0x0100,
		ReportDescriptor: uhid.FIDO2HIDReportDescriptor,
	}

	err = device.Create(cfg)
	if err != nil {
		device.Close()
		t.Fatalf("Failed to create UHID device: %v", err)
	}

	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Logf("Warning: failed to close device: %v", err)
		}
	}

	return device, cleanup
}

// createTestDeviceWithConfig creates a UHID device with a custom configuration.
func createTestDeviceWithConfig(t *testing.T, cfg *uhid.CreateConfig) (*uhid.Device, func()) {
	t.Helper()
	requireUHID(t)

	device, err := uhid.Open()
	if err != nil {
		t.Fatalf("Failed to open UHID: %v", err)
	}

	err = device.Create(cfg)
	if err != nil {
		device.Close()
		t.Fatalf("Failed to create UHID device: %v", err)
	}

	cleanup := func() {
		if err := device.Close(); err != nil {
			t.Logf("Warning: failed to close device: %v", err)
		}
	}

	return device, cleanup
}

// generateUniqueDeviceName generates a unique device name for testing.
func generateUniqueDeviceName(prefix string) string {
	counter := deviceCounter.Add(1)
	return fmt.Sprintf("%s-%d", prefix, counter)
}

// generateUniqueSerial generates a unique serial number for testing.
func generateUniqueSerial() string {
	counter := deviceCounter.Add(1)
	return fmt.Sprintf("VFIDO%06d", counter)
}

// createFIDO2HIDReport creates a simple FIDO2 HID report for testing.
// The report is 64 bytes as per FIDO2 HID specification.
func createFIDO2HIDReport(data []byte) []byte {
	report := make([]byte, uhid.HIDReportSize)
	copy(report, data)
	return report
}
