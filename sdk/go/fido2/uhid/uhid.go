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

// Package uhid is the SDK re-export of the Linux UHID virtual HID device
// (pkg/fido2/uhid). Client binaries import this package instead of pkg/* so
// they depend only on the SDK.
package uhid

import (
	"github.com/jeremyhahn/go-xkms/pkg/fido2/uhid"
)

const (
	AuthenticatorDeviceName = uhid.AuthenticatorDeviceName
	HIDReportSize           = uhid.HIDReportSize
	ProductIDVirtualFIDO    = uhid.ProductIDVirtualFIDO
	UHIDDevicePath          = uhid.UHIDDevicePath
	VendorIDVirtualFIDO     = uhid.VendorIDVirtualFIDO
)

type (
	Device       = uhid.Device
	CreateConfig = uhid.CreateConfig
)

var (
	DefaultCreateConfig      = uhid.DefaultCreateConfig
	FIDO2HIDReportDescriptor = uhid.FIDO2HIDReportDescriptor
	Open                     = uhid.Open

	ErrDeviceNotOpen = uhid.ErrDeviceNotOpen
	ErrTimeout       = uhid.ErrTimeout
)
