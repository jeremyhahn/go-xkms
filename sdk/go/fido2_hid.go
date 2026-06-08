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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/fido2"

// FIDO2 CTAP-HID surface re-exported so the xkey authenticator drives the
// canonical pkg/fido2 USB-HID transport (device enumeration, CTAPHID frame
// codes and CTAP2 command opcodes) through the SDK.

// FIDO2HIDDevice is an open FIDO2 USB-HID device.
type FIDO2HIDDevice = fido2.HIDDevice

// FIDO2HIDDeviceEnumerator enumerates connected FIDO2 USB-HID devices.
type FIDO2HIDDeviceEnumerator = fido2.HIDDeviceEnumerator

// FIDO2HIDPacketSize is the fixed CTAP-HID packet size.
const FIDO2HIDPacketSize = fido2.HIDPacketSize

// FIDO2CIDBroadcast is the CTAP-HID broadcast channel identifier.
const FIDO2CIDBroadcast = fido2.CIDBroadcast

const (
	// FIDO2CTAPHIDInit is the CTAPHID_INIT command code.
	FIDO2CTAPHIDInit = fido2.CTAPHID_INIT
	// FIDO2CTAPHIDCBOR is the CTAPHID_CBOR command code.
	FIDO2CTAPHIDCBOR = fido2.CTAPHID_CBOR
	// FIDO2CTAPHIDPing is the CTAPHID_PING command code.
	FIDO2CTAPHIDPing = fido2.CTAPHID_PING
	// FIDO2CTAPHIDKeepalive is the CTAPHID_KEEPALIVE command code.
	FIDO2CTAPHIDKeepalive = fido2.CTAPHID_KEEPALIVE
	// FIDO2CTAPHIDError is the CTAPHID_ERROR command code.
	FIDO2CTAPHIDError = fido2.CTAPHID_ERROR
)

const (
	// FIDO2CmdMakeCredential is the authenticatorMakeCredential opcode.
	FIDO2CmdMakeCredential = fido2.CmdMakeCredential
	// FIDO2CmdGetAssertion is the authenticatorGetAssertion opcode.
	FIDO2CmdGetAssertion = fido2.CmdGetAssertion
	// FIDO2CmdGetInfo is the authenticatorGetInfo opcode.
	FIDO2CmdGetInfo = fido2.CmdGetInfo
)
