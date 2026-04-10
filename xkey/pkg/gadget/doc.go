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

// Package gadget provides USB transport abstractions for xkey virtual devices.
// It defines the Transport interface implemented by UHID (software HID
// emulation) and USB Gadget (ConfigFS/FunctionFS for real USB devices). The
// package enables xkey to present as a native USB composite device with true
// CCID and HID class interfaces on OTG-capable hardware.
package gadget
