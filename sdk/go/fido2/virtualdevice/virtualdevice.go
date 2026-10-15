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

//go:build linux

// Package virtualdevice is the SDK re-export of the in-process virtual FIDO2
// authenticator (pkg/fido2/virtualdevice) and of the backend credential
// storage it persists to (pkg/fido2/authenticator). Client binaries import
// this package instead of pkg/* so they depend only on the SDK.
package virtualdevice

import (
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/fido2/virtualdevice"
)

const (
	NativeVirtualDeviceProductID = virtualdevice.NativeVirtualDeviceProductID
	NativeVirtualDeviceVendorID  = virtualdevice.NativeVirtualDeviceVendorID
)

type (
	NativeVirtualDevice           = virtualdevice.NativeVirtualDevice
	NativeVirtualDeviceConfig     = virtualdevice.NativeVirtualDeviceConfig
	NativeVirtualDeviceEnumerator = virtualdevice.NativeVirtualDeviceEnumerator
	StatefulCredentialStorage     = authenticator.StatefulCredentialStorage
	BackendStorage                = authenticator.BackendStorage
)

var (
	NewNativeVirtualDevice           = virtualdevice.NewNativeVirtualDevice
	NewNativeVirtualDeviceEnumerator = virtualdevice.NewNativeVirtualDeviceEnumerator
	NewBackendStorage                = authenticator.NewBackendStorage
)
