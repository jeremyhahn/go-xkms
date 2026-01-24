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

//go:build integration && fido2

// Package fido2 provides FIDO2 integration test utilities.
// This file provides type aliases for the fido2 package's NativeVirtualDeviceEnumerator
// to maintain backward compatibility with existing tests.
package fido2

import (
	"github.com/jeremyhahn/go-keychain/pkg/fido2"
)

// Type aliases for backward compatibility with existing tests.
type NativeVirtualDeviceEnumerator = fido2.NativeVirtualDeviceEnumerator

// Error aliases for backward compatibility.
var (
	ErrNativeEnumeratorDeviceNil      = fido2.ErrNativeEnumeratorDeviceNil
	ErrNativeEnumeratorDeviceExists   = fido2.ErrNativeEnumeratorDeviceExists
	ErrNativeEnumeratorDeviceNotFound = fido2.ErrNativeEnumeratorDeviceNotFound
)

// NewNativeVirtualDeviceEnumerator creates a new native virtual device enumerator.
func NewNativeVirtualDeviceEnumerator() *NativeVirtualDeviceEnumerator {
	return fido2.NewNativeVirtualDeviceEnumerator()
}
