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

// Package android implements the PlatformVerifier for Android Key Attestation.
//
// This package verifies attestation certificate chains produced by Android
// Keystore hardware (TEE/StrongBox) using the Android Key Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17). It registers itself with the phone backend's
// platform registry via init(), enabling automatic Android attestation support
// when imported.
//
// Import this package with a blank import to enable Android attestation:
//
//	import _ "github.com/jeremyhahn/go-xkms/pkg/backend/phone/android"
package android
