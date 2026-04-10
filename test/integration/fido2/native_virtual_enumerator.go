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

//go:build integration && fido2

// Package fido2 provides FIDO2 integration test utilities.
//
// Integration tests use the native authenticator-based virtual device
// (NativeVirtualDevice) from the xkey module's virtualdevice package.
// This provides a pure Go CTAP2 authenticator implementation with full
// support for hmac-secret, resident keys, and credential management.
package fido2
