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

//go:build pkcs11

package xkms

import pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"

// PKCS#11 (HSM/token) crypto backend re-exported behind the pkcs11 build tag,
// matching the gating of pkg/backend/pkcs11. Consumers (e.g. the xkey yubikey
// provider) reach this backend through the SDK only when built with
// -tags pkcs11.

// PKCS11Backend is the PKCS#11 (HSM/token) crypto backend.
type PKCS11Backend = pkcs11backend.Backend

// PKCS11BackendConfig configures the PKCS#11 crypto backend.
type PKCS11BackendConfig = pkcs11backend.Config

// PKCS11SessionPool manages a pool of PKCS#11 sessions for the backend.
type PKCS11SessionPool = pkcs11backend.SessionPool

// NewPKCS11Backend constructs a PKCS#11 crypto backend.
var NewPKCS11Backend = pkcs11backend.NewBackend

// ErrPKCS11BackendNotInitialized is returned when the PKCS#11 backend is used
// before initialization.
var ErrPKCS11BackendNotInitialized = pkcs11backend.ErrNotInitialized
