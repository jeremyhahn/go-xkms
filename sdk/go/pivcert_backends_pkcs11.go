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

import pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"

// PIVPKCS11Backend is the concrete PKCS#11-backed PIV certificate store
// returned by the NewPIVPKCS11Backend* constructors. It is re-exported so
// callers can name the constructor return type through the SDK.
type PIVPKCS11Backend = pivpkcs11.PKCS11CertStorage

// PKCS#11-backed PIV certificate storage constructors re-exported behind the
// pkcs11 build tag, matching pkg/pivcert/pkcs11. The xkey yubikey PIV paths
// reach these through the SDK only when built with -tags pkcs11.
//
// The names carry PIV prefixes because the bare New SDK name aliases the xkms
// backend client constructor.

// NewPIVPKCS11Backend constructs a PKCS#11-backed PIV certificate store from a
// PIVPKCS11StorageConfig.
var NewPIVPKCS11Backend = pivpkcs11.New

// NewPIVPKCS11BackendFromSession constructs a PKCS#11-backed PIV certificate
// store from an existing session.
var NewPIVPKCS11BackendFromSession = pivpkcs11.NewFromSession

// NewPIVPKCS11BackendFromSessionWithSO constructs a PKCS#11-backed PIV
// certificate store from an existing session using SO/User PINs.
var NewPIVPKCS11BackendFromSessionWithSO = pivpkcs11.NewFromSessionWithSO

// NewPIVPKCS11SlotModel constructs the PIV slot model over a PKCS#11 session pool.
var NewPIVPKCS11SlotModel = pivpkcs11.NewPIVSlotModel
