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

// Package main is the entry point for the xkey standalone PKCS#11 shared library.
//
// This module implements a PKCS#11 v3.0 Cryptoki interface that uses an embedded
// (in-process) xkms service, eliminating the need for a remote daemon connection.
// All cryptographic operations are delegated directly to the go-xkms
// singleton via the embedded transport.
//
// Build with: CGO_ENABLED=1 go build -buildmode=c-shared -tags ble -o libxkey_pkcs11.so ./cmd/pkcs11-module
package main

import "C"

// main is required for the c-shared build mode but is never called.
// The shared library is loaded and used via the exported C_* functions.
func main() {}
