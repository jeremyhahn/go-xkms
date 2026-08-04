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

package main

import "errors"

// Sentinel errors shared across xkmsctl test files as underlying causes
// injected into fakes and mocks.
var (
	errTestBackendCreation       = errors.New("backend creation failed")
	errTestSourceBackendCreation = errors.New("source backend creation failed")
	errTestDestBackendCreation   = errors.New("dest backend creation failed")
	errTestExport                = errors.New("export failed")
	errTestGetKeyOp              = errors.New("get key operation failed")
	errTestListKeys              = errors.New("list keys failed")
	errTestError                 = errors.New("test error")
)
