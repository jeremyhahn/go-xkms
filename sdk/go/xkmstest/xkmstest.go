// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package xkmstest re-exports the go-xkms test-support helpers that SDK
// consumers' test suites need. It is for tests only: no production package
// imports it, so the helpers never reach a production binary. Keep the
// production SDK (package xkms) free of test helpers and add them here.
package xkmstest

import (
	"github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
)

// NewPKCS11ModuleFactory creates a mock PKCS#11 module and its teardown func.
var NewPKCS11ModuleFactory = pkcs11test.NewModuleFactory

// NewPKCS11Suite constructs a PKCS#11 conformance test suite.
var NewPKCS11Suite = pkcs11test.NewSuite

// EnrollPlatformSRK enrolls the Platform SRK on a freshly provisioned
// simulator or swtpm. Provision creates only the TCG-standard keys, and xkms
// seals under the Platform SRK.
var EnrollPlatformSRK = tpm2test.EnrollPlatformSRK
