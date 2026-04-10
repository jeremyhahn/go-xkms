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

package module_test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"
)

// TestPKCS11V3Suite runs the shared PKCS#11 v3.0 conformance suite
// against a module backed by the CryptoMockClient which provides real
// cryptographic operations using Go stdlib crypto.
func TestPKCS11V3Suite(t *testing.T) {
	suite := pkcs11test.NewSuite(pkcs11test.NewModuleFactory)
	suite.RunAll(t)
}
