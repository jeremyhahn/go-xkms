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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/testing/pkcs11test"

// PKCS#11 test-harness surface re-exported so xkey test suites build the
// canonical pkg/testing/pkcs11test mock module and conformance suite through
// the SDK.

// NewPKCS11TestModuleFactory creates a mock PKCS#11 module and its teardown func.
var NewPKCS11TestModuleFactory = pkcs11test.NewModuleFactory

// NewPKCS11TestSuite constructs a PKCS#11 conformance test suite.
var NewPKCS11TestSuite = pkcs11test.NewSuite
