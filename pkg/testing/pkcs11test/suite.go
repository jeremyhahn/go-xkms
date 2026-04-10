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

// Package pkcs11test provides a shared OASIS PKCS#11 v3.0 conformance test suite.
//
// The suite verifies PKCS#11 state machine behavior: correct CK_RV return codes,
// state transitions, and operation sequencing. Tests are backend-agnostic and work
// with any transport.Client implementation (mock, embedded, gRPC, etc.).
//
// Files are regular .go files (NOT _test.go) so they are importable by other packages.
// Each file exports methods on *Suite that accept *testing.T.
//
// Usage:
//
//	func TestPKCS11V3Suite(t *testing.T) {
//	    suite := pkcs11test.NewSuite(func(t *testing.T) (*module.Module, func()) {
//	        m, _ := module.New(module.WithClient(myClient), module.WithConfig(module.DefaultConfig()))
//	        return m, func() { m.Finalize() }
//	    })
//	    suite.RunAll(t)
//	}
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package pkcs11test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// ModuleFactory creates a fresh Module instance for testing.
// Each invocation must return an independent, uninitialized module
// and a cleanup function that will be called when the test completes.
type ModuleFactory func(t *testing.T) (m *module.Module, cleanup func())

// SuiteOption configures the conformance suite.
type SuiteOption func(*Suite)

// WithSkipUnsupported causes the suite to skip tests for operations that
// return CKR_FUNCTION_NOT_SUPPORTED instead of failing them.
// This is intended for embedded/xkey transports that do not support all operations.
func WithSkipUnsupported(skip bool) SuiteOption {
	return func(s *Suite) {
		s.skipUnsupported = skip
	}
}

// Suite is a shared PKCS#11 v3.0 conformance test suite.
// It verifies PKCS#11 state machine behavior across any backend.
type Suite struct {
	factory         ModuleFactory
	skipUnsupported bool
}

// NewSuite creates a new conformance suite with the given module factory.
func NewSuite(factory ModuleFactory, opts ...SuiteOption) *Suite {
	s := &Suite{
		factory: factory,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RunAll runs all PKCS#11 v3.0 conformance tests organized by spec sections.
func (s *Suite) RunAll(t *testing.T) {
	t.Run("Section5.4_General", s.RunGeneralTests)
	t.Run("Section5.5_Slot", s.RunSlotTests)
	t.Run("Section5.6_Session", s.RunSessionTests)
	t.Run("Section5.7_Object", s.RunObjectTests)
	t.Run("Section5.8_Encryption", s.RunEncryptionTests)
	t.Run("Section5.9_Decryption", s.RunDecryptionTests)
	t.Run("Section5.10_Digest", s.RunDigestTests)
	t.Run("Section5.11_Signing", s.RunSigningTests)
	t.Run("Section5.12_Verification", s.RunVerificationTests)
	t.Run("Section5.13_DualFunction", s.RunDualFunctionTests)
	t.Run("Section5.14_KeyManagement", s.RunKeyManagementTests)
	t.Run("Section5.15_Random", s.RunRandomTests)
	t.Run("Section5.16_Parallel", s.RunParallelFunctionTests)
	t.Run("Section5.17_Message", s.RunMessageTests)
}

// skipIfUnsupported skips the test if the return value indicates the operation
// is not supported or cannot be performed by this backend.
// When skipUnsupported is true, the following return codes cause a skip:
//   - CKR_FUNCTION_NOT_SUPPORTED: operation not implemented
//   - CKR_FUNCTION_FAILED: operation implemented but backend cannot perform it
//   - CKR_GENERAL_ERROR: backend-level failure (e.g., mock backend without real crypto)
//
// Returns true if the test was skipped.
func (s *Suite) skipIfUnsupported(t *testing.T, rv module.CK_RV) bool {
	t.Helper()
	if !s.skipUnsupported {
		return false
	}
	switch rv {
	case module.CKR_FUNCTION_NOT_SUPPORTED:
		t.Skipf("operation not supported by this backend (CKR_FUNCTION_NOT_SUPPORTED)")
		return true
	case module.CKR_FUNCTION_FAILED:
		t.Skipf("operation failed on this backend (CKR_FUNCTION_FAILED)")
		return true
	case module.CKR_GENERAL_ERROR:
		t.Skipf("operation failed on this backend (CKR_GENERAL_ERROR)")
		return true
	}
	return false
}

// requireRV asserts that the return value matches the expected value.
func requireRV(t *testing.T, expected, actual module.CK_RV, msgAndArgs ...interface{}) {
	t.Helper()
	if expected != actual {
		if len(msgAndArgs) > 0 {
			t.Fatalf("expected %s, got %s: %v", expected, actual, msgAndArgs[0])
		}
		t.Fatalf("expected %s, got %s", expected, actual)
	}
}

// assertRV asserts that the return value matches the expected value (non-fatal).
func assertRV(t *testing.T, expected, actual module.CK_RV, msgAndArgs ...interface{}) {
	t.Helper()
	if expected != actual {
		if len(msgAndArgs) > 0 {
			t.Errorf("expected %s, got %s: %v", expected, actual, msgAndArgs[0])
		} else {
			t.Errorf("expected %s, got %s", expected, actual)
		}
	}
}
