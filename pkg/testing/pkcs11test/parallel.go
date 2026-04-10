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

package pkcs11test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// RunParallelFunctionTests verifies Section 5.16 Parallel Function Management of the
// PKCS#11 v3.0 spec. These are legacy functions that must return CKR_FUNCTION_NOT_PARALLEL
// for compliant implementations.
//
// Tests cover:
//   - C_GetFunctionStatus: legacy function always returns CKR_FUNCTION_NOT_PARALLEL
//   - C_CancelFunction: legacy function always returns CKR_FUNCTION_NOT_PARALLEL
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.16
func (s *Suite) RunParallelFunctionTests(t *testing.T) {
	t.Run("C_GetFunctionStatus", s.testGetFunctionStatus)
	t.Run("C_CancelFunction", s.testCancelFunction)
}

// testGetFunctionStatus verifies C_GetFunctionStatus behavior per PKCS#11 v3.0 Section 5.16.1.
// Per the specification, this legacy function must always return CKR_FUNCTION_NOT_PARALLEL.
func (s *Suite) testGetFunctionStatus(t *testing.T) {

	t.Run("valid_session_returns_function_not_parallel", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.GetFunctionStatus(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_FUNCTION_NOT_PARALLEL, rv,
			"GetFunctionStatus should always return CKR_FUNCTION_NOT_PARALLEL")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		rv := m.GetFunctionStatus(invalidSession)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		// Some implementations validate the session handle first and return
		// CKR_SESSION_HANDLE_INVALID; others return CKR_FUNCTION_NOT_PARALLEL
		// unconditionally. Both are spec-compliant behaviors.
		if rv != module.CKR_SESSION_HANDLE_INVALID && rv != module.CKR_FUNCTION_NOT_PARALLEL {
			t.Fatalf("GetFunctionStatus with invalid session: expected CKR_SESSION_HANDLE_INVALID "+
				"or CKR_FUNCTION_NOT_PARALLEL, got %s", rv)
		}
	})
}

// testCancelFunction verifies C_CancelFunction behavior per PKCS#11 v3.0 Section 5.16.2.
// Per the specification, this legacy function must always return CKR_FUNCTION_NOT_PARALLEL.
func (s *Suite) testCancelFunction(t *testing.T) {

	t.Run("valid_session_returns_function_not_parallel", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		rv := m.CancelFunction(sh)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_FUNCTION_NOT_PARALLEL, rv,
			"CancelFunction should always return CKR_FUNCTION_NOT_PARALLEL")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		rv := m.CancelFunction(invalidSession)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		// Some implementations validate the session handle first and return
		// CKR_SESSION_HANDLE_INVALID; others return CKR_FUNCTION_NOT_PARALLEL
		// unconditionally. Both are spec-compliant behaviors.
		if rv != module.CKR_SESSION_HANDLE_INVALID && rv != module.CKR_FUNCTION_NOT_PARALLEL {
			t.Fatalf("CancelFunction with invalid session: expected CKR_SESSION_HANDLE_INVALID "+
				"or CKR_FUNCTION_NOT_PARALLEL, got %s", rv)
		}
	})
}
