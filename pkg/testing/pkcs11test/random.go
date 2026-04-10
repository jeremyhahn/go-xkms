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

// RunRandomTests verifies Section 5.15 Random Number Generation of the
// PKCS#11 v3.0 spec.
//
// Tests cover:
//   - C_GenerateRandom: random byte generation with various lengths and error handling
//   - C_SeedRandom: seeding the RNG and error handling
//
// References:
//   - OASIS PKCS#11 v3.0 Section 5.15
func (s *Suite) RunRandomTests(t *testing.T) {
	t.Run("C_GenerateRandom", s.testGenerateRandom)
	t.Run("C_SeedRandom", s.testSeedRandom)
}

// testGenerateRandom verifies C_GenerateRandom behavior per PKCS#11 v3.0 Section 5.15.2.
func (s *Suite) testGenerateRandom(t *testing.T) {

	t.Run("generate_32_bytes_succeeds", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		data, rv := m.GenerateRandom(sh, 32)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "GenerateRandom(32) should return CKR_OK")

		if len(data) != 32 {
			t.Fatalf("GenerateRandom(32): got %d bytes, want 32", len(data))
		}

		// Verify the output is not all zeros (probabilistically impossible for a real RNG).
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("GenerateRandom(32) returned all zeros; expected random data")
		}
	})

	t.Run("generate_0_bytes_returns_ok_with_empty", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		data, rv := m.GenerateRandom(sh, 0)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_OK, rv, "GenerateRandom(0) should return CKR_OK")

		if len(data) != 0 {
			t.Fatalf("GenerateRandom(0): got %d bytes, want 0", len(data))
		}
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		_, rv := m.GenerateRandom(invalidSession, 32)
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"GenerateRandom with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}

// testSeedRandom verifies C_SeedRandom behavior per PKCS#11 v3.0 Section 5.15.1.
func (s *Suite) testSeedRandom(t *testing.T) {

	t.Run("seed_with_valid_data_succeeds_or_not_supported", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		sh := openRWSession(t, m)

		seed := []byte("conformance-test-seed-entropy-data")
		rv := m.SeedRandom(sh, seed)
		if s.skipIfUnsupported(t, rv) {
			return
		}

		// Per PKCS#11, SeedRandom may return CKR_RANDOM_SEED_NOT_SUPPORTED
		// if the token's RNG does not accept external seed data. Both
		// CKR_OK and CKR_RANDOM_SEED_NOT_SUPPORTED are acceptable.
		if rv == module.CKR_RANDOM_SEED_NOT_SUPPORTED {
			t.Skipf("SeedRandom returned CKR_RANDOM_SEED_NOT_SUPPORTED; token RNG does not accept seeds")
			return
		}
		requireRV(t, module.CKR_OK, rv, "SeedRandom with valid seed should return CKR_OK")
	})

	t.Run("invalid_session_returns_session_handle_invalid", func(t *testing.T) {
		m, cleanup := s.createInitializedModule(t)
		defer cleanup()

		invalidSession := module.SessionHandle(0xDEADBEEF)

		rv := m.SeedRandom(invalidSession, []byte("seed"))
		if s.skipIfUnsupported(t, rv) {
			return
		}
		requireRV(t, module.CKR_SESSION_HANDLE_INVALID, rv,
			"SeedRandom with invalid session should return CKR_SESSION_HANDLE_INVALID")
	})
}
