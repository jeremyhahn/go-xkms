// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package issuance

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIssuanceError(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := NewIssuanceError(PhaseCSRValidation, "validation failed", cause)

		msg := err.Error()
		assert.Contains(t, msg, "csr_validation")
		assert.Contains(t, msg, "validation failed")
		assert.Contains(t, msg, "underlying error")

		// Test unwrap
		assert.ErrorIs(t, err, cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := NewIssuanceError(PhaseLinting, "linting failed", nil)

		msg := err.Error()
		assert.Contains(t, msg, "linting")
		assert.Contains(t, msg, "linting failed")
		assert.NotContains(t, msg, "nil")
	})

	t.Run("all phases", func(t *testing.T) {
		phases := []IssuancePhase{
			PhaseCSRValidation,
			PhaseKeyValidation,
			PhaseSerialGeneration,
			PhaseSerialPersistence,
			PhaseLinting,
			PhasePrecertSigning,
			PhaseTBSVerification,
			PhaseCTSubmission,
			PhaseFinalSigning,
			PhasePersistence,
			PhaseAudit,
		}

		for _, phase := range phases {
			err := NewIssuanceError(phase, "test", nil)
			assert.Contains(t, err.Error(), string(phase))
		}
	})
}

func TestLintError(t *testing.T) {
	err := NewLintError("3 errors, 2 warnings", []string{"e_err1", "e_err2", "e_err3"}, []string{"w_warn1", "w_warn2"})

	msg := err.Error()
	assert.Contains(t, msg, "linting failed")
	assert.Contains(t, msg, "3 errors, 2 warnings")

	assert.Len(t, err.Errors, 3)
	assert.Len(t, err.Warnings, 2)
}

func TestCSRValidationError(t *testing.T) {
	err := NewCSRValidationError("publicKey", "key algorithm not allowed")

	msg := err.Error()
	assert.Contains(t, msg, "CSR validation failed")
	assert.Contains(t, msg, "publicKey")
	assert.Contains(t, msg, "key algorithm not allowed")

	assert.Equal(t, "publicKey", err.Field)
	assert.Equal(t, "key algorithm not allowed", err.Message)
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are properly defined
	errs := []error{
		ErrNilInput,
		ErrInvalidCSR,
		ErrInvalidTemplate,
		ErrInvalidConfig,
		ErrKeyValidationFailed,
		ErrSerialGenerationFailed,
		ErrSerialPersistenceFailed,
		ErrLintFailed,
		ErrPrecertSigningFailed,
		ErrFinalCertSigningFailed,
		ErrTBSDeterminismFailed,
		ErrCTSubmissionFailed,
		ErrCertificatePersistenceFailed,
		ErrProfileNotFound,
		ErrIssuanceDisabled,
		ErrAuditFailed,
		ErrValidityPeriodInvalid,
		ErrCTDisabled,
	}

	for _, err := range errs {
		assert.Error(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestIssuancePhaseConstants(t *testing.T) {
	phases := []IssuancePhase{
		PhaseCSRValidation,
		PhaseKeyValidation,
		PhaseSerialGeneration,
		PhaseSerialPersistence,
		PhaseLinting,
		PhasePrecertSigning,
		PhaseTBSVerification,
		PhaseCTSubmission,
		PhaseFinalSigning,
		PhasePersistence,
		PhaseAudit,
	}

	// Ensure all phases have non-empty string values
	for _, phase := range phases {
		assert.NotEmpty(t, string(phase))
	}

	// Ensure phases are unique
	seen := make(map[IssuancePhase]struct{})
	for _, phase := range phases {
		_, exists := seen[phase]
		assert.False(t, exists, "duplicate phase: %s", phase)
		seen[phase] = struct{}{}
	}
}
