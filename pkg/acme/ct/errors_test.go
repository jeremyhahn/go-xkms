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

package ct

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCTSubmissionError(t *testing.T) {
	cause := errors.New("network timeout")
	err := NewCTSubmissionError("Google Argon", "https://ct.googleapis.com", cause)

	t.Run("Error message", func(t *testing.T) {
		msg := err.Error()
		assert.Contains(t, msg, "Google Argon")
		assert.Contains(t, msg, "https://ct.googleapis.com")
		assert.Contains(t, msg, "network timeout")
	})

	t.Run("Unwrap", func(t *testing.T) {
		assert.ErrorIs(t, err, cause)
	})

	t.Run("fields", func(t *testing.T) {
		assert.Equal(t, "Google Argon", err.LogName)
		assert.Equal(t, "https://ct.googleapis.com", err.LogURL)
		assert.Equal(t, cause, err.Cause)
	})
}

func TestPolicyViolationError(t *testing.T) {
	err := NewPolicyViolationError("SCTs", 1, 2)

	t.Run("Error message", func(t *testing.T) {
		msg := err.Error()
		assert.Contains(t, msg, "SCTs")
		assert.Contains(t, msg, "obtained 1")
		assert.Contains(t, msg, "required 2")
	})

	t.Run("fields", func(t *testing.T) {
		assert.Equal(t, "SCTs", err.Requirement)
		assert.Equal(t, 1, err.Obtained)
		assert.Equal(t, 2, err.Required)
	})
}

func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are properly defined
	assert.Error(t, ErrNilInput)
	assert.Error(t, ErrInvalidSCT)
	assert.Error(t, ErrSCTEncodingFailed)
	assert.Error(t, ErrSCTDecodingFailed)
	assert.Error(t, ErrInvalidLogConfig)
	assert.Error(t, ErrNoLogsConfigured)
	assert.Error(t, ErrNoEligibleLogs)
	assert.Error(t, ErrInsufficientSCTs)
	assert.Error(t, ErrInsufficientOperators)
	assert.Error(t, ErrNoRFC6962Log)
	assert.Error(t, ErrCTSubmissionFailed)
	assert.Error(t, ErrCTSubmissionTimeout)
	assert.Error(t, ErrInvalidPolicyConfig)
	assert.Error(t, ErrLogTemporalMismatch)
	assert.Error(t, ErrInvalidSignature)
	assert.Error(t, ErrPrecertPoisonMissing)
	assert.Error(t, ErrPrecertPoisonInvalid)
}

func TestErrorWrapping(t *testing.T) {
	t.Run("CTSubmissionError wraps cause", func(t *testing.T) {
		innerErr := errors.New("inner error")
		err := NewCTSubmissionError("Log", "URL", innerErr)

		assert.True(t, errors.Is(err, innerErr))
	})
}
