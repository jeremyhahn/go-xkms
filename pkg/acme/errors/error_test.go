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

package errors

import (
	"errors"
	"testing"
	"time"
)

func TestTrustedCAError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *TrustedCAError
		expected string
	}{
		{
			name: "returns detail message",
			err: &TrustedCAError{
				Type:   Malformed,
				Detail: "request body was malformed",
			},
			expected: "request body was malformed",
		},
		{
			name: "empty detail",
			err: &TrustedCAError{
				Type:   InternalServer,
				Detail: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTrustedCAError_Unwrap_NoCause(t *testing.T) {
	err := &TrustedCAError{
		Type:   Malformed,
		Detail: "test",
	}

	unwrapped := err.Unwrap()
	if len(unwrapped) != 1 {
		t.Fatalf("Unwrap() returned %d errors, want 1", len(unwrapped))
	}
	if unwrapped[0] != Malformed {
		t.Errorf("Unwrap()[0] = %v, want %v", unwrapped[0], Malformed)
	}

	// Verify errors.Is works with the type
	if !errors.Is(err, Malformed) {
		t.Error("errors.Is(err, Malformed) = false, want true")
	}
}

func TestTrustedCAError_Unwrap_WithCause(t *testing.T) {
	sentinel := errors.New("ca: certificate not found")
	err := &TrustedCAError{
		Type:   NotFound,
		Detail: "failed to get certificate",
		Cause:  sentinel,
	}

	unwrapped := err.Unwrap()
	if len(unwrapped) != 2 {
		t.Fatalf("Unwrap() returned %d errors, want 2", len(unwrapped))
	}
	if unwrapped[0] != NotFound {
		t.Errorf("Unwrap()[0] = %v, want %v", unwrapped[0], NotFound)
	}
	if unwrapped[1] != sentinel {
		t.Errorf("Unwrap()[1] = %v, want %v", unwrapped[1], sentinel)
	}

	// errors.Is must match both the ErrorType and the sentinel cause
	if !errors.Is(err, NotFound) {
		t.Error("errors.Is(err, NotFound) = false, want true")
	}
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is(err, sentinel) = false, want true")
	}
	if errors.Is(err, Malformed) {
		t.Error("errors.Is(err, Malformed) = true, want false")
	}
}

func TestTrustedCAError_WithCause(t *testing.T) {
	original := &TrustedCAError{
		Type:       NotFound,
		Detail:     "not found",
		RetryAfter: 5 * time.Second,
		Instance:   "https://example.com/instance",
	}

	sentinel := errors.New("ca: certificate not found")
	withCause := original.WithCause(sentinel)

	// Original unchanged
	if original.Cause != nil {
		t.Error("original Cause was modified")
	}

	// New error has cause
	if withCause.Cause != sentinel {
		t.Errorf("Cause = %v, want %v", withCause.Cause, sentinel)
	}

	// Preserves other fields
	if withCause.Type != NotFound {
		t.Errorf("Type = %v, want %v", withCause.Type, NotFound)
	}
	if withCause.Detail != "not found" {
		t.Errorf("Detail = %q, want %q", withCause.Detail, "not found")
	}
	if withCause.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter = %v, want 5s", withCause.RetryAfter)
	}
	if withCause.Instance != "https://example.com/instance" {
		t.Errorf("Instance = %q, want URL", withCause.Instance)
	}

	// errors.Is traverses the cause chain
	if !errors.Is(withCause, sentinel) {
		t.Error("errors.Is(withCause, sentinel) = false, want true")
	}
	if !errors.Is(withCause, NotFound) {
		t.Error("errors.Is(withCause, NotFound) = false, want true")
	}
}

func TestWrap(t *testing.T) {
	sentinel := errors.New("ca: certificate not found")
	err := Wrap(NotFound, sentinel, "failed to get certificate for %s", "example.com")

	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatal("Wrap() did not return *TrustedCAError")
	}
	if tce.Type != NotFound {
		t.Errorf("Type = %v, want %v", tce.Type, NotFound)
	}
	if tce.Cause != sentinel {
		t.Errorf("Cause = %v, want %v", tce.Cause, sentinel)
	}
	if tce.Detail != "failed to get certificate for example.com" {
		t.Errorf("Detail = %q, want formatted message", tce.Detail)
	}

	// errors.Is works for both the type and the sentinel
	if !errors.Is(err, NotFound) {
		t.Error("errors.Is(err, NotFound) = false, want true")
	}
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is(err, sentinel) = false, want true")
	}
	if errors.Is(err, Malformed) {
		t.Error("errors.Is(err, Malformed) = true, want false")
	}
}

func TestWrap_NestedCause(t *testing.T) {
	inner := errors.New("disk I/O error")
	middle := Wrap(StorageFailure, inner, "storage backend failed")
	outer := Wrap(NotFound, middle, "certificate lookup failed")

	// errors.Is traverses the full chain
	if !errors.Is(outer, NotFound) {
		t.Error("errors.Is(outer, NotFound) = false, want true")
	}
	if !errors.Is(outer, StorageFailure) {
		t.Error("errors.Is(outer, StorageFailure) = false, want true")
	}
	if !errors.Is(outer, inner) {
		t.Error("errors.Is(outer, inner) = false, want true")
	}

	// errors.As extracts the middle TrustedCAError
	var tce *TrustedCAError
	if !errors.As(outer, &tce) {
		t.Error("errors.As(outer, &tce) = false, want true")
	}
}

func TestTrustedCAError_IsMethod(t *testing.T) {
	err := &TrustedCAError{
		Type:   NotFound,
		Detail: "account not found",
	}

	tests := []struct {
		name     string
		target   error
		expected bool
	}{
		{
			name:     "matches ErrorType",
			target:   NotFound,
			expected: true,
		},
		{
			name:     "does not match different ErrorType",
			target:   Malformed,
			expected: false,
		},
		{
			name: "matches TrustedCAError with same type",
			target: &TrustedCAError{
				Type:   NotFound,
				Detail: "different detail",
			},
			expected: true,
		},
		{
			name: "does not match TrustedCAError with different type",
			target: &TrustedCAError{
				Type:   Unauthorized,
				Detail: "test",
			},
			expected: false,
		},
		{
			name:     "does not match unrelated error",
			target:   errors.New("unrelated"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := err.Is(tt.target); got != tt.expected {
				t.Errorf("Is(%v) = %v, want %v", tt.target, got, tt.expected)
			}
		})
	}
}

func TestTrustedCAError_WithSubErrors(t *testing.T) {
	original := &TrustedCAError{
		Type:       CompoundError,
		Detail:     "multiple errors",
		Cause:      errors.New("original cause"),
		RetryAfter: 5 * time.Second,
		Instance:   "https://example.com/action",
	}

	subErrors := []SubError{
		{
			TrustedCAError: &TrustedCAError{Type: BadCSR, Detail: "invalid CSR"},
			Identifier:     ACMEIdentifier{Type: "dns", Value: "example.com"},
		},
	}

	newErr := original.WithSubErrors(subErrors)

	// Original unchanged
	if len(original.SubErrors) != 0 {
		t.Error("original SubErrors modified")
	}

	// New error has sub-errors
	if len(newErr.SubErrors) != 1 {
		t.Errorf("SubErrors len = %d, want 1", len(newErr.SubErrors))
	}

	// Preserves all fields including Cause
	if newErr.Type != CompoundError {
		t.Errorf("Type = %v, want %v", newErr.Type, CompoundError)
	}
	if newErr.Cause == nil || newErr.Cause.Error() != "original cause" {
		t.Errorf("Cause not preserved, got %v", newErr.Cause)
	}
	if newErr.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter = %v, want 5s", newErr.RetryAfter)
	}
	if newErr.Instance != "https://example.com/action" {
		t.Errorf("Instance = %q, want URL", newErr.Instance)
	}
}

func TestTrustedCAError_WithInstance(t *testing.T) {
	original := &TrustedCAError{
		Type:   UserActionRequired,
		Detail: "action required",
		Cause:  errors.New("original cause"),
	}

	newErr := original.WithInstance("https://example.com/action")

	if original.Instance != "" {
		t.Error("original Instance modified")
	}
	if newErr.Instance != "https://example.com/action" {
		t.Errorf("Instance = %q, want URL", newErr.Instance)
	}
	if newErr.Type != UserActionRequired {
		t.Errorf("Type = %v, want %v", newErr.Type, UserActionRequired)
	}
	if newErr.Cause == nil || newErr.Cause.Error() != "original cause" {
		t.Errorf("Cause not preserved, got %v", newErr.Cause)
	}
}

func TestTrustedCAError_WithRetryAfter(t *testing.T) {
	original := &TrustedCAError{
		Type:   RateLimit,
		Detail: "too many requests",
		Cause:  errors.New("original cause"),
	}

	newErr := original.WithRetryAfter(30 * time.Second)

	if original.RetryAfter != 0 {
		t.Error("original RetryAfter modified")
	}
	if newErr.RetryAfter != 30*time.Second {
		t.Errorf("RetryAfter = %v, want 30s", newErr.RetryAfter)
	}
	if newErr.Cause == nil || newErr.Cause.Error() != "original cause" {
		t.Errorf("Cause not preserved, got %v", newErr.Cause)
	}
}

func TestNewTrustedCAError(t *testing.T) {
	err := NewTrustedCAError(BadNonce, "nonce expired")

	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatal("NewTrustedCAError() did not return *TrustedCAError")
	}
	if tce.Type != BadNonce {
		t.Errorf("Type = %v, want %v", tce.Type, BadNonce)
	}
	if tce.Detail != "nonce expired" {
		t.Errorf("Detail = %q, want 'nonce expired'", tce.Detail)
	}
}

func TestNewTrustedCAErrorf(t *testing.T) {
	err := newTrustedCAErrorf(AccountDoesNotExist, "account %s not found", "abc123")

	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatal("newTrustedCAErrorf() did not return *TrustedCAError")
	}
	if tce.Detail != "account abc123 not found" {
		t.Errorf("Detail = %q, want formatted message", tce.Detail)
	}
}

func TestNewTrustedCAErrorWithRetryAfter(t *testing.T) {
	err := NewTrustedCAErrorWithRetryAfter(RateLimit, 60*time.Second, "rate limited for %d seconds", 60)

	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatal("NewTrustedCAErrorWithRetryAfter() did not return *TrustedCAError")
	}
	if tce.Type != RateLimit {
		t.Errorf("Type = %v, want %v", tce.Type, RateLimit)
	}
	if tce.RetryAfter != 60*time.Second {
		t.Errorf("RetryAfter = %v, want 60s", tce.RetryAfter)
	}
	if tce.Detail != "rate limited for 60 seconds" {
		t.Errorf("Detail = %q, want formatted message", tce.Detail)
	}
}

func TestNewTrustedCAErrorWithInstance(t *testing.T) {
	err := NewTrustedCAErrorWithInstance(UserActionRequired, "https://example.com/terms", "agree to terms")

	tce, ok := err.(*TrustedCAError)
	if !ok {
		t.Fatal("NewTrustedCAErrorWithInstance() did not return *TrustedCAError")
	}
	if tce.Type != UserActionRequired {
		t.Errorf("Type = %v, want %v", tce.Type, UserActionRequired)
	}
	if tce.Instance != "https://example.com/terms" {
		t.Errorf("Instance = %q, want URL", tce.Instance)
	}
}

func TestIsType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   ErrorType
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			target:   Malformed,
			expected: false,
		},
		{
			name:     "matching type",
			err:      &TrustedCAError{Type: Malformed},
			target:   Malformed,
			expected: true,
		},
		{
			name:     "non-matching type",
			err:      &TrustedCAError{Type: Malformed},
			target:   Unauthorized,
			expected: false,
		},
		{
			name:     "non-TrustedCAError",
			err:      errors.New("regular error"),
			target:   Malformed,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsType(tt.err, tt.target); got != tt.expected {
				t.Errorf("IsType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetType(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedType ErrorType
		expectedOk   bool
	}{
		{
			name:         "TrustedCAError",
			err:          &TrustedCAError{Type: BadCSR},
			expectedType: BadCSR,
			expectedOk:   true,
		},
		{
			name:         "non-TrustedCAError",
			err:          errors.New("regular"),
			expectedType: 0,
			expectedOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotOk := GetType(tt.err)
			if gotType != tt.expectedType || gotOk != tt.expectedOk {
				t.Errorf("GetType() = (%v, %v), want (%v, %v)",
					gotType, gotOk, tt.expectedType, tt.expectedOk)
			}
		})
	}
}

func TestGetRetryAfter(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		expectedDuration time.Duration
		expectedOk       bool
	}{
		{
			name: "with retry after",
			err: &TrustedCAError{
				Type:       RateLimit,
				RetryAfter: 30 * time.Second,
			},
			expectedDuration: 30 * time.Second,
			expectedOk:       true,
		},
		{
			name: "without retry after",
			err: &TrustedCAError{
				Type: Malformed,
			},
			expectedDuration: 0,
			expectedOk:       false,
		},
		{
			name:             "non-TrustedCAError",
			err:              errors.New("regular"),
			expectedDuration: 0,
			expectedOk:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDuration, gotOk := GetRetryAfter(tt.err)
			if gotDuration != tt.expectedDuration || gotOk != tt.expectedOk {
				t.Errorf("GetRetryAfter() = (%v, %v), want (%v, %v)",
					gotDuration, gotOk, tt.expectedDuration, tt.expectedOk)
			}
		})
	}
}

func TestGetInstance(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		expectedInstance string
		expectedOk       bool
	}{
		{
			name: "with instance",
			err: &TrustedCAError{
				Type:     UserActionRequired,
				Instance: "https://example.com/action",
			},
			expectedInstance: "https://example.com/action",
			expectedOk:       true,
		},
		{
			name: "without instance",
			err: &TrustedCAError{
				Type: Malformed,
			},
			expectedInstance: "",
			expectedOk:       false,
		},
		{
			name:             "non-TrustedCAError",
			err:              errors.New("regular"),
			expectedInstance: "",
			expectedOk:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotInstance, gotOk := GetInstance(tt.err)
			if gotInstance != tt.expectedInstance || gotOk != tt.expectedOk {
				t.Errorf("GetInstance() = (%v, %v), want (%v, %v)",
					gotInstance, gotOk, tt.expectedInstance, tt.expectedOk)
			}
		})
	}
}

func TestGetSubErrors(t *testing.T) {
	subErrors := []SubError{
		{
			TrustedCAError: &TrustedCAError{Type: BadCSR, Detail: "invalid CSR"},
			Identifier:     ACMEIdentifier{Type: "dns", Value: "example.com"},
		},
	}

	tests := []struct {
		name       string
		err        error
		hasErrors  bool
		errorCount int
	}{
		{
			name: "with sub-errors",
			err: &TrustedCAError{
				Type:      CompoundError,
				SubErrors: subErrors,
			},
			hasErrors:  true,
			errorCount: 1,
		},
		{
			name: "without sub-errors",
			err: &TrustedCAError{
				Type: Malformed,
			},
			hasErrors:  false,
			errorCount: 0,
		},
		{
			name:       "non-TrustedCAError",
			err:        errors.New("regular"),
			hasErrors:  false,
			errorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErrors, gotOk := GetSubErrors(tt.err)
			if gotOk != tt.hasErrors {
				t.Errorf("GetSubErrors() ok = %v, want %v", gotOk, tt.hasErrors)
			}
			if len(gotErrors) != tt.errorCount {
				t.Errorf("GetSubErrors() len = %d, want %d", len(gotErrors), tt.errorCount)
			}
		})
	}
}

func TestACMEIdentifier(t *testing.T) {
	id := ACMEIdentifier{
		Type:  "dns",
		Value: "example.com",
	}

	if id.Type != "dns" {
		t.Errorf("Type = %q, want 'dns'", id.Type)
	}
	if id.Value != "example.com" {
		t.Errorf("Value = %q, want 'example.com'", id.Value)
	}
}

func TestSubError(t *testing.T) {
	se := SubError{
		TrustedCAError: &TrustedCAError{
			Type:   RejectedIdentifier,
			Detail: "domain blocked",
		},
		Identifier: ACMEIdentifier{
			Type:  "dns",
			Value: "blocked.example.com",
		},
	}

	if se.Type != RejectedIdentifier {
		t.Errorf("Type = %v, want %v", se.Type, RejectedIdentifier)
	}
	if se.Identifier.Value != "blocked.example.com" {
		t.Errorf("Identifier.Value = %q, want 'blocked.example.com'", se.Identifier.Value)
	}
}
