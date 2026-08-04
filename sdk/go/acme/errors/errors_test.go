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
)

func TestNew(t *testing.T) {
	err := New(CodeNotFound, "TestOp", "resource not found")

	if err.Code != CodeNotFound {
		t.Errorf("expected code %v, got %v", CodeNotFound, err.Code)
	}
	if err.Op != "TestOp" {
		t.Errorf("expected op 'TestOp', got %q", err.Op)
	}
	if err.Message != "resource not found" {
		t.Errorf("expected message 'resource not found', got %q", err.Message)
	}
	if err.Err != nil {
		t.Errorf("expected nil underlying error, got %v", err.Err)
	}
	if err.Context != nil {
		t.Errorf("expected nil context, got %v", err.Context)
	}
}

func TestNew_EmptyFields(t *testing.T) {
	err := New(CodeUnknown, "", "")

	if err.Code != CodeUnknown {
		t.Errorf("expected code %v, got %v", CodeUnknown, err.Code)
	}
	if err.Op != "" {
		t.Errorf("expected empty op, got %q", err.Op)
	}
	if err.Message != "" {
		t.Errorf("expected empty message, got %q", err.Message)
	}
}

func TestWrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := Wrap(underlying, CodeInternal, "WrapOp", "wrapped message")

	if err.Code != CodeInternal {
		t.Errorf("expected code %v, got %v", CodeInternal, err.Code)
	}
	if err.Err != underlying {
		t.Error("expected wrapped error to be preserved")
	}
	if !errors.Is(err, underlying) {
		t.Error("expected errors.Is to find underlying error")
	}
}

func TestWrap_NilError(t *testing.T) {
	err := Wrap(nil, CodeInternal, "WrapOp", "wrapped message")

	if err.Err != nil {
		t.Errorf("expected nil underlying error, got %v", err.Err)
	}
}

func TestCAError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *CAError
		expected string
	}{
		{
			name:     "without underlying error",
			err:      New(CodeNotFound, "Get", "key not found"),
			expected: "NOT_FOUND: Get: key not found",
		},
		{
			name:     "with underlying error",
			err:      Wrap(errors.New("io error"), CodeInternal, "Read", "failed to read"),
			expected: "INTERNAL: Read: failed to read: io error",
		},
		{
			name:     "ACME error code",
			err:      New(CodeACMEBadNonce, "ValidateNonce", "invalid nonce"),
			expected: "urn:ietf:params:acme:error:badNonce: ValidateNonce: invalid nonce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestCAError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying")
	err := Wrap(underlying, CodeInternal, "Op", "message")

	if unwrapped := err.Unwrap(); unwrapped != underlying {
		t.Error("expected Unwrap to return underlying error")
	}
}

func TestCAError_Unwrap_Nil(t *testing.T) {
	err := New(CodeInternal, "Op", "message")

	if unwrapped := err.Unwrap(); unwrapped != nil {
		t.Errorf("expected Unwrap to return nil, got %v", unwrapped)
	}
}

func TestCAError_Is(t *testing.T) {
	err1 := New(CodeNotFound, "Op1", "message1")
	err2 := New(CodeNotFound, "Op2", "message2")
	err3 := New(CodeInternal, "Op3", "message3")

	if !errors.Is(err1, err2) {
		t.Error("expected errors with same code to match")
	}
	if errors.Is(err1, err3) {
		t.Error("expected errors with different codes to not match")
	}
}

func TestCAError_Is_NonCAError(t *testing.T) {
	err := New(CodeNotFound, "Op", "message")
	stdErr := errors.New("standard error")

	if err.Is(stdErr) {
		t.Error("expected Is to return false for non-CAError")
	}
}

func TestCAError_IsRetryable(t *testing.T) {
	tests := []struct {
		code      ErrorCode
		retryable bool
	}{
		{CodeNotFound, false},
		{CodeInvalidInput, false},
		{CodeUnavailable, true},
		{CodeTimeout, true},
		{CodeResourceExhausted, true},
		{CodeInternal, false},
		{CodeACMEBadNonce, true},
		{CodeACMERateLimited, true},
		{CodeACMEServerInternal, true},
		{CodeACMEMalformed, false},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			err := New(tt.code, "Op", "message")
			if got := err.IsRetryable(); got != tt.retryable {
				t.Errorf("expected IsRetryable=%v for %v, got %v", tt.retryable, tt.code, got)
			}
		})
	}
}

func TestCAError_WithContext(t *testing.T) {
	err := New(CodeNotFound, "Op", "message")
	err.WithContext("key", "value")
	err.WithContext("count", 42)

	if err.Context["key"] != "value" {
		t.Error("expected context key to be set")
	}
	if err.Context["count"] != 42 {
		t.Error("expected context count to be set")
	}
}

func TestCAError_WithContext_Chaining(t *testing.T) {
	err := New(CodeNotFound, "Op", "message").
		WithContext("a", 1).
		WithContext("b", 2).
		WithContext("c", 3)

	if len(err.Context) != 3 {
		t.Errorf("expected 3 context entries, got %d", len(err.Context))
	}
}

func TestCAError_WithCause(t *testing.T) {
	underlying := errors.New("underlying")
	err := New(CodeInternal, "Op", "message").WithCause(underlying)

	if err.Err != underlying {
		t.Error("expected WithCause to set the underlying error")
	}
	if !errors.Is(err, underlying) {
		t.Error("expected errors.Is to find underlying error")
	}
}

func TestCAError_WithCause_Chaining(t *testing.T) {
	underlying := errors.New("underlying")
	err := New(CodeInternal, "Op", "message").
		WithCause(underlying).
		WithContext("key", "value")

	if err.Err != underlying {
		t.Error("expected underlying error to be preserved")
	}
	if err.Context["key"] != "value" {
		t.Error("expected context to be preserved")
	}
}

func TestHelperConstructors(t *testing.T) {
	tests := []struct {
		name     string
		err      *CAError
		expected ErrorCode
	}{
		{"NewInvalidInput", NewInvalidInput("Op", "msg"), CodeInvalidInput},
		{"NewNotFound", NewNotFound("Op", "msg"), CodeNotFound},
		{"NewAlreadyExists", NewAlreadyExists("Op", "msg"), CodeAlreadyExists},
		{"NewUnauthorized", NewUnauthorized("Op", "msg"), CodeUnauthorized},
		{"NewForbidden", NewForbidden("Op", "msg"), CodeForbidden},
		{"NewConflict", NewConflict("Op", "msg"), CodeConflict},
		{"NewInternal", NewInternal("Op", "msg"), CodeInternal},
		{"NewUnavailable", NewUnavailable("Op", "msg"), CodeUnavailable},
		{"NewTimeout", NewTimeout("Op", "msg"), CodeTimeout},
		{"NewCanceled", NewCanceled("Op", "msg"), CodeCanceled},
		{"NewConnection", NewConnection("Op", "msg"), CodeConnection},
		{"NewNotInitialized", NewNotInitialized("Op", "msg"), CodeNotInitialized},
		{"NewConfiguration", NewConfiguration("Op", "msg"), CodeConfiguration},
		{"NewResourceExhausted", NewResourceExhausted("Op", "msg"), CodeResourceExhausted},
		{"NewUnimplemented", NewUnimplemented("Op", "msg"), CodeUnimplemented},
		{"NewPreconditionFailed", NewPreconditionFailed("Op", "msg"), CodePreconditionFailed},
		{"NewRateLimited", NewRateLimited("Op", "msg"), CodeRateLimited},
		{"NewTransport", NewTransport("Op", "msg"), CodeTransport},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.expected {
				t.Errorf("expected code %v, got %v", tt.expected, tt.err.Code)
			}
			if tt.err.Op != "Op" {
				t.Errorf("expected op 'Op', got %q", tt.err.Op)
			}
			if tt.err.Message != "msg" {
				t.Errorf("expected message 'msg', got %q", tt.err.Message)
			}
		})
	}
}

func TestCodeHelpers(t *testing.T) {
	tests := []struct {
		err      error
		fn       func(error) bool
		expected bool
	}{
		{NewNotFound("Op", "msg"), IsNotFound, true},
		{NewInvalidInput("Op", "msg"), IsNotFound, false},
		{NewAlreadyExists("Op", "msg"), IsAlreadyExists, true},
		{NewInvalidInput("Op", "msg"), IsInvalidInput, true},
		{NewUnauthorized("Op", "msg"), IsUnauthorized, true},
		{NewForbidden("Op", "msg"), IsForbidden, true},
		{NewConflict("Op", "msg"), IsConflict, true},
		{NewTimeout("Op", "msg"), IsTimeout, true},
		{NewUnavailable("Op", "msg"), IsUnavailable, true},
		{NewCanceled("Op", "msg"), IsCanceled, true},
		{NewUnimplemented("Op", "msg"), IsUnimplemented, true},
		{NewInternal("Op", "msg"), IsInternal, true},
		{NewUnavailable("Op", "msg"), IsRetryable, true},
		{NewNotFound("Op", "msg"), IsRetryable, false},
		{NewInvalidInput("Op", "msg"), IsClientError, true},
		{NewInternal("Op", "msg"), IsClientError, false},
		{NewInternal("Op", "msg"), IsServerError, true},
		{NewNotFound("Op", "msg"), IsServerError, false},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			if got := tt.fn(tt.err); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestCode(t *testing.T) {
	if Code(NewNotFound("Op", "msg")) != CodeNotFound {
		t.Error("expected Code to return NotFound")
	}
	if Code(errors.New("regular error")) != CodeUnknown {
		t.Error("expected Code to return Unknown for non-CAError")
	}
}

func TestIs(t *testing.T) {
	err := NewNotFound("Op", "msg")
	if !Is(err, CodeNotFound) {
		t.Error("expected Is to return true for matching code")
	}
	if Is(err, CodeInternal) {
		t.Error("expected Is to return false for non-matching code")
	}
}

func TestOp(t *testing.T) {
	if Op(New(CodeNotFound, "MyOp", "msg")) != "MyOp" {
		t.Error("expected Op to return operation name")
	}
	if Op(errors.New("regular error")) != "" {
		t.Error("expected Op to return empty for non-CAError")
	}
}

func TestMessage(t *testing.T) {
	if Message(New(CodeNotFound, "Op", "my message")) != "my message" {
		t.Error("expected Message to return message")
	}
	if Message(errors.New("regular error")) != "regular error" {
		t.Error("expected Message to return error string for non-CAError")
	}
}

func TestContext(t *testing.T) {
	err := New(CodeNotFound, "Op", "msg").WithContext("key", "value")
	ctx := Context(err)
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx["key"] != "value" {
		t.Error("expected context to contain key")
	}

	stdErr := errors.New("regular error")
	if Context(stdErr) != nil {
		t.Error("expected Context to return nil for non-CAError")
	}
}

func TestContext_NilContext(t *testing.T) {
	err := New(CodeNotFound, "Op", "msg")
	ctx := Context(err)
	if ctx != nil {
		t.Error("expected nil context for error without context")
	}
}

func TestIsRetryable_NonCAError(t *testing.T) {
	stdErr := errors.New("regular error")
	if IsRetryable(stdErr) {
		t.Error("expected IsRetryable to return false for non-CAError")
	}
}

func TestErrorChain(t *testing.T) {
	level1 := errors.New("base error")
	level2 := Wrap(level1, CodeInternal, "level2", "second level")
	level3 := Wrap(level2, CodeNotFound, "level3", "third level")

	// Should find level1 in chain
	if !errors.Is(level3, level1) {
		t.Error("expected to find level1 in error chain")
	}

	// Code should return outermost CAError code
	if Code(level3) != CodeNotFound {
		t.Errorf("expected CodeNotFound, got %v", Code(level3))
	}

	// Unwrap should return level2
	unwrapped := level3.Unwrap()
	if unwrapped != level2 {
		t.Error("expected Unwrap to return level2")
	}
}

func TestNilError(t *testing.T) {
	var err error = nil

	if Code(err) != CodeUnknown {
		t.Error("Code(nil) should return CodeUnknown")
	}
	if Op(err) != "" {
		t.Error("Op(nil) should return empty string")
	}
	if IsRetryable(err) {
		t.Error("IsRetryable(nil) should return false")
	}
	if Context(err) != nil {
		t.Error("Context(nil) should return nil")
	}
}

func TestErrorsAs(t *testing.T) {
	err := NewNotFound("Op", "msg").WithContext("key", "value")

	var caErr *CAError
	if !errors.As(err, &caErr) {
		t.Fatal("expected errors.As to succeed")
	}
	if caErr.Code != CodeNotFound {
		t.Error("expected code to be preserved")
	}
	if caErr.Context["key"] != "value" {
		t.Error("expected context to be preserved")
	}
}

func TestWrappedErrorChain(t *testing.T) {
	base := errors.New("base")
	wrapped := Wrap(base, CodeInternal, "wrap", "wrapped")

	var caErr *CAError
	if !errors.As(wrapped, &caErr) {
		t.Fatal("expected errors.As to find CAError")
	}
	if !errors.Is(wrapped, base) {
		t.Error("expected errors.Is to find base error")
	}
}
