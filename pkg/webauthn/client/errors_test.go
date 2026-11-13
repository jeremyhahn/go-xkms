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

package client

import (
	"errors"
	"testing"
)

func TestClientError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ClientError
		expected string
	}{
		{
			name:     "with operation",
			err:      &ClientError{Op: "register", Err: ErrServerUnavailable},
			expected: "webauthn/client: register: webauthn/client: server unavailable",
		},
		{
			name:     "without operation",
			err:      &ClientError{Op: "", Err: ErrNilConfig},
			expected: "webauthn/client: nil config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestWrapError_NilPassthrough(t *testing.T) {
	result := wrapError("test", nil)
	if result != nil {
		t.Errorf("wrapError with nil should return nil, got %v", result)
	}
}

func TestWrapError_WrapsError(t *testing.T) {
	inner := errors.New("something broke")
	result := wrapError("register", inner)

	if result == nil {
		t.Fatal("wrapError should not return nil for non-nil error")
	}

	ce, ok := result.(*ClientError)
	if !ok {
		t.Fatalf("expected *ClientError, got %T", result)
	}

	if ce.Op != "register" {
		t.Errorf("Op = %q, want %q", ce.Op, "register")
	}

	if !errors.Is(result, inner) {
		t.Error("wrapped error should match inner via errors.Is")
	}
}

func TestServerError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ServerError
		expected string
	}{
		{
			name: "with error code",
			err: &ServerError{
				StatusCode: 400,
				ErrorCode:  "invalid_request",
				Message:    "email is required",
			},
			expected: "webauthn/client: server error 400 (invalid_request): email is required",
		},
		{
			name: "without error code",
			err: &ServerError{
				StatusCode: 500,
				Message:    "internal server error",
			},
			expected: "webauthn/client: server error 500: internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestServerError_Is(t *testing.T) {
	tests := []struct {
		name        string
		err         *ServerError
		target      error
		shouldMatch bool
	}{
		{
			name:        "500 matches ErrServerUnavailable",
			err:         &ServerError{StatusCode: 500},
			target:      ErrServerUnavailable,
			shouldMatch: true,
		},
		{
			name:        "503 matches ErrServerUnavailable",
			err:         &ServerError{StatusCode: 503},
			target:      ErrServerUnavailable,
			shouldMatch: true,
		},
		{
			name:        "400 does not match ErrServerUnavailable",
			err:         &ServerError{StatusCode: 400},
			target:      ErrServerUnavailable,
			shouldMatch: false,
		},
		{
			name:        "200 does not match ErrServerUnavailable",
			err:         &ServerError{StatusCode: 200},
			target:      ErrServerUnavailable,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Is(tt.target)
			if result != tt.shouldMatch {
				t.Errorf("Is() = %v, want %v", result, tt.shouldMatch)
			}
		})
	}
}

func TestRelyingPartyRejection_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *RelyingPartyRejection
		expected string
	}{
		{
			name:     "with message",
			err:      &RelyingPartyRejection{Err: ErrRegistrationFailed, Message: "attestation rejected"},
			expected: "webauthn/client: registration failed: attestation rejected",
		},
		{
			name:     "without message",
			err:      &RelyingPartyRejection{Err: ErrAuthenticationFailed},
			expected: "webauthn/client: authentication failed: rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}
