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

package authenticator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestAutoGrantHandler_RequestUserPresence tests the auto grant handler
// for user presence requests.
func TestAutoGrantHandler_RequestUserPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		request      *UserPresenceRequest
		wantApproved bool
		wantErr      bool
	}{
		{
			name: "approves presence with full request",
			request: &UserPresenceRequest{
				RPID:      "example.com",
				RPName:    "Example Corp",
				UserName:  "testuser",
				Operation: "register",
				Timeout:   30 * time.Second,
			},
			wantApproved: true,
			wantErr:      false,
		},
		{
			name: "approves presence with minimal request",
			request: &UserPresenceRequest{
				RPID: "example.com",
			},
			wantApproved: true,
			wantErr:      false,
		},
		{
			name:         "approves presence with empty request",
			request:      &UserPresenceRequest{},
			wantApproved: true,
			wantErr:      false,
		},
		{
			name: "approves authenticate operation",
			request: &UserPresenceRequest{
				RPID:      "auth.example.com",
				Operation: "authenticate",
			},
			wantApproved: true,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := NewAutoGrantHandler()
			ctx := context.Background()

			result, err := handler.RequestUserPresence(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Approved != tt.wantApproved {
				t.Errorf("Approved = %v, want %v", result.Approved, tt.wantApproved)
			}
		})
	}
}

// TestAutoGrantHandler_RequestUserPresence_ContextCancellation tests
// that the auto grant handler respects context cancellation.
func TestAutoGrantHandler_RequestUserPresence_ContextCancellation(t *testing.T) {
	t.Parallel()

	handler := NewAutoGrantHandler()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	request := &UserPresenceRequest{
		RPID:      "example.com",
		Operation: "register",
	}

	result, err := handler.RequestUserPresence(ctx, request)

	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestAutoGrantHandler_RequestUserVerification tests the auto grant handler
// for user verification requests.
func TestAutoGrantHandler_RequestUserVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		handler      *AutoGrantHandler
		request      *UserVerificationRequest
		wantVerified bool
		wantPIN      string
		wantErr      bool
	}{
		{
			name:    "verifies without PIN",
			handler: NewAutoGrantHandler(),
			request: &UserVerificationRequest{
				RPID:        "example.com",
				RPName:      "Example Corp",
				UserName:    "testuser",
				Operation:   "register",
				Timeout:     30 * time.Second,
				PINRequired: false,
			},
			wantVerified: true,
			wantPIN:      "",
			wantErr:      false,
		},
		{
			name:    "returns simulated PIN when required",
			handler: NewAutoGrantHandlerWithPIN("123456"),
			request: &UserVerificationRequest{
				RPID:        "example.com",
				PINRequired: true,
			},
			wantVerified: true,
			wantPIN:      "123456",
			wantErr:      false,
		},
		{
			name:    "returns empty PIN when not set but required",
			handler: NewAutoGrantHandler(),
			request: &UserVerificationRequest{
				RPID:        "example.com",
				PINRequired: true,
			},
			wantVerified: true,
			wantPIN:      "",
			wantErr:      false,
		},
		{
			name:    "verifies with minimal request",
			handler: NewAutoGrantHandler(),
			request: &UserVerificationRequest{
				RPID: "example.com",
			},
			wantVerified: true,
			wantPIN:      "",
			wantErr:      false,
		},
		{
			name:         "verifies with empty request",
			handler:      NewAutoGrantHandler(),
			request:      &UserVerificationRequest{},
			wantVerified: true,
			wantPIN:      "",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			result, err := tt.handler.RequestUserVerification(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", result.Verified, tt.wantVerified)
			}

			if result.PIN != tt.wantPIN {
				t.Errorf("PIN = %q, want %q", result.PIN, tt.wantPIN)
			}
		})
	}
}

// TestAutoGrantHandler_RequestUserVerification_ContextCancellation tests
// that the auto grant handler respects context cancellation for verification.
func TestAutoGrantHandler_RequestUserVerification_ContextCancellation(t *testing.T) {
	t.Parallel()

	handler := NewAutoGrantHandlerWithPIN("123456")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	request := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
	}

	result, err := handler.RequestUserVerification(ctx, request)

	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestAutoGrantHandler_ImplementsInterface verifies the handler implements
// the UserPresenceHandler interface.
func TestAutoGrantHandler_ImplementsInterface(t *testing.T) {
	t.Parallel()

	// Compile-time interface satisfaction checks via assignment.
	// These constructors return concrete types, so the result is never nil.
	var _ UserPresenceHandler = NewAutoGrantHandler()
	var _ UserPresenceHandler = NewAutoGrantHandlerWithPIN("test")
}

// TestAutoGrantHandler_ConcurrentAccess tests that the handler is safe
// for concurrent use.
func TestAutoGrantHandler_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	handler := NewAutoGrantHandlerWithPIN("concurrent-pin")
	ctx := context.Background()

	done := make(chan struct{})
	workers := 100

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()

			// Test presence request
			presenceReq := &UserPresenceRequest{
				RPID:      "example.com",
				Operation: "register",
			}
			presenceResult, err := handler.RequestUserPresence(ctx, presenceReq)
			if err != nil {
				t.Errorf("worker %d: presence error: %v", id, err)
				return
			}
			if !presenceResult.Approved {
				t.Errorf("worker %d: presence not approved", id)
			}

			// Test verification request
			verifyReq := &UserVerificationRequest{
				RPID:        "example.com",
				PINRequired: true,
			}
			verifyResult, err := handler.RequestUserVerification(ctx, verifyReq)
			if err != nil {
				t.Errorf("worker %d: verification error: %v", id, err)
				return
			}
			if !verifyResult.Verified {
				t.Errorf("worker %d: not verified", id)
			}
			if verifyResult.PIN != "concurrent-pin" {
				t.Errorf("worker %d: wrong PIN %q", id, verifyResult.PIN)
			}
		}(i)
	}

	for i := 0; i < workers; i++ {
		<-done
	}
}

// TestInteractiveHandler_NewInteractiveHandlerWithIO tests creating an
// interactive handler with custom I/O.
func TestInteractiveHandler_NewInteractiveHandlerWithIO(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("test input\n")
	writer := &bytes.Buffer{}

	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	if handler == nil {
		t.Fatal("NewInteractiveHandlerWithIO returned nil")
	}

	if handler.reader != reader {
		t.Error("reader not set correctly")
	}

	if handler.writer != writer {
		t.Error("writer not set correctly")
	}

	if handler.fd != -1 {
		t.Errorf("fd = %d, want -1", handler.fd)
	}
}

// TestInteractiveHandler_RequestUserPresence tests the interactive handler
// for user presence requests using mock I/O.
func TestInteractiveHandler_RequestUserPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		request      *UserPresenceRequest
		wantApproved bool
		wantErr      error
		wantPrompt   []string
	}{
		{
			name:  "approves on y input",
			input: "y\n",
			request: &UserPresenceRequest{
				RPID:      "example.com",
				RPName:    "Example Corp",
				UserName:  "testuser",
				Operation: "register",
				Timeout:   5 * time.Second,
			},
			wantApproved: true,
			wantErr:      nil,
			wantPrompt:   []string{"register", "Example Corp", "testuser", "'y'"},
		},
		{
			name:  "shows RPID when RPName is empty",
			input: "y\n",
			request: &UserPresenceRequest{
				RPID:      "auth.example.com",
				Operation: "authenticate",
				Timeout:   5 * time.Second,
			},
			wantApproved: true,
			wantErr:      nil,
			wantPrompt:   []string{"authenticate", "auth.example.com"},
		},
		{
			name:  "uses default operation text",
			input: "y\n",
			request: &UserPresenceRequest{
				RPID:    "example.com",
				Timeout: 5 * time.Second,
			},
			wantApproved: true,
			wantErr:      nil,
			wantPrompt:   []string{"operation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}
			handler := NewInteractiveHandlerWithIO(reader, writer, -1)

			ctx := context.Background()
			result, err := handler.RequestUserPresence(ctx, tt.request)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Approved != tt.wantApproved {
				t.Errorf("Approved = %v, want %v", result.Approved, tt.wantApproved)
			}

			output := writer.String()
			for _, s := range tt.wantPrompt {
				if !strings.Contains(output, s) {
					t.Errorf("output missing %q:\n%s", s, output)
				}
			}
		})
	}
}

// TestInteractiveHandler_RequestUserPresence_Denied tests the interactive
// handler when user presence is denied (EOF/error input).
func TestInteractiveHandler_RequestUserPresence_Denied(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("") // Empty input simulates EOF
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx := context.Background()
	request := &UserPresenceRequest{
		RPID:    "example.com",
		Timeout: 5 * time.Second,
	}

	result, err := handler.RequestUserPresence(ctx, request)

	if err != ErrUserPresenceDenied {
		t.Errorf("expected ErrUserPresenceDenied, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestInteractiveHandler_RequestUserPresence_ContextCancellation tests
// that the interactive handler respects context cancellation.
func TestInteractiveHandler_RequestUserPresence_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Use a pipe that blocks forever
	reader := &blockingReader{}
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	request := &UserPresenceRequest{
		RPID:    "example.com",
		Timeout: 5 * time.Second,
	}

	result, err := handler.RequestUserPresence(ctx, request)

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestInteractiveHandler_RequestUserVerification tests the interactive
// handler for user verification requests.
func TestInteractiveHandler_RequestUserVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		request      *UserVerificationRequest
		wantVerified bool
		wantPIN      string
		wantErr      error
		wantPrompt   []string
	}{
		{
			name:  "verifies with PIN",
			input: "123456\n",
			request: &UserVerificationRequest{
				RPID:        "example.com",
				RPName:      "Example Corp",
				UserName:    "testuser",
				Operation:   "authenticate",
				PINRequired: true,
				Timeout:     5 * time.Second,
			},
			wantVerified: true,
			wantPIN:      "123456",
			wantErr:      nil,
			wantPrompt:   []string{"authenticate", "Example Corp", "testuser", "PIN"},
		},
		{
			name:  "verifies with y when PIN not required",
			input: "y\n",
			request: &UserVerificationRequest{
				RPID:        "example.com",
				Operation:   "register",
				PINRequired: false,
				Timeout:     5 * time.Second,
			},
			wantVerified: true,
			wantPIN:      "",
			wantErr:      nil,
			wantPrompt:   []string{"register", "'y'"},
		},
		{
			name:  "shows RPID when RPName is empty",
			input: "pin123\n",
			request: &UserVerificationRequest{
				RPID:        "auth.example.com",
				PINRequired: true,
				Timeout:     5 * time.Second,
			},
			wantVerified: true,
			wantPIN:      "pin123",
			wantErr:      nil,
			wantPrompt:   []string{"auth.example.com"},
		},
		{
			name:  "uses default operation text",
			input: "mypin\n",
			request: &UserVerificationRequest{
				RPID:        "example.com",
				PINRequired: true,
				Timeout:     5 * time.Second,
			},
			wantVerified: true,
			wantPIN:      "mypin",
			wantErr:      nil,
			wantPrompt:   []string{"operation"},
		},
		{
			name:  "trims whitespace from PIN",
			input: "  pin with spaces  \n",
			request: &UserVerificationRequest{
				RPID:        "example.com",
				PINRequired: true,
				Timeout:     5 * time.Second,
			},
			wantVerified: true,
			wantPIN:      "pin with spaces",
			wantErr:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}
			handler := NewInteractiveHandlerWithIO(reader, writer, -1)

			ctx := context.Background()
			result, err := handler.RequestUserVerification(ctx, tt.request)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Verified != tt.wantVerified {
				t.Errorf("Verified = %v, want %v", result.Verified, tt.wantVerified)
			}

			if result.PIN != tt.wantPIN {
				t.Errorf("PIN = %q, want %q", result.PIN, tt.wantPIN)
			}

			output := writer.String()
			for _, s := range tt.wantPrompt {
				if !strings.Contains(output, s) {
					t.Errorf("output missing %q:\n%s", s, output)
				}
			}
		})
	}
}

// TestInteractiveHandler_RequestUserVerification_EmptyPIN tests that
// empty PIN is rejected.
func TestInteractiveHandler_RequestUserVerification_EmptyPIN(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("\n") // Empty PIN
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx := context.Background()
	request := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
		Timeout:     5 * time.Second,
	}

	result, err := handler.RequestUserVerification(ctx, request)

	if err != ErrUserVerificationDenied {
		t.Errorf("expected ErrUserVerificationDenied, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}

	output := writer.String()
	if !strings.Contains(output, "empty PIN") {
		t.Errorf("expected empty PIN message in output:\n%s", output)
	}
}

// TestInteractiveHandler_RequestUserVerification_DeniedWithError tests the
// interactive handler when verification is denied due to a read error.
func TestInteractiveHandler_RequestUserVerification_DeniedWithError(t *testing.T) {
	t.Parallel()

	reader := &errorReader{err: errors.New("simulated read error")}
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx := context.Background()
	request := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
		Timeout:     5 * time.Second,
	}

	result, err := handler.RequestUserVerification(ctx, request)

	if err != ErrUserVerificationDenied {
		t.Errorf("expected ErrUserVerificationDenied, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestInteractiveHandler_RequestUserVerification_WaitConfirmationWithError tests
// that waitForConfirmation returns error on read failure.
func TestInteractiveHandler_RequestUserVerification_WaitConfirmationWithError(t *testing.T) {
	t.Parallel()

	reader := &errorReader{err: errors.New("simulated read error")}
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx := context.Background()
	request := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: false, // Uses waitForConfirmation
		Timeout:     5 * time.Second,
	}

	result, err := handler.RequestUserVerification(ctx, request)

	if err != ErrUserVerificationDenied {
		t.Errorf("expected ErrUserVerificationDenied, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestInteractiveHandler_RequestUserVerification_ContextCancellation tests
// that the interactive handler respects context cancellation for verification.
func TestInteractiveHandler_RequestUserVerification_ContextCancellation(t *testing.T) {
	t.Parallel()

	reader := &blockingReader{}
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	request := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
		Timeout:     5 * time.Second,
	}

	result, err := handler.RequestUserVerification(ctx, request)

	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
}

// TestInteractiveHandler_DefaultTimeout tests that the default timeout
// is used when none is specified in the request.
func TestInteractiveHandler_DefaultTimeout(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("y\n")
	writer := &bytes.Buffer{}
	handler := NewInteractiveHandlerWithIO(reader, writer, -1)

	ctx := context.Background()

	// Test presence request with zero timeout
	presenceReq := &UserPresenceRequest{
		RPID:    "example.com",
		Timeout: 0, // Should use default
	}

	result, err := handler.RequestUserPresence(ctx, presenceReq)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !result.Approved {
		t.Error("presence not approved")
	}

	// Test verification request with zero timeout
	reader = strings.NewReader("pin\n")
	handler = NewInteractiveHandlerWithIO(reader, writer, -1)

	verifyReq := &UserVerificationRequest{
		RPID:        "example.com",
		PINRequired: true,
		Timeout:     0, // Should use default
	}

	verifyResult, err := handler.RequestUserVerification(ctx, verifyReq)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !verifyResult.Verified {
		t.Error("verification failed")
	}
}

// TestInteractiveHandler_ImplementsInterface verifies the handler
// implements the UserPresenceHandler interface.
func TestInteractiveHandler_ImplementsInterface(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("")
	writer := &bytes.Buffer{}

	// Compile-time interface satisfaction check via assignment.
	// The constructor returns a concrete type, so the result is never nil.
	var _ UserPresenceHandler = NewInteractiveHandlerWithIO(reader, writer, -1)
}

// TestUserPresenceRequest_Fields tests the UserPresenceRequest struct fields.
func TestUserPresenceRequest_Fields(t *testing.T) {
	t.Parallel()

	req := UserPresenceRequest{
		RPID:      "example.com",
		RPName:    "Example",
		UserName:  "user",
		Operation: "register",
		Timeout:   30 * time.Second,
	}

	if req.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", req.RPID, "example.com")
	}
	if req.RPName != "Example" {
		t.Errorf("RPName = %q, want %q", req.RPName, "Example")
	}
	if req.UserName != "user" {
		t.Errorf("UserName = %q, want %q", req.UserName, "user")
	}
	if req.Operation != "register" {
		t.Errorf("Operation = %q, want %q", req.Operation, "register")
	}
	if req.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want %v", req.Timeout, 30*time.Second)
	}
}

// TestUserVerificationRequest_Fields tests the UserVerificationRequest struct fields.
func TestUserVerificationRequest_Fields(t *testing.T) {
	t.Parallel()

	req := UserVerificationRequest{
		RPID:        "example.com",
		RPName:      "Example",
		UserName:    "user",
		Operation:   "authenticate",
		Timeout:     60 * time.Second,
		PINRequired: true,
	}

	if req.RPID != "example.com" {
		t.Errorf("RPID = %q, want %q", req.RPID, "example.com")
	}
	if req.RPName != "Example" {
		t.Errorf("RPName = %q, want %q", req.RPName, "Example")
	}
	if req.UserName != "user" {
		t.Errorf("UserName = %q, want %q", req.UserName, "user")
	}
	if req.Operation != "authenticate" {
		t.Errorf("Operation = %q, want %q", req.Operation, "authenticate")
	}
	if req.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want %v", req.Timeout, 60*time.Second)
	}
	if !req.PINRequired {
		t.Error("PINRequired = false, want true")
	}
}

// TestUserPresenceResult_Fields tests the UserPresenceResult struct fields.
func TestUserPresenceResult_Fields(t *testing.T) {
	t.Parallel()

	result := UserPresenceResult{Approved: true}
	if !result.Approved {
		t.Error("Approved = false, want true")
	}

	result = UserPresenceResult{Approved: false}
	if result.Approved {
		t.Error("Approved = true, want false")
	}
}

// TestUserVerificationResult_Fields tests the UserVerificationResult struct fields.
func TestUserVerificationResult_Fields(t *testing.T) {
	t.Parallel()

	result := UserVerificationResult{
		Verified: true,
		PIN:      "123456",
	}

	if !result.Verified {
		t.Error("Verified = false, want true")
	}
	if result.PIN != "123456" {
		t.Errorf("PIN = %q, want %q", result.PIN, "123456")
	}
}

// TestErrors_Sentinel tests the sentinel errors are properly defined.
func TestErrors_Sentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrUserPresenceDenied",
			err:  ErrUserPresenceDenied,
			want: "authenticator: user presence denied",
		},
		{
			name: "ErrUserPresenceTimeout",
			err:  ErrUserPresenceTimeout,
			want: "authenticator: user presence timeout",
		},
		{
			name: "ErrUserVerificationDenied",
			err:  ErrUserVerificationDenied,
			want: "authenticator: user verification denied",
		},
		{
			name: "ErrTerminalUnavailable",
			err:  ErrTerminalUnavailable,
			want: "authenticator: terminal unavailable",
		},
		{
			name: "ErrInvalidPIN",
			err:  ErrInvalidPIN,
			want: "authenticator: invalid PIN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.err == nil {
				t.Error("error is nil")
				return
			}

			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDefaultUserPresenceTimeout tests the default timeout constant.
func TestDefaultUserPresenceTimeout(t *testing.T) {
	t.Parallel()

	if DefaultUserPresenceTimeout != 30*time.Second {
		t.Errorf("DefaultUserPresenceTimeout = %v, want %v",
			DefaultUserPresenceTimeout, 30*time.Second)
	}
}

// blockingReader is a reader that blocks forever until the context is cancelled.
// Used for testing timeout and cancellation behavior.
type blockingReader struct{}

func (r *blockingReader) Read(p []byte) (n int, err error) {
	// Block forever
	select {}
}

// errorReader is a reader that always returns an error.
// Used for testing error handling behavior.
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
