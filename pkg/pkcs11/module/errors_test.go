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

package module

import (
	"errors"
	"testing"
)

// TestCKRV_String tests the CK_RV String method for known, vendor-defined, and unknown codes.
func TestCKRV_String(t *testing.T) {
	tests := []struct {
		name     string
		rv       CK_RV
		expected string
	}{
		{
			name:     "CKR_OK returns correct string",
			rv:       CKR_OK,
			expected: "CKR_OK",
		},
		{
			name:     "CKR_GENERAL_ERROR returns correct string",
			rv:       CKR_GENERAL_ERROR,
			expected: "CKR_GENERAL_ERROR",
		},
		{
			name:     "CKR_PIN_INCORRECT returns correct string",
			rv:       CKR_PIN_INCORRECT,
			expected: "CKR_PIN_INCORRECT",
		},
		{
			name:     "CKR_SESSION_HANDLE_INVALID returns correct string",
			rv:       CKR_SESSION_HANDLE_INVALID,
			expected: "CKR_SESSION_HANDLE_INVALID",
		},
		{
			name:     "CKR_KEY_HANDLE_INVALID returns correct string",
			rv:       CKR_KEY_HANDLE_INVALID,
			expected: "CKR_KEY_HANDLE_INVALID",
		},
		{
			name:     "CKR_DEVICE_ERROR returns correct string",
			rv:       CKR_DEVICE_ERROR,
			expected: "CKR_DEVICE_ERROR",
		},
		{
			name:     "CKR_MECHANISM_INVALID returns correct string",
			rv:       CKR_MECHANISM_INVALID,
			expected: "CKR_MECHANISM_INVALID",
		},
		{
			name:     "CKR_VENDOR_DEFINED returns correct string",
			rv:       CKR_VENDOR_DEFINED,
			expected: "CKR_VENDOR_DEFINED",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.rv.String()
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestCKRV_String_VendorDefinedOffset tests vendor-defined codes with offset.
func TestCKRV_String_VendorDefinedOffset(t *testing.T) {
	tests := []struct {
		name     string
		rv       CK_RV
		contains string
	}{
		{
			name:     "vendor defined with offset 1",
			rv:       CKR_VENDOR_DEFINED + 1,
			contains: "CKR_VENDOR_DEFINED+0x00000001",
		},
		{
			name:     "vendor defined with offset 0x100",
			rv:       CKR_VENDOR_DEFINED + 0x100,
			contains: "CKR_VENDOR_DEFINED+0x00000100",
		},
		{
			name:     "vendor defined with large offset",
			rv:       CKR_VENDOR_DEFINED + 0x7FFFFFFF,
			contains: "CKR_VENDOR_DEFINED+0x7FFFFFFF",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.rv.String()
			if result != tc.contains {
				t.Errorf("expected %q, got %q", tc.contains, result)
			}
		})
	}
}

// TestCKRV_String_Unknown tests unknown (non-vendor-defined) codes.
func TestCKRV_String_Unknown(t *testing.T) {
	tests := []struct {
		name     string
		rv       CK_RV
		contains string
	}{
		{
			name:     "unknown code 0x00000004",
			rv:       0x00000004,
			contains: "CKR_UNKNOWN(0x00000004)",
		},
		{
			name:     "unknown code in gap between defined codes",
			rv:       0x000000FF,
			contains: "CKR_UNKNOWN(0x000000FF)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.rv.String()
			if result != tc.contains {
				t.Errorf("expected %q, got %q", tc.contains, result)
			}
		})
	}
}

// TestPKCS11Error_Error tests the Error method for various PKCS11Error configurations.
func TestPKCS11Error_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *PKCS11Error
		expected string
	}{
		{
			name:     "code only",
			err:      &PKCS11Error{Code: CKR_GENERAL_ERROR},
			expected: "pkcs11: CKR_GENERAL_ERROR",
		},
		{
			name:     "code with message",
			err:      &PKCS11Error{Code: CKR_GENERAL_ERROR, Message: "operation failed"},
			expected: "pkcs11: CKR_GENERAL_ERROR: operation failed",
		},
		{
			name:     "code with cause",
			err:      &PKCS11Error{Code: CKR_GENERAL_ERROR, Cause: errors.New("underlying error")},
			expected: "pkcs11: CKR_GENERAL_ERROR: underlying error",
		},
		{
			name:     "code with message and cause",
			err:      &PKCS11Error{Code: CKR_GENERAL_ERROR, Message: "operation failed", Cause: errors.New("underlying error")},
			expected: "pkcs11: CKR_GENERAL_ERROR: operation failed: underlying error",
		},
		{
			name:     "PIN incorrect code",
			err:      &PKCS11Error{Code: CKR_PIN_INCORRECT},
			expected: "pkcs11: CKR_PIN_INCORRECT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.err.Error()
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestPKCS11Error_Unwrap tests the Unwrap method.
func TestPKCS11Error_Unwrap(t *testing.T) {
	t.Run("returns nil when no cause", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		if err.Unwrap() != nil {
			t.Error("expected nil cause")
		}
	})

	t.Run("returns cause when present", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR, Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected cause to be returned")
		}
	})

	t.Run("errors.Unwrap extracts cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR, Cause: cause}
		unwrapped := errors.Unwrap(err)
		if unwrapped != cause {
			t.Error("errors.Unwrap should extract cause")
		}
	})
}

// TestPKCS11Error_Is tests the Is method for error comparison.
func TestPKCS11Error_Is(t *testing.T) {
	t.Run("matches same PKCS11Error code", func(t *testing.T) {
		err1 := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		err2 := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		if !err1.Is(err2) {
			t.Error("expected errors with same code to match")
		}
	})

	t.Run("does not match different PKCS11Error code", func(t *testing.T) {
		err1 := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		err2 := &PKCS11Error{Code: CKR_FUNCTION_FAILED}
		if err1.Is(err2) {
			t.Error("expected errors with different codes not to match")
		}
	})

	t.Run("matches sentinel error for known code", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		if !err.Is(ErrGeneralError) {
			t.Error("expected PKCS11Error to match sentinel error")
		}
	})

	t.Run("matches sentinel error for PIN incorrect", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_PIN_INCORRECT}
		if !err.Is(ErrPINIncorrect) {
			t.Error("expected PKCS11Error to match ErrPINIncorrect sentinel")
		}
	})

	t.Run("does not match different sentinel error", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		if err.Is(ErrPINIncorrect) {
			t.Error("expected PKCS11Error not to match different sentinel")
		}
	})

	t.Run("does not match unrelated error", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		unrelated := errors.New("some other error")
		if err.Is(unrelated) {
			t.Error("expected PKCS11Error not to match unrelated error")
		}
	})

	t.Run("unknown code does not match sentinel", func(t *testing.T) {
		// Use an unknown code that has no sentinel mapping
		err := &PKCS11Error{Code: 0x00000004}
		if err.Is(ErrGeneralError) {
			t.Error("expected unknown code not to match sentinel")
		}
	})
}

// TestNewPKCS11ErrorWithCause tests the NewPKCS11ErrorWithCause constructor.
func TestNewPKCS11ErrorWithCause(t *testing.T) {
	t.Run("creates error with code and cause", func(t *testing.T) {
		cause := errors.New("original error")
		err := NewPKCS11ErrorWithCause(CKR_GENERAL_ERROR, cause)

		if err.Code != CKR_GENERAL_ERROR {
			t.Errorf("expected code CKR_GENERAL_ERROR, got %v", err.Code)
		}
		if err.Cause != cause {
			t.Error("expected cause to be set")
		}
		if err.Message != "" {
			t.Error("expected message to be empty")
		}
	})

	t.Run("creates error with nil cause", func(t *testing.T) {
		err := NewPKCS11ErrorWithCause(CKR_FUNCTION_FAILED, nil)

		if err.Code != CKR_FUNCTION_FAILED {
			t.Errorf("expected code CKR_FUNCTION_FAILED, got %v", err.Code)
		}
		if err.Cause != nil {
			t.Error("expected cause to be nil")
		}
	})

	t.Run("error string includes cause", func(t *testing.T) {
		cause := errors.New("underlying failure")
		err := NewPKCS11ErrorWithCause(CKR_DEVICE_ERROR, cause)

		expected := "pkcs11: CKR_DEVICE_ERROR: underlying failure"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

// TestToError tests the ToError function.
func TestToError(t *testing.T) {
	t.Run("returns nil for CKR_OK", func(t *testing.T) {
		err := ToError(CKR_OK)
		if err != nil {
			t.Errorf("expected nil for CKR_OK, got %v", err)
		}
	})

	t.Run("returns PKCS11Error for CKR_GENERAL_ERROR", func(t *testing.T) {
		err := ToError(CKR_GENERAL_ERROR)
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Code != CKR_GENERAL_ERROR {
			t.Errorf("expected code CKR_GENERAL_ERROR, got %v", pkcs11Err.Code)
		}
	})

	t.Run("returns PKCS11Error for CKR_PIN_INCORRECT", func(t *testing.T) {
		err := ToError(CKR_PIN_INCORRECT)
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Code != CKR_PIN_INCORRECT {
			t.Errorf("expected code CKR_PIN_INCORRECT, got %v", pkcs11Err.Code)
		}
	})

	t.Run("returns PKCS11Error for unknown code", func(t *testing.T) {
		unknownCode := CK_RV(0x00000004)
		err := ToError(unknownCode)
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Code != unknownCode {
			t.Errorf("expected code 0x00000004, got %v", pkcs11Err.Code)
		}
	})

	t.Run("returns PKCS11Error for vendor-defined code", func(t *testing.T) {
		vendorCode := CKR_VENDOR_DEFINED + 0x100
		err := ToError(vendorCode)
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Code != vendorCode {
			t.Errorf("expected vendor code, got %v", pkcs11Err.Code)
		}
	})
}

// TestToErrorWithMessage tests the ToErrorWithMessage function.
func TestToErrorWithMessage(t *testing.T) {
	t.Run("returns nil for CKR_OK", func(t *testing.T) {
		err := ToErrorWithMessage(CKR_OK, "some message")
		if err != nil {
			t.Errorf("expected nil for CKR_OK, got %v", err)
		}
	})

	t.Run("returns PKCS11Error with message for error code", func(t *testing.T) {
		err := ToErrorWithMessage(CKR_GENERAL_ERROR, "operation failed")
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Code != CKR_GENERAL_ERROR {
			t.Errorf("expected code CKR_GENERAL_ERROR, got %v", pkcs11Err.Code)
		}
		if pkcs11Err.Message != "operation failed" {
			t.Errorf("expected message 'operation failed', got %q", pkcs11Err.Message)
		}
	})

	t.Run("returns correct error string", func(t *testing.T) {
		err := ToErrorWithMessage(CKR_PIN_INCORRECT, "login failed")
		expected := "pkcs11: CKR_PIN_INCORRECT: login failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("handles empty message", func(t *testing.T) {
		err := ToErrorWithMessage(CKR_DEVICE_ERROR, "")
		if err == nil {
			t.Fatal("expected non-nil error")
		}

		var pkcs11Err *PKCS11Error
		if !errors.As(err, &pkcs11Err) {
			t.Fatal("expected PKCS11Error type")
		}
		if pkcs11Err.Message != "" {
			t.Errorf("expected empty message, got %q", pkcs11Err.Message)
		}
	})
}

// TestFromError tests the FromError function.
func TestFromError(t *testing.T) {
	t.Run("returns CKR_OK for nil error", func(t *testing.T) {
		rv := FromError(nil)
		if rv != CKR_OK {
			t.Errorf("expected CKR_OK, got %v", rv)
		}
	})

	t.Run("returns code from PKCS11Error", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_PIN_INCORRECT}
		rv := FromError(err)
		if rv != CKR_PIN_INCORRECT {
			t.Errorf("expected CKR_PIN_INCORRECT, got %v", rv)
		}
	})

	t.Run("returns code from wrapped PKCS11Error", func(t *testing.T) {
		innerErr := &PKCS11Error{Code: CKR_DEVICE_ERROR}
		wrappedErr := errors.Join(errors.New("wrapper"), innerErr)
		rv := FromError(wrappedErr)
		if rv != CKR_DEVICE_ERROR {
			t.Errorf("expected CKR_DEVICE_ERROR, got %v", rv)
		}
	})

	t.Run("returns code from sentinel error", func(t *testing.T) {
		rv := FromError(ErrGeneralError)
		if rv != CKR_GENERAL_ERROR {
			t.Errorf("expected CKR_GENERAL_ERROR, got %v", rv)
		}
	})

	t.Run("returns code from sentinel PIN error", func(t *testing.T) {
		rv := FromError(ErrPINIncorrect)
		if rv != CKR_PIN_INCORRECT {
			t.Errorf("expected CKR_PIN_INCORRECT, got %v", rv)
		}
	})

	t.Run("returns CKR_GENERAL_ERROR for unknown error", func(t *testing.T) {
		unknownErr := errors.New("unknown error")
		rv := FromError(unknownErr)
		if rv != CKR_GENERAL_ERROR {
			t.Errorf("expected CKR_GENERAL_ERROR, got %v", rv)
		}
	})

	t.Run("handles PKCS11Error with cause", func(t *testing.T) {
		cause := errors.New("cause")
		err := NewPKCS11ErrorWithCause(CKR_SESSION_CLOSED, cause)
		rv := FromError(err)
		if rv != CKR_SESSION_CLOSED {
			t.Errorf("expected CKR_SESSION_CLOSED, got %v", rv)
		}
	})
}

// TestIsPKCS11Error tests the IsPKCS11Error function.
func TestIsPKCS11Error(t *testing.T) {
	t.Run("returns true and code for PKCS11Error", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		rv, ok := IsPKCS11Error(err)
		if !ok {
			t.Error("expected ok to be true")
		}
		if rv != CKR_GENERAL_ERROR {
			t.Errorf("expected CKR_GENERAL_ERROR, got %v", rv)
		}
	})

	t.Run("returns true and code for wrapped PKCS11Error", func(t *testing.T) {
		innerErr := &PKCS11Error{Code: CKR_PIN_LOCKED}
		wrappedErr := errors.Join(errors.New("wrapper"), innerErr)
		rv, ok := IsPKCS11Error(wrappedErr)
		if !ok {
			t.Error("expected ok to be true for wrapped error")
		}
		if rv != CKR_PIN_LOCKED {
			t.Errorf("expected CKR_PIN_LOCKED, got %v", rv)
		}
	})

	t.Run("returns false for non-PKCS11Error", func(t *testing.T) {
		err := errors.New("regular error")
		rv, ok := IsPKCS11Error(err)
		if ok {
			t.Error("expected ok to be false")
		}
		if rv != CKR_OK {
			t.Errorf("expected CKR_OK, got %v", rv)
		}
	})

	t.Run("returns false for nil error", func(t *testing.T) {
		rv, ok := IsPKCS11Error(nil)
		if ok {
			t.Error("expected ok to be false for nil")
		}
		if rv != CKR_OK {
			t.Errorf("expected CKR_OK, got %v", rv)
		}
	})

	t.Run("returns false for sentinel error", func(t *testing.T) {
		rv, ok := IsPKCS11Error(ErrGeneralError)
		if ok {
			t.Error("expected ok to be false for sentinel")
		}
		if rv != CKR_OK {
			t.Errorf("expected CKR_OK, got %v", rv)
		}
	})
}

// TestIsRetryable tests the IsRetryable function.
func TestIsRetryable(t *testing.T) {
	retryableCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_DEVICE_ERROR", CKR_DEVICE_ERROR},
		{"CKR_DEVICE_MEMORY", CKR_DEVICE_MEMORY},
		{"CKR_HOST_MEMORY", CKR_HOST_MEMORY},
		{"CKR_SESSION_COUNT", CKR_SESSION_COUNT},
		{"CKR_TOKEN_RESOURCE_EXCEEDED", CKR_TOKEN_RESOURCE_EXCEEDED},
	}

	for _, tc := range retryableCodes {
		t.Run(tc.name+" is retryable", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsRetryable(err) {
				t.Errorf("expected %s to be retryable", tc.name)
			}
		})
	}

	nonRetryableCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
		{"CKR_MECHANISM_INVALID", CKR_MECHANISM_INVALID},
		{"CKR_OK", CKR_OK},
	}

	for _, tc := range nonRetryableCodes {
		t.Run(tc.name+" is not retryable", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsRetryable(err) {
				t.Errorf("expected %s to not be retryable", tc.name)
			}
		})
	}

	t.Run("nil error is not retryable", func(t *testing.T) {
		if IsRetryable(nil) {
			t.Error("expected nil error to not be retryable")
		}
	})

	t.Run("unknown error is not retryable", func(t *testing.T) {
		unknownErr := errors.New("unknown error")
		if IsRetryable(unknownErr) {
			t.Error("expected unknown error to not be retryable")
		}
	})
}

// TestIsAuthenticationError tests the IsAuthenticationError function.
func TestIsAuthenticationError(t *testing.T) {
	authCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_PIN_INVALID", CKR_PIN_INVALID},
		{"CKR_PIN_LEN_RANGE", CKR_PIN_LEN_RANGE},
		{"CKR_PIN_EXPIRED", CKR_PIN_EXPIRED},
		{"CKR_PIN_LOCKED", CKR_PIN_LOCKED},
		{"CKR_PIN_TOO_WEAK", CKR_PIN_TOO_WEAK},
		{"CKR_USER_NOT_LOGGED_IN", CKR_USER_NOT_LOGGED_IN},
		{"CKR_USER_ALREADY_LOGGED_IN", CKR_USER_ALREADY_LOGGED_IN},
		{"CKR_USER_TYPE_INVALID", CKR_USER_TYPE_INVALID},
		{"CKR_USER_ANOTHER_ALREADY_LOGGED_IN", CKR_USER_ANOTHER_ALREADY_LOGGED_IN},
		{"CKR_USER_PIN_NOT_INITIALIZED", CKR_USER_PIN_NOT_INITIALIZED},
	}

	for _, tc := range authCodes {
		t.Run(tc.name+" is authentication error", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsAuthenticationError(err) {
				t.Errorf("expected %s to be authentication error", tc.name)
			}
		})
	}

	nonAuthCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_DEVICE_ERROR", CKR_DEVICE_ERROR},
		{"CKR_SESSION_CLOSED", CKR_SESSION_CLOSED},
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
	}

	for _, tc := range nonAuthCodes {
		t.Run(tc.name+" is not authentication error", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsAuthenticationError(err) {
				t.Errorf("expected %s to not be authentication error", tc.name)
			}
		})
	}

	t.Run("nil error is not authentication error", func(t *testing.T) {
		if IsAuthenticationError(nil) {
			t.Error("expected nil error to not be authentication error")
		}
	})
}

// TestIsSessionError tests the IsSessionError function.
func TestIsSessionError(t *testing.T) {
	sessionCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_SESSION_CLOSED", CKR_SESSION_CLOSED},
		{"CKR_SESSION_COUNT", CKR_SESSION_COUNT},
		{"CKR_SESSION_HANDLE_INVALID", CKR_SESSION_HANDLE_INVALID},
		{"CKR_SESSION_PARALLEL_NOT_SUPPORTED", CKR_SESSION_PARALLEL_NOT_SUPPORTED},
		{"CKR_SESSION_READ_ONLY", CKR_SESSION_READ_ONLY},
		{"CKR_SESSION_EXISTS", CKR_SESSION_EXISTS},
		{"CKR_SESSION_READ_ONLY_EXISTS", CKR_SESSION_READ_ONLY_EXISTS},
		{"CKR_SESSION_READ_WRITE_SO_EXISTS", CKR_SESSION_READ_WRITE_SO_EXISTS},
	}

	for _, tc := range sessionCodes {
		t.Run(tc.name+" is session error", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsSessionError(err) {
				t.Errorf("expected %s to be session error", tc.name)
			}
		})
	}

	nonSessionCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_DEVICE_ERROR", CKR_DEVICE_ERROR},
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
	}

	for _, tc := range nonSessionCodes {
		t.Run(tc.name+" is not session error", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsSessionError(err) {
				t.Errorf("expected %s to not be session error", tc.name)
			}
		})
	}

	t.Run("nil error is not session error", func(t *testing.T) {
		if IsSessionError(nil) {
			t.Error("expected nil error to not be session error")
		}
	})
}

// TestIsKeyError tests the IsKeyError function.
func TestIsKeyError(t *testing.T) {
	keyCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
		{"CKR_KEY_SIZE_RANGE", CKR_KEY_SIZE_RANGE},
		{"CKR_KEY_TYPE_INCONSISTENT", CKR_KEY_TYPE_INCONSISTENT},
		{"CKR_KEY_NOT_NEEDED", CKR_KEY_NOT_NEEDED},
		{"CKR_KEY_CHANGED", CKR_KEY_CHANGED},
		{"CKR_KEY_NEEDED", CKR_KEY_NEEDED},
		{"CKR_KEY_INDIGESTIBLE", CKR_KEY_INDIGESTIBLE},
		{"CKR_KEY_FUNCTION_NOT_PERMITTED", CKR_KEY_FUNCTION_NOT_PERMITTED},
		{"CKR_KEY_NOT_WRAPPABLE", CKR_KEY_NOT_WRAPPABLE},
		{"CKR_KEY_UNEXTRACTABLE", CKR_KEY_UNEXTRACTABLE},
		{"CKR_KEY_EXHAUSTED", CKR_KEY_EXHAUSTED},
	}

	for _, tc := range keyCodes {
		t.Run(tc.name+" is key error", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsKeyError(err) {
				t.Errorf("expected %s to be key error", tc.name)
			}
		})
	}

	nonKeyCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_SESSION_CLOSED", CKR_SESSION_CLOSED},
		{"CKR_DEVICE_ERROR", CKR_DEVICE_ERROR},
	}

	for _, tc := range nonKeyCodes {
		t.Run(tc.name+" is not key error", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsKeyError(err) {
				t.Errorf("expected %s to not be key error", tc.name)
			}
		})
	}

	t.Run("nil error is not key error", func(t *testing.T) {
		if IsKeyError(nil) {
			t.Error("expected nil error to not be key error")
		}
	})
}

// TestIsCryptographicError tests the IsCryptographicError function.
func TestIsCryptographicError(t *testing.T) {
	cryptoCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_MECHANISM_INVALID", CKR_MECHANISM_INVALID},
		{"CKR_MECHANISM_PARAM_INVALID", CKR_MECHANISM_PARAM_INVALID},
		{"CKR_SIGNATURE_INVALID", CKR_SIGNATURE_INVALID},
		{"CKR_SIGNATURE_LEN_RANGE", CKR_SIGNATURE_LEN_RANGE},
		{"CKR_ENCRYPTED_DATA_INVALID", CKR_ENCRYPTED_DATA_INVALID},
		{"CKR_ENCRYPTED_DATA_LEN_RANGE", CKR_ENCRYPTED_DATA_LEN_RANGE},
		{"CKR_AEAD_DECRYPT_FAILED", CKR_AEAD_DECRYPT_FAILED},
		{"CKR_DATA_INVALID", CKR_DATA_INVALID},
		{"CKR_DATA_LEN_RANGE", CKR_DATA_LEN_RANGE},
		{"CKR_WRAPPED_KEY_INVALID", CKR_WRAPPED_KEY_INVALID},
		{"CKR_WRAPPED_KEY_LEN_RANGE", CKR_WRAPPED_KEY_LEN_RANGE},
	}

	for _, tc := range cryptoCodes {
		t.Run(tc.name+" is cryptographic error", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsCryptographicError(err) {
				t.Errorf("expected %s to be cryptographic error", tc.name)
			}
		})
	}

	nonCryptoCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_SESSION_CLOSED", CKR_SESSION_CLOSED},
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
	}

	for _, tc := range nonCryptoCodes {
		t.Run(tc.name+" is not cryptographic error", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsCryptographicError(err) {
				t.Errorf("expected %s to not be cryptographic error", tc.name)
			}
		})
	}

	t.Run("nil error is not cryptographic error", func(t *testing.T) {
		if IsCryptographicError(nil) {
			t.Error("expected nil error to not be cryptographic error")
		}
	})
}

// TestIsDeviceError tests the IsDeviceError function.
func TestIsDeviceError(t *testing.T) {
	deviceCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_DEVICE_ERROR", CKR_DEVICE_ERROR},
		{"CKR_DEVICE_MEMORY", CKR_DEVICE_MEMORY},
		{"CKR_DEVICE_REMOVED", CKR_DEVICE_REMOVED},
		{"CKR_TOKEN_NOT_PRESENT", CKR_TOKEN_NOT_PRESENT},
		{"CKR_TOKEN_NOT_RECOGNIZED", CKR_TOKEN_NOT_RECOGNIZED},
		{"CKR_TOKEN_WRITE_PROTECTED", CKR_TOKEN_WRITE_PROTECTED},
		{"CKR_TOKEN_RESOURCE_EXCEEDED", CKR_TOKEN_RESOURCE_EXCEEDED},
		{"CKR_SLOT_ID_INVALID", CKR_SLOT_ID_INVALID},
	}

	for _, tc := range deviceCodes {
		t.Run(tc.name+" is device error", func(t *testing.T) {
			err := ToError(tc.rv)
			if !IsDeviceError(err) {
				t.Errorf("expected %s to be device error", tc.name)
			}
		})
	}

	nonDeviceCodes := []struct {
		name string
		rv   CK_RV
	}{
		{"CKR_GENERAL_ERROR", CKR_GENERAL_ERROR},
		{"CKR_PIN_INCORRECT", CKR_PIN_INCORRECT},
		{"CKR_SESSION_CLOSED", CKR_SESSION_CLOSED},
		{"CKR_KEY_HANDLE_INVALID", CKR_KEY_HANDLE_INVALID},
	}

	for _, tc := range nonDeviceCodes {
		t.Run(tc.name+" is not device error", func(t *testing.T) {
			err := ToError(tc.rv)
			if IsDeviceError(err) {
				t.Errorf("expected %s to not be device error", tc.name)
			}
		})
	}

	t.Run("nil error is not device error", func(t *testing.T) {
		if IsDeviceError(nil) {
			t.Error("expected nil error to not be device error")
		}
	})
}

// TestErrorsIsIntegration tests that errors.Is works correctly with PKCS11Error.
func TestErrorsIsIntegration(t *testing.T) {
	t.Run("errors.Is matches PKCS11Error with sentinel", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_GENERAL_ERROR}
		if !errors.Is(err, ErrGeneralError) {
			t.Error("expected errors.Is to match sentinel error")
		}
	})

	t.Run("errors.Is matches wrapped PKCS11Error", func(t *testing.T) {
		inner := &PKCS11Error{Code: CKR_PIN_INCORRECT}
		wrapped := errors.Join(errors.New("context"), inner)
		if !errors.Is(wrapped, ErrPINIncorrect) {
			t.Error("expected errors.Is to match wrapped PKCS11Error")
		}
	})
}

// TestErrorsAsIntegration tests that errors.As works correctly with PKCS11Error.
func TestErrorsAsIntegration(t *testing.T) {
	t.Run("errors.As extracts PKCS11Error", func(t *testing.T) {
		err := &PKCS11Error{Code: CKR_SESSION_CLOSED, Message: "session timed out"}
		var target *PKCS11Error
		if !errors.As(err, &target) {
			t.Fatal("expected errors.As to succeed")
		}
		if target.Code != CKR_SESSION_CLOSED {
			t.Errorf("expected CKR_SESSION_CLOSED, got %v", target.Code)
		}
		if target.Message != "session timed out" {
			t.Errorf("expected 'session timed out', got %q", target.Message)
		}
	})

	t.Run("errors.As extracts wrapped PKCS11Error", func(t *testing.T) {
		inner := &PKCS11Error{Code: CKR_KEY_HANDLE_INVALID}
		wrapped := errors.Join(errors.New("context"), inner)
		var target *PKCS11Error
		if !errors.As(wrapped, &target) {
			t.Fatal("expected errors.As to succeed")
		}
		if target.Code != CKR_KEY_HANDLE_INVALID {
			t.Errorf("expected CKR_KEY_HANDLE_INVALID, got %v", target.Code)
		}
	})
}

// TestNewPKCS11Error tests the NewPKCS11Error constructor.
func TestNewPKCS11Error(t *testing.T) {
	t.Run("creates error with code only", func(t *testing.T) {
		err := NewPKCS11Error(CKR_FUNCTION_FAILED)
		if err.Code != CKR_FUNCTION_FAILED {
			t.Errorf("expected code CKR_FUNCTION_FAILED, got %v", err.Code)
		}
		if err.Message != "" {
			t.Error("expected empty message")
		}
		if err.Cause != nil {
			t.Error("expected nil cause")
		}
	})
}

// TestNewPKCS11ErrorWithMessage tests the NewPKCS11ErrorWithMessage constructor.
func TestNewPKCS11ErrorWithMessage(t *testing.T) {
	t.Run("creates error with code and message", func(t *testing.T) {
		err := NewPKCS11ErrorWithMessage(CKR_FUNCTION_FAILED, "operation timed out")
		if err.Code != CKR_FUNCTION_FAILED {
			t.Errorf("expected code CKR_FUNCTION_FAILED, got %v", err.Code)
		}
		if err.Message != "operation timed out" {
			t.Errorf("expected message 'operation timed out', got %q", err.Message)
		}
		if err.Cause != nil {
			t.Error("expected nil cause")
		}
	})
}

// TestNewPKCS11ErrorFull tests the NewPKCS11ErrorFull constructor.
func TestNewPKCS11ErrorFull(t *testing.T) {
	t.Run("creates error with code, message, and cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := NewPKCS11ErrorFull(CKR_DEVICE_ERROR, "device communication failed", cause)
		if err.Code != CKR_DEVICE_ERROR {
			t.Errorf("expected code CKR_DEVICE_ERROR, got %v", err.Code)
		}
		if err.Message != "device communication failed" {
			t.Errorf("expected message 'device communication failed', got %q", err.Message)
		}
		if err.Cause != cause {
			t.Error("expected cause to be set")
		}
	})

	t.Run("error string includes all components", func(t *testing.T) {
		cause := errors.New("timeout")
		err := NewPKCS11ErrorFull(CKR_DEVICE_ERROR, "device communication failed", cause)
		expected := "pkcs11: CKR_DEVICE_ERROR: device communication failed: timeout"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

// TestSentinelErrorMapping tests that all sentinel errors map correctly.
func TestSentinelErrorMapping(t *testing.T) {
	// Test a sample of sentinel error mappings
	mappings := []struct {
		sentinel error
		code     CK_RV
	}{
		{ErrOK, CKR_OK},
		{ErrCancel, CKR_CANCEL},
		{ErrHostMemory, CKR_HOST_MEMORY},
		{ErrSlotIDInvalid, CKR_SLOT_ID_INVALID},
		{ErrGeneralError, CKR_GENERAL_ERROR},
		{ErrPINIncorrect, CKR_PIN_INCORRECT},
		{ErrSessionClosed, CKR_SESSION_CLOSED},
		{ErrKeyHandleInvalid, CKR_KEY_HANDLE_INVALID},
		{ErrDeviceError, CKR_DEVICE_ERROR},
		{ErrMechanismInvalid, CKR_MECHANISM_INVALID},
		{ErrVendorDefined, CKR_VENDOR_DEFINED},
	}

	for _, m := range mappings {
		t.Run(m.sentinel.Error(), func(t *testing.T) {
			// Test FromError returns correct code
			rv := FromError(m.sentinel)
			if rv != m.code {
				t.Errorf("expected %v, got %v", m.code, rv)
			}

			// Test sentinelErrors map contains this mapping
			if sentinel, ok := sentinelErrors[m.code]; ok {
				if sentinel != m.sentinel {
					t.Errorf("sentinel mismatch for code %v", m.code)
				}
			}
		})
	}
}

// TestCKRVAllKnownCodes tests that all defined CK_RV codes have string representations.
func TestCKRVAllKnownCodes(t *testing.T) {
	knownCodes := []CK_RV{
		CKR_OK, CKR_CANCEL, CKR_HOST_MEMORY, CKR_SLOT_ID_INVALID,
		CKR_GENERAL_ERROR, CKR_FUNCTION_FAILED, CKR_ARGUMENTS_BAD,
		CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS, CKR_CANT_LOCK,
		CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_SENSITIVE,
		CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
		CKR_ACTION_PROHIBITED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
		CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
		CKR_AEAD_DECRYPT_FAILED, CKR_FUNCTION_CANCELED,
		CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED,
		CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE,
		CKR_KEY_TYPE_INCONSISTENT, CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED,
		CKR_KEY_NEEDED, CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
		CKR_KEY_NOT_WRAPPABLE, CKR_KEY_UNEXTRACTABLE, CKR_MECHANISM_INVALID,
		CKR_MECHANISM_PARAM_INVALID, CKR_OBJECT_HANDLE_INVALID,
		CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
		CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE,
		CKR_PIN_EXPIRED, CKR_PIN_LOCKED, CKR_SESSION_CLOSED,
		CKR_SESSION_COUNT, CKR_SESSION_HANDLE_INVALID,
		CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_ONLY,
		CKR_SESSION_EXISTS, CKR_SESSION_READ_ONLY_EXISTS,
		CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SIGNATURE_INVALID,
		CKR_SIGNATURE_LEN_RANGE, CKR_TEMPLATE_INCOMPLETE,
		CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_NOT_PRESENT,
		CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED,
		CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_SIZE_RANGE,
		CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR_USER_ALREADY_LOGGED_IN,
		CKR_USER_NOT_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED,
		CKR_USER_TYPE_INVALID, CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		CKR_USER_TOO_MANY_TYPES, CKR_WRAPPED_KEY_INVALID,
		CKR_WRAPPED_KEY_LEN_RANGE, CKR_WRAPPING_KEY_HANDLE_INVALID,
		CKR_WRAPPING_KEY_SIZE_RANGE, CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
		CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_RANDOM_NO_RNG,
		CKR_DOMAIN_PARAMS_INVALID, CKR_CURVE_NOT_SUPPORTED,
		CKR_BUFFER_TOO_SMALL, CKR_SAVED_STATE_INVALID,
		CKR_INFORMATION_SENSITIVE, CKR_STATE_UNSAVEABLE,
		CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CRYPTOKI_ALREADY_INITIALIZED,
		CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED, CKR_NEW_PIN_MODE,
		CKR_NEXT_OTP, CKR_EXCEEDED_MAX_ITERATIONS,
		CKR_FIPS_SELF_TEST_FAILED, CKR_LIBRARY_LOAD_FAILED,
		CKR_PIN_TOO_WEAK, CKR_PUBLIC_KEY_INVALID, CKR_FUNCTION_REJECTED,
		CKR_TOKEN_RESOURCE_EXCEEDED, CKR_OPERATION_CANCEL_FAILED,
		CKR_KEY_EXHAUSTED, CKR_VENDOR_DEFINED,
	}

	for _, code := range knownCodes {
		t.Run(code.String(), func(t *testing.T) {
			str := code.String()
			if str == "" {
				t.Errorf("expected non-empty string for code %v", code)
			}
			// Verify it doesn't return UNKNOWN for known codes
			if code != CKR_VENDOR_DEFINED && code < CKR_VENDOR_DEFINED {
				if len(str) > 10 && str[:10] == "CKR_UNKNOW" {
					t.Errorf("expected known string for code %v, got %s", code, str)
				}
			}
		})
	}
}
