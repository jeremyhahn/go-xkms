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

package password

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func TestNewPassword(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid password",
			input:   []byte("secure-password-123"),
			wantErr: false,
		},
		{
			name:    "empty password",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "nil password",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "password with special characters",
			input:   []byte("p@$$w0rd!#%&*()"),
			wantErr: false,
		},
		{
			name:    "unicode password",
			input:   []byte("пароль密码🔐"),
			wantErr: false,
		},
		{
			name:    "single character password",
			input:   []byte("x"),
			wantErr: false,
		},
		{
			name:    "binary password with null and non-utf8 bytes",
			input:   []byte{'p', 0x00, 0x01, 0xFF},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := NewPassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pwd == nil {
					t.Error("NewPassword() returned nil password without error")
					return
				}
				// Verify password is correctly stored
				bytes := pwd.Bytes()
				if bytes == nil {
					t.Error("Bytes() returned nil")
					return
				}
				if string(bytes) != string(tt.input) {
					t.Errorf("Bytes() = %v, want %v", string(bytes), string(tt.input))
				}
				// Test that returned bytes are a copy
				if len(bytes) > 0 {
					bytes[0] = 'X'
					bytes2 := pwd.Bytes()
					if bytes2[0] == 'X' {
						t.Error("Bytes() did not return a copy, original was modified")
					}
				}
			}
		})
	}
}

func TestNewPasswordFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid string password",
			input:   "my-secure-password",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "password with whitespace",
			input:   "  spaced password  ",
			wantErr: false,
		},
		{
			name:    "password with newlines",
			input:   "multi\nline\npassword",
			wantErr: false,
		},
		{
			name:    "password with tabs",
			input:   "tab\tseparated\tpassword",
			wantErr: false,
		},
		{
			name:    "long password",
			input:   "this-is-a-very-long-password-that-exceeds-normal-length-expectations-for-testing-purposes",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := NewPasswordFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPasswordFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pwd == nil {
					t.Error("NewPasswordFromString() returned nil password without error")
					return
				}
				str, err := withString(pwd)
				if err != nil {
					t.Errorf("WithBytes() error = %v", err)
					return
				}
				if str != tt.input {
					t.Errorf("WithBytes() = %v, want %v", str, tt.input)
				}
			}
		})
	}
}

func TestClearPassword_Clear(t *testing.T) {
	t.Run("clear is idempotent", func(t *testing.T) {
		pwd, err := NewPasswordFromString("test-password")
		if err != nil {
			t.Fatalf("NewPasswordFromString() error = %v", err)
		}

		// Clear multiple times should not panic
		pwd.Clear()
		pwd.Clear()
		pwd.Clear()

		// Verify still returns error
		_, err = withString(pwd)
		if err == nil {
			t.Error("WithBytes() after multiple Clear calls should return error")
		}
	})
}

func TestClearPassword_IsolationAndSecurity(t *testing.T) {
	t.Run("external modification does not affect password", func(t *testing.T) {
		original := []byte("original-password")
		pwd, err := NewPassword(original)
		if err != nil {
			t.Fatalf("NewPassword() error = %v", err)
		}

		// Modify the original slice
		original[0] = 'X'

		// Verify password is unaffected
		stored, err := withString(pwd)
		if err != nil {
			t.Errorf("WithBytes() error = %v", err)
		}
		if stored != "original-password" {
			t.Errorf("Password was modified externally: got %v", stored)
		}
	})
}

func TestEqual(t *testing.T) {
	tests := []struct {
		name    string
		pwd1    string
		pwd2    string
		want    bool
		wantErr bool
	}{
		{
			name:    "equal passwords",
			pwd1:    "same-password",
			pwd2:    "same-password",
			want:    true,
			wantErr: false,
		},
		{
			name:    "different passwords",
			pwd1:    "password1",
			pwd2:    "password2",
			want:    false,
			wantErr: false,
		},
		{
			name:    "different lengths",
			pwd1:    "short",
			pwd2:    "much-longer-password",
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, err := NewPasswordFromString(tt.pwd1)
			if err != nil {
				t.Fatalf("NewPasswordFromString(pwd1) error = %v", err)
			}
			p2, err := NewPasswordFromString(tt.pwd2)
			if err != nil {
				t.Fatalf("NewPasswordFromString(pwd2) error = %v", err)
			}

			got, err := Equal(p1, p2)
			if (err != nil) != tt.wantErr {
				t.Errorf("Equal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("equal returns error for cleared password", func(t *testing.T) {
		p1, _ := NewPasswordFromString("password1")
		p2, _ := NewPasswordFromString("password2")

		p1.Clear()

		_, err := Equal(p1, p2)
		if err == nil {
			t.Error("Equal() should return error when first password is cleared")
		}

		p1, _ = NewPasswordFromString("password1")
		p2.Clear()

		_, err = Equal(p1, p2)
		if err == nil {
			t.Error("Equal() should return error when second password is cleared")
		}
	})
}

func BenchmarkNewPassword(b *testing.B) {
	password := []byte("benchmark-password-123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewPassword(password)
	}
}

func BenchmarkClearPassword_Bytes(b *testing.B) {
	password := []byte("benchmark-password-123")
	pwd, _ := NewPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pwd.Bytes()
	}
}

func BenchmarkClearPassword_String(b *testing.B) {
	password := []byte("benchmark-password-123")
	pwd, _ := NewPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = withString(pwd)
	}
}

func BenchmarkClearPassword_Clear(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pwd, _ := NewPassword([]byte("benchmark-password-123"))
		b.StartTimer()
		pwd.Clear()
	}
}

func BenchmarkEqual(b *testing.B) {
	pwd1, _ := NewPasswordFromString("password1")
	pwd2, _ := NewPasswordFromString("password1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Equal(pwd1, pwd2)
	}
}

// withString reads a password through WithBytes, the only accessor that
// reports why a password is unreadable.
func withString(p types.Password) (string, error) {
	var s string
	err := p.WithBytes(func(b []byte) error {
		s = string(b)
		return nil
	})
	return s, err
}

func TestClearPassword_StringNeverReturnsTheSecret(t *testing.T) {
	pwd, err := NewPasswordFromString("hunter2")
	if err != nil {
		t.Fatalf("NewPasswordFromString() error = %v", err)
	}
	defer pwd.Clear()

	if got := pwd.String(); got != types.PasswordRedacted {
		t.Errorf("String() = %q, want %q", got, types.PasswordRedacted)
	}
	if got := fmt.Sprintf("%v|%s|%+v", pwd, pwd, pwd); strings.Contains(got, "hunter2") {
		t.Errorf("formatting leaked the password: %q", got)
	}
}

func TestClearPassword_WithBytesAfterClearFailsClosed(t *testing.T) {
	pwd, err := NewPasswordFromString("hunter2")
	if err != nil {
		t.Fatalf("NewPasswordFromString() error = %v", err)
	}
	pwd.Clear()

	err = pwd.WithBytes(func([]byte) error {
		t.Error("callback must not run after Clear")
		return nil
	})
	if !errors.Is(err, ErrPasswordZeroed) {
		t.Errorf("WithBytes() after Clear = %v, want ErrPasswordZeroed", err)
	}
	if got := pwd.Bytes(); got != nil {
		t.Errorf("Bytes() after Clear = %v, want nil", got)
	}
}

// TestClearPassword_DestroyedBufferFailsClosed pins the refusals of a
// password whose locked buffer was destroyed underneath it without Clear,
// as a shutdown secure.WipeAll does: no call may lend or return the secret.
func TestClearPassword_DestroyedBufferFailsClosed(t *testing.T) {
	pwd, err := NewPasswordFromString("hunter2")
	if err != nil {
		t.Fatalf("NewPasswordFromString() error = %v", err)
	}
	pwd.(*ClearPassword).buf.Destroy()

	if got := pwd.Bytes(); got != nil {
		t.Errorf("Bytes() on a destroyed buffer = %v, want nil", got)
	}

	err = pwd.WithBytes(func([]byte) error {
		t.Error("callback must not run on a destroyed buffer")
		return nil
	})
	var nilBuf *secure.NilBufferError
	if !errors.As(err, &nilBuf) {
		t.Errorf("WithBytes() on a destroyed buffer = %v, want *secure.NilBufferError", err)
	}

	same, err := NewPasswordFromString("hunter2")
	if err != nil {
		t.Fatalf("NewPasswordFromString() error = %v", err)
	}
	defer same.Clear()
	equal, err := Equal(pwd, same)
	if equal || !errors.Is(err, ErrPasswordZeroed) {
		t.Errorf("Equal() with a destroyed buffer = (%v, %v), want (false, ErrPasswordZeroed)", equal, err)
	}
}
