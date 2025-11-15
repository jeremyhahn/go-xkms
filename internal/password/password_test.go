// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package password

import (
	"testing"
	"unicode/utf8"
)

func TestNewClearPassword(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := NewClearPassword(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClearPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pwd == nil {
					t.Error("NewClearPassword() returned nil password without error")
					return
				}
				// Verify password is correctly stored
				bytes, err := pwd.Bytes()
				if err != nil {
					t.Errorf("Bytes() error = %v", err)
					return
				}
				if string(bytes) != string(tt.input) {
					t.Errorf("Bytes() = %v, want %v", string(bytes), string(tt.input))
				}
				// Test that returned bytes are a copy
				if len(bytes) > 0 {
					bytes[0] = 'X'
					bytes2, _ := pwd.Bytes()
					if bytes2[0] == 'X' {
						t.Error("Bytes() did not return a copy, original was modified")
					}
				}
			}
		})
	}
}

func TestNewClearPasswordFromString(t *testing.T) {
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
			pwd, err := NewClearPasswordFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClearPasswordFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pwd == nil {
					t.Error("NewClearPasswordFromString() returned nil password without error")
					return
				}
				str, err := pwd.String()
				if err != nil {
					t.Errorf("String() error = %v", err)
					return
				}
				if str != tt.input {
					t.Errorf("String() = %v, want %v", str, tt.input)
				}
			}
		})
	}
}

func TestClearPassword_String(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "simple password",
			input:   "password123",
			wantErr: false,
		},
		{
			name:    "special characters",
			input:   "p@$$w0rd!",
			wantErr: false,
		},
		{
			name:    "unicode characters",
			input:   "密码🔐",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := NewClearPasswordFromString(tt.input)
			if err != nil {
				t.Fatalf("NewClearPasswordFromString() error = %v", err)
			}
			got, err := pwd.String()
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.input {
				t.Errorf("String() = %v, want %v", got, tt.input)
			}
		})
	}
}

func TestClearPassword_Bytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "simple password",
			input:   []byte("password123"),
			wantErr: false,
		},
		{
			name:    "binary data",
			input:   []byte{0x00, 0x01, 0x02, 0xFF},
			wantErr: false,
		},
		{
			name:    "special characters",
			input:   []byte("p@$$w0rd!#%"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := NewClearPassword(tt.input)
			if err != nil {
				t.Fatalf("NewClearPassword() error = %v", err)
			}
			got, err := pwd.Bytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("Bytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if string(got) != string(tt.input) {
					t.Errorf("Bytes() = %v, want %v", got, tt.input)
				}
			}
		})
	}
}

func TestClearPassword_Zero(t *testing.T) {
	t.Run("password can be zeroed", func(t *testing.T) {
		pwd, err := NewClearPasswordFromString("sensitive-password")
		if err != nil {
			t.Fatalf("NewClearPasswordFromString() error = %v", err)
		}

		// Verify password works before zeroing
		before, err := pwd.String()
		if err != nil {
			t.Errorf("String() before Zero error = %v", err)
		}
		if before != "sensitive-password" {
			t.Errorf("String() before Zero = %v, want %v", before, "sensitive-password")
		}

		// Zero the password
		pwd.Zero()

		// Verify password is zeroed
		after, err := pwd.String()
		if err == nil {
			t.Error("String() after Zero should return error")
		}
		if after != "" {
			t.Errorf("String() after Zero = %v, want empty", after)
		}

		// Verify Bytes also returns error
		bytes, err := pwd.Bytes()
		if err == nil {
			t.Error("Bytes() after Zero should return error")
		}
		if bytes != nil {
			t.Errorf("Bytes() after Zero = %v, want nil", bytes)
		}
	})

	t.Run("zero is idempotent", func(t *testing.T) {
		pwd, err := NewClearPasswordFromString("test-password")
		if err != nil {
			t.Fatalf("NewClearPasswordFromString() error = %v", err)
		}

		// Zero multiple times should not panic
		pwd.Zero()
		pwd.Zero()
		pwd.Zero()

		// Verify still returns error
		_, err = pwd.String()
		if err == nil {
			t.Error("String() after multiple Zero calls should return error")
		}
	})
}

func TestClearPassword_IsolationAndSecurity(t *testing.T) {
	t.Run("external modification does not affect password", func(t *testing.T) {
		original := []byte("original-password")
		pwd, err := NewClearPassword(original)
		if err != nil {
			t.Fatalf("NewClearPassword() error = %v", err)
		}

		// Modify the original slice
		original[0] = 'X'

		// Verify password is unaffected
		stored, err := pwd.String()
		if err != nil {
			t.Errorf("String() error = %v", err)
		}
		if stored != "original-password" {
			t.Errorf("Password was modified externally: got %v", stored)
		}
	})

	t.Run("returned bytes are independent copies", func(t *testing.T) {
		pwd, err := NewClearPasswordFromString("test-password")
		if err != nil {
			t.Fatalf("NewClearPasswordFromString() error = %v", err)
		}

		// Get two copies
		bytes1, err := pwd.Bytes()
		if err != nil {
			t.Fatalf("Bytes() error = %v", err)
		}
		bytes2, err := pwd.Bytes()
		if err != nil {
			t.Fatalf("Bytes() error = %v", err)
		}

		// Modify first copy
		bytes1[0] = 'X'

		// Verify second copy is unaffected
		if bytes2[0] == 'X' {
			t.Error("Modifying one byte slice affected another, not independent copies")
		}

		// Verify original is unaffected
		bytes3, err := pwd.Bytes()
		if err != nil {
			t.Fatalf("Bytes() error = %v", err)
		}
		if bytes3[0] == 'X' {
			t.Error("Original password was modified through returned bytes")
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
			name:    "case sensitive",
			pwd1:    "Password",
			pwd2:    "password",
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
		{
			name:    "special characters equal",
			pwd1:    "p@$$w0rd!",
			pwd2:    "p@$$w0rd!",
			want:    true,
			wantErr: false,
		},
		{
			name:    "unicode equal",
			pwd1:    "密码🔐",
			pwd2:    "密码🔐",
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p1, err := NewClearPasswordFromString(tt.pwd1)
			if err != nil {
				t.Fatalf("NewClearPasswordFromString(pwd1) error = %v", err)
			}
			p2, err := NewClearPasswordFromString(tt.pwd2)
			if err != nil {
				t.Fatalf("NewClearPasswordFromString(pwd2) error = %v", err)
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

	t.Run("equal returns error for zeroed password", func(t *testing.T) {
		p1, _ := NewClearPasswordFromString("password1")
		p2, _ := NewClearPasswordFromString("password2")

		p1.Zero()

		_, err := Equal(p1, p2)
		if err == nil {
			t.Error("Equal() should return error when first password is zeroed")
		}

		p1, _ = NewClearPasswordFromString("password1")
		p2.Zero()

		_, err = Equal(p1, p2)
		if err == nil {
			t.Error("Equal() should return error when second password is zeroed")
		}
	})
}

func TestClearPassword_EdgeCases(t *testing.T) {
	t.Run("password with null bytes", func(t *testing.T) {
		input := []byte{'p', 'a', 's', 's', 0x00, 'w', 'o', 'r', 'd'}
		pwd, err := NewClearPassword(input)
		if err != nil {
			t.Fatalf("NewClearPassword() error = %v", err)
		}

		got, err := pwd.Bytes()
		if err != nil {
			t.Errorf("Bytes() error = %v", err)
		}
		if string(got) != string(input) {
			t.Errorf("Bytes() = %v, want %v", got, input)
		}
	})

	t.Run("password with only special characters", func(t *testing.T) {
		input := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
		pwd, err := NewClearPasswordFromString(input)
		if err != nil {
			t.Fatalf("NewClearPasswordFromString() error = %v", err)
		}

		got, err := pwd.String()
		if err != nil {
			t.Errorf("String() error = %v", err)
		}
		if got != input {
			t.Errorf("String() = %v, want %v", got, input)
		}
	})

	t.Run("password with mixed valid utf8", func(t *testing.T) {
		input := "Hello世界🌍Мир"
		pwd, err := NewClearPasswordFromString(input)
		if err != nil {
			t.Fatalf("NewClearPasswordFromString() error = %v", err)
		}

		got, err := pwd.String()
		if err != nil {
			t.Errorf("String() error = %v", err)
		}
		if got != input {
			t.Errorf("String() = %v, want %v", got, input)
		}
		if !utf8.ValidString(got) {
			t.Error("String() returned invalid UTF-8")
		}
	})
}

func BenchmarkNewClearPassword(b *testing.B) {
	password := []byte("benchmark-password-123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewClearPassword(password)
	}
}

func BenchmarkClearPassword_Bytes(b *testing.B) {
	password := []byte("benchmark-password-123")
	pwd, _ := NewClearPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pwd.Bytes()
	}
}

func BenchmarkClearPassword_String(b *testing.B) {
	password := []byte("benchmark-password-123")
	pwd, _ := NewClearPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pwd.String()
	}
}

func BenchmarkClearPassword_Zero(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pwd, _ := NewClearPassword([]byte("benchmark-password-123"))
		b.StartTimer()
		pwd.Zero()
	}
}

func BenchmarkEqual(b *testing.B) {
	pwd1, _ := NewClearPasswordFromString("password1")
	pwd2, _ := NewClearPasswordFromString("password1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Equal(pwd1, pwd2)
	}
}
