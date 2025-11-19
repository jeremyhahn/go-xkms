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

package keychain

import (
	"bytes"
	"testing"
)

func TestNewClearPassword(t *testing.T) {
	password := []byte("test-password-123")
	p := NewClearPassword(password)

	if p == nil {
		t.Fatal("NewClearPassword returned nil")
	}

	// Verify it returns the correct password
	str, err := p.String()
	if err != nil {
		t.Errorf("String() error = %v", err)
	}
	if str != string(password) {
		t.Errorf("String() = %v, want %v", str, string(password))
	}

	// Verify defensive copy (modifying original doesn't affect stored password)
	originalPassword := []byte("test-password-123")
	p2 := NewClearPassword(originalPassword)
	originalPassword[0] = 'X' // Modify original

	str2, _ := p2.String()
	if str2[0] == 'X' {
		t.Error("NewClearPassword did not make defensive copy")
	}
}

func TestNewClearPasswordFromString(t *testing.T) {
	passwordStr := "my-secure-password"
	p := NewClearPasswordFromString(passwordStr)

	if p == nil {
		t.Fatal("NewClearPasswordFromString returned nil")
	}

	// Verify it returns the correct password
	str, err := p.String()
	if err != nil {
		t.Errorf("String() error = %v", err)
	}
	if str != passwordStr {
		t.Errorf("String() = %v, want %v", str, passwordStr)
	}

	// Verify bytes match
	b, err := p.Bytes()
	if err != nil {
		t.Errorf("Bytes() error = %v", err)
	}
	if string(b) != passwordStr {
		t.Errorf("Bytes() = %v, want %v", string(b), passwordStr)
	}
}

func TestClearPassword_String(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"Simple password", "password123"},
		{"Empty password", ""},
		{"Special characters", "p@ssw0rd!#$%"},
		{"Unicode", "пароль密码"},
		{"Long password", "this-is-a-very-long-password-with-many-characters-to-test-edge-cases"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewClearPasswordFromString(tt.password)
			got, err := p.String()
			if err != nil {
				t.Errorf("String() error = %v", err)
				return
			}
			if got != tt.password {
				t.Errorf("String() = %v, want %v", got, tt.password)
			}
		})
	}
}

func TestClearPassword_Bytes(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
	}{
		{"Simple bytes", []byte("password123")},
		{"Empty bytes", []byte{}},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}},
		{"Null bytes", []byte{0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewClearPassword(tt.password)
			got, err := p.Bytes()
			if err != nil {
				t.Errorf("Bytes() error = %v", err)
				return
			}
			if !bytes.Equal(got, tt.password) {
				t.Errorf("Bytes() = %v, want %v", got, tt.password)
			}

			// Verify it returns a copy (modifying returned bytes doesn't affect stored password)
			if len(got) > 0 {
				got[0] = 0xFF
				got2, _ := p.Bytes()
				if bytes.Equal(got, got2) {
					t.Error("Bytes() did not return a defensive copy")
				}
			}
		})
	}
}

func TestClearPassword_Zeroize(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
	}{
		{"Short password", []byte("test")},
		{"Long password", []byte("this-is-a-very-long-password-for-testing-zeroize")},
		{"Binary password", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"Empty password", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewClearPassword(tt.password)
			cp := p.(*ClearPassword)

			// Verify password is set
			if len(tt.password) > 0 {
				before, _ := p.Bytes()
				if !bytes.Equal(before, tt.password) {
					t.Error("Password not correctly initialized")
				}
			}

			// Zeroize the password
			cp.Zeroize()

			// Verify all bytes are zero
			for i, b := range cp.password {
				if b != 0 {
					t.Errorf("Zeroize() failed: byte at index %d is %v, want 0", i, b)
				}
			}

			// Verify String() returns empty string
			str, err := p.String()
			if err != nil {
				t.Errorf("String() error after Zeroize = %v", err)
			}
			expectedZeroes := make([]byte, len(tt.password))
			if str != string(expectedZeroes) {
				t.Errorf("String() after Zeroize = %v, want all zeroes", str)
			}
		})
	}
}

func TestClearPassword_Interface(t *testing.T) {
	// Verify ClearPassword implements Password interface
	var _ Password = (*ClearPassword)(nil)
	_ = NewClearPassword([]byte("test"))
	_ = NewClearPasswordFromString("test")
}

func TestPassword_Lifecycle(t *testing.T) {
	// Test complete lifecycle of a password
	originalPassword := "my-secret-password"

	// Create
	p := NewClearPasswordFromString(originalPassword)

	// Use as string
	str, err := p.String()
	if err != nil {
		t.Fatalf("String() error = %v", err)
	}
	if str != originalPassword {
		t.Errorf("String() = %v, want %v", str, originalPassword)
	}

	// Use as bytes
	b, err := p.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	if string(b) != originalPassword {
		t.Errorf("Bytes() = %v, want %v", string(b), originalPassword)
	}

	// Zeroize
	cp := p.(*ClearPassword)
	cp.Zeroize()

	// Verify zeroized
	afterZeroize, _ := p.Bytes()
	for i, b := range afterZeroize {
		if b != 0 {
			t.Errorf("After Zeroize: byte at index %d is %v, want 0", i, b)
		}
	}
}

func TestPassword_EdgeCases(t *testing.T) {
	t.Run("Very long password", func(t *testing.T) {
		longPassword := make([]byte, 10000)
		for i := range longPassword {
			longPassword[i] = byte(i % 256)
		}

		p := NewClearPassword(longPassword)
		got, err := p.Bytes()
		if err != nil {
			t.Fatalf("Bytes() error = %v", err)
		}
		if !bytes.Equal(got, longPassword) {
			t.Error("Long password not correctly stored")
		}

		// Zeroize and verify
		cp := p.(*ClearPassword)
		cp.Zeroize()
		for i, b := range cp.password {
			if b != 0 {
				t.Errorf("Zeroize failed at index %d", i)
				break
			}
		}
	})

	t.Run("Nil bytes should not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("NewClearPassword(nil) panicked: %v", r)
			}
		}()

		p := NewClearPassword(nil)
		if p == nil {
			t.Error("NewClearPassword(nil) returned nil")
		}

		b, err := p.Bytes()
		if err != nil {
			t.Errorf("Bytes() error = %v", err)
		}
		if len(b) != 0 {
			t.Errorf("Expected empty bytes, got %v", b)
		}
	})
}
