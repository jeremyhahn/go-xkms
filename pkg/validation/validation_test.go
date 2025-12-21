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

package validation

import (
	"strings"
	"testing"
)

func TestValidateKeyID(t *testing.T) {
	tests := []struct {
		name    string
		keyID   string
		wantErr bool
	}{
		// Valid key IDs
		{"valid alphanumeric", "mykey123", false},
		{"valid with dash", "my-signing-key", false},
		{"valid with underscore", "my_signing_key", false},
		{"valid with dot", "app.production.key", false},
		{"valid mixed", "app-prod_v1.2", false},
		{"valid single char", "a", false},
		{"valid numbers only", "12345", false},

		// Invalid key IDs
		{"empty string", "", true},
		{"null byte", "key\x00name", true},
		{"path traversal double dot", "../key", true},
		{"path traversal with slash", "../../etc/passwd", true},
		{"path traversal middle", "foo/../bar", true},
		{"absolute path unix", "/etc/passwd", true},
		{"absolute path windows", "C:\\Windows\\System32", true},
		{"control character", "key\nname", true},
		{"control character tab", "key\tname", true},
		{"special char space", "my key", true},
		{"special char semicolon", "key;name", true},
		{"special char pipe", "key|name", true},
		{"special char ampersand", "key&name", true},
		{"special char dollar", "key$name", true},
		{"special char backtick", "key`name", true},
		{"special char quote", "key'name", true},
		{"special char doublequote", "key\"name", true},
		{"special char asterisk", "key*name", true},
		{"special char question", "key?name", true},
		{"special char bracket", "key[name]", true},
		{"special char paren", "key(name)", true},
		{"special char brace", "key{name}", true},
		{"special char at", "key@name", true},
		{"special char hash", "key#name", true},
		{"special char percent", "key%name", true},
		{"special char caret", "key^name", true},
		{"too long", strings.Repeat("a", 256), true},
		{"del character", "key\x7fname", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyID(tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyID(%q) error = %v, wantErr %v", tt.keyID, err, tt.wantErr)
			}
		})
	}
}

func TestValidateBackendName(t *testing.T) {
	tests := []struct {
		name        string
		backendName string
		wantErr     bool
	}{
		// Valid backend names
		{"valid lowercase", "pkcs8", false},
		{"valid with dash", "my-backend", false},
		{"valid with numbers", "backend123", false},
		{"valid mixed", "pkcs11-hsm", false},
		{"valid single char", "a", false},

		// Invalid backend names
		{"empty string", "", true},
		{"null byte", "backend\x00", true},
		{"uppercase", "PKCS8", true},
		{"mixed case", "Pkcs8", true},
		{"underscore", "my_backend", true},
		{"dot", "my.backend", true},
		{"space", "my backend", true},
		{"path traversal", "../backend", true},
		{"absolute path", "/backend", true},
		{"special char semicolon", "backend;", true},
		{"special char quote", "backend'", true},
		{"control character", "backend\n", true},
		{"too long", strings.Repeat("a", 65), true},
		{"del character", "backend\x7f", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBackendName(tt.backendName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBackendName(%q) error = %v, wantErr %v", tt.backendName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyReference(t *testing.T) {
	tests := []struct {
		name    string
		keyRef  string
		wantErr bool
	}{
		// Valid key references - 4-part format: backend:type:algo:keyname
		{"simple key ID", "my-key", false},
		{"full format", "pkcs8:signing:ecdsa-p256:my-key", false},
		{"full format with dots in keyname", "pkcs8:signing:ecdsa-p256:app.prod.key", false},
		{"full format with numbers", "pkcs8:signing:ecdsa-p256:key456", false},
		{"full format rsa", "pkcs8:encryption:rsa:my-rsa-key", false},
		{"full format ed25519", "pkcs8:signing:ed25519:my-ed-key", false},
		{"minimal format empty components", ":::my-key", false},
		{"backend only", "pkcs8:::my-key", false},
		{"type only", ":signing::my-key", false},
		{"algo only", "::ecdsa-p256:my-key", false},

		// Invalid key references
		{"empty string", "", true},
		{"wrong colon count 1", "backend:key", true},
		{"wrong colon count 2", "backend:type:key", true},
		{"null byte in key", "backend:type:algo:key\x00", true},
		{"null byte in backend", "backend\x00:type:algo:key", true},
		{"invalid backend uppercase", "PKCS8:signing:ecdsa-p256:key", true},
		{"invalid backend underscore", "my_backend:signing:ecdsa-p256:key", true},
		{"invalid key path traversal", "pkcs8:signing:ecdsa-p256:../key", true},
		{"invalid key absolute", "pkcs8:signing:ecdsa-p256:/etc/passwd", true},
		{"invalid key special char", "pkcs8:signing:ecdsa-p256:key;rm", true},
		{"control character", "pkcs8:signing:ecdsa-p256:key\n", true},
		{"too long total", strings.Repeat("a", 513), true},
		{"too long backend", strings.Repeat("a", 65) + ":signing:ecdsa-p256:key", true},
		{"too long key", "pkcs8:signing:ecdsa-p256:" + strings.Repeat("a", 256), true},
		{"invalid type", "pkcs8:invalid:ecdsa-p256:key", true},
		{"invalid algo", "pkcs8:signing:invalid-algo:key", true},
		{"colon only", ":", true},
		{"colon at start", ":key", true},
		{"colon at end", "backend:", true},
		{"empty keyname", "pkcs8:signing:ecdsa-p256:", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyReference(tt.keyRef)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyReference(%q) error = %v, wantErr %v", tt.keyRef, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean string", "hello world", "hello world"},
		{"with newline", "hello\nworld", "helloworld"},
		{"with tab", "hello\tworld", "helloworld"},
		{"with null byte", "hello\x00world", "helloworld"},
		{"with del character", "hello\x7fworld", "helloworld"},
		{"with multiple controls", "hello\n\r\t\x00world", "helloworld"},
		{"very long string", strings.Repeat("a", 1500), strings.Repeat("a", 1000) + "...[truncated]"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForLog(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeForLog(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkValidateKeyID(b *testing.B) {
	keyID := "my-signing-key"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateKeyID(keyID)
	}
}

func BenchmarkValidateBackendName(b *testing.B) {
	backend := "pkcs8"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateBackendName(backend)
	}
}

func BenchmarkValidateKeyReference(b *testing.B) {
	ref := "pkcs8:my-signing-key"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateKeyReference(ref)
	}
}

func BenchmarkSanitizeForLog(b *testing.B) {
	input := "hello world with some text"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SanitizeForLog(input)
	}
}

// Security tests - specifically test attack vectors
func TestSecurityAttackVectors(t *testing.T) {
	attackVectors := []struct {
		name   string
		input  string
		testFn func(string) error
	}{
		// Path traversal attacks
		{"path traversal keyID", "../../../etc/passwd", ValidateKeyID},
		{"path traversal keyID 2", "../../etc/shadow", ValidateKeyID},
		{"path traversal backend", "../backend", ValidateBackendName},

		// Null byte attacks
		{"null byte keyID", "key\x00.txt", ValidateKeyID},
		{"null byte backend", "backend\x00", ValidateBackendName},

		// Command injection attempts
		{"command injection keyID 1", "key;rm -rf /", ValidateKeyID},
		{"command injection keyID 2", "key`whoami`", ValidateKeyID},
		{"command injection keyID 3", "key$(whoami)", ValidateKeyID},
		{"command injection backend", "backend;ls", ValidateBackendName},

		// SQL injection attempts
		{"sql injection backend 1", "backend' OR '1'='1", ValidateBackendName},
		{"sql injection keyID", "key' OR '1'='1", ValidateKeyID},

		// Log injection attempts
		{"log injection newline", "key\nINFO: fake log", ValidateKeyID},
		{"log injection carriage return", "key\rINFO: fake", ValidateKeyID},

		// Unicode attacks
		{"unicode normalization", "key\u202e", ValidateKeyID}, // Right-to-left override
	}

	for _, tt := range attackVectors {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFn(tt.input)
			if err == nil {
				t.Errorf("Attack vector %q was not blocked!", tt.input)
			}
		})
	}
}
