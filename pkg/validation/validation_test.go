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

package validation

import (
	"errors"
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

func TestValidateKeyIDTypedErrors(t *testing.T) {
	tests := []struct {
		name           string
		keyID          string
		wantConstraint Constraint
	}{
		{"empty returns ConstraintEmpty", "", ConstraintEmpty},
		{"null byte returns ConstraintNullByte", "key\x00", ConstraintNullByte},
		{"too long returns ConstraintTooLong", strings.Repeat("a", 256), ConstraintTooLong},
		{"absolute path returns ConstraintAbsolutePath", "/etc/passwd", ConstraintAbsolutePath},
		{"path traversal returns ConstraintPathTraversal", "../key", ConstraintPathTraversal},
		{"control char returns ConstraintControlChars", "key\nname", ConstraintControlChars},
		{"invalid chars returns ConstraintInvalidChars", "key;name", ConstraintInvalidChars},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyID(tt.keyID)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var keyIDErr *ErrKeyID
			if !errors.As(err, &keyIDErr) {
				t.Fatalf("expected *ErrKeyID, got %T: %v", err, err)
			}
			if keyIDErr.Constraint != tt.wantConstraint {
				t.Errorf("constraint = %v, want %v", keyIDErr.Constraint, tt.wantConstraint)
			}
			if keyIDErr.Field != "key ID" {
				t.Errorf("field = %q, want %q", keyIDErr.Field, "key ID")
			}
			// Verify error message is non-empty and readable
			msg := err.Error()
			if msg == "" {
				t.Error("error message is empty")
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

func TestValidateBackendNameTypedErrors(t *testing.T) {
	tests := []struct {
		name           string
		backendName    string
		wantConstraint Constraint
	}{
		{"empty returns ConstraintEmpty", "", ConstraintEmpty},
		{"null byte returns ConstraintNullByte", "backend\x00", ConstraintNullByte},
		{"too long returns ConstraintTooLong", strings.Repeat("a", 65), ConstraintTooLong},
		{"control char returns ConstraintControlChars", "backend\n", ConstraintControlChars},
		{"invalid chars returns ConstraintInvalidChars", "PKCS8", ConstraintInvalidChars},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBackendName(tt.backendName)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var backendErr *ErrBackendName
			if !errors.As(err, &backendErr) {
				t.Fatalf("expected *ErrBackendName, got %T: %v", err, err)
			}
			if backendErr.Constraint != tt.wantConstraint {
				t.Errorf("constraint = %v, want %v", backendErr.Constraint, tt.wantConstraint)
			}
			if backendErr.Field != "backend name" {
				t.Errorf("field = %q, want %q", backendErr.Field, "backend name")
			}
		})
	}
}

func TestValidateKeyReference(t *testing.T) {
	tests := []struct {
		name    string
		keyID   string
		wantErr bool
	}{
		// Valid key IDs - 4-part format: backend:type:algo:keyname
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

		// Valid ChaCha20 and XChaCha20 algorithms
		{"chacha20-poly1305", "software:encryption:chacha20-poly1305:stream-key", false},
		{"xchacha20-poly1305", "software:encryption:xchacha20-poly1305:xstream-key", false},
		{"chacha20 shorthand", "software:encryption:chacha20:stream-key", false},
		{"xchacha20 shorthand", "software:encryption:xchacha20:stream-key", false},

		// Valid Ed448 and key exchange algorithms
		{"ed448", "pkcs8:signing:ed448:my-ed448-key", false},
		{"x25519", "software:encryption:x25519:my-kex-key", false},
		{"x448", "software:encryption:x448:my-kex-key", false},

		// Valid post-quantum algorithms
		{"ml-dsa-44", "software:signing:ml-dsa-44:pq-sig-key", false},
		{"ml-dsa-65", "software:signing:ml-dsa-65:pq-sig-key", false},
		{"ml-dsa-87", "software:signing:ml-dsa-87:pq-sig-key", false},
		{"mldsa44", "software:signing:mldsa44:pq-sig-key", false},
		{"ml-kem-768", "software:encryption:ml-kem-768:pq-enc-key", false},
		{"mlkem1024", "software:encryption:mlkem1024:pq-enc-key", false},

		// Valid HMAC algorithms
		{"hmac-sha256", "software:hmac:hmac-sha256:hmac-key", false},
		{"hmac-sha384", "software:hmac:hmac-sha384:hmac-key", false},
		{"hmac-sha512", "software:hmac:hmac-sha512:hmac-key", false},

		// Valid FROST algorithms
		{"frost-ed25519", "software:signing:frost-ed25519:frost-key", false},
		{"frost-p256-sha256", "software:signing:frost-p256-sha256:frost-key", false},

		// Invalid key IDs
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
			err := ValidateKeyReference(tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyReference(%q) error = %v, wantErr %v", tt.keyID, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyReferenceTypedErrors(t *testing.T) {
	tests := []struct {
		name           string
		keyID          string
		wantRefErr     bool
		wantKeyIDErr   bool
		wantBackendErr bool
		wantConstraint Constraint
		wantComponent  string
	}{
		{
			name:           "empty returns ErrKeyReference with ConstraintEmpty",
			keyID:          "",
			wantRefErr:     true,
			wantConstraint: ConstraintEmpty,
		},
		{
			name:           "null byte returns ErrKeyReference with ConstraintNullByte",
			keyID:          "key\x00",
			wantRefErr:     true,
			wantConstraint: ConstraintNullByte,
		},
		{
			name:           "too long returns ErrKeyReference with ConstraintTooLong",
			keyID:          strings.Repeat("a", 513),
			wantRefErr:     true,
			wantConstraint: ConstraintTooLong,
		},
		{
			name:           "control char returns ErrKeyReference with ConstraintControlChars",
			keyID:          "key\n",
			wantRefErr:     true,
			wantConstraint: ConstraintControlChars,
		},
		{
			name:           "wrong colon count returns ConstraintInvalidFormat",
			keyID:          "backend:key",
			wantRefErr:     true,
			wantConstraint: ConstraintInvalidFormat,
		},
		{
			name:          "empty keyname returns component error",
			keyID:         "pkcs8:signing:ecdsa-p256:",
			wantRefErr:    true,
			wantComponent: "keyname",
		},
		{
			name:           "invalid backend wraps ErrBackendName",
			keyID:          "PKCS8:signing:ecdsa-p256:key",
			wantRefErr:     true,
			wantBackendErr: true,
			wantComponent:  "backend",
		},
		{
			name:          "invalid key type returns component error",
			keyID:         "pkcs8:invalid:ecdsa-p256:key",
			wantRefErr:    true,
			wantComponent: "key type",
		},
		{
			name:          "invalid algorithm returns component error",
			keyID:         "pkcs8:signing:invalid-algo:key",
			wantRefErr:    true,
			wantComponent: "algorithm",
		},
		{
			name:          "invalid keyname wraps ErrKeyID",
			keyID:         "pkcs8:signing:ecdsa-p256:key;rm",
			wantRefErr:    true,
			wantKeyIDErr:  true,
			wantComponent: "keyname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyReference(tt.keyID)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tt.wantRefErr {
				var refErr *ErrKeyReference
				if !errors.As(err, &refErr) {
					t.Fatalf("expected *ErrKeyReference, got %T: %v", err, err)
				}
				if tt.wantComponent != "" && refErr.Component != tt.wantComponent {
					t.Errorf("component = %q, want %q", refErr.Component, tt.wantComponent)
				}
				if tt.wantComponent == "" && tt.wantConstraint != 0 {
					if refErr.Constraint != tt.wantConstraint {
						t.Errorf("constraint = %v, want %v", refErr.Constraint, tt.wantConstraint)
					}
				}

				// Verify wrapping for backend errors
				if tt.wantBackendErr {
					var backendErr *ErrBackendName
					if !errors.As(err, &backendErr) {
						t.Errorf("expected wrapped *ErrBackendName, got %T", err)
					}
				}

				// Verify wrapping for key ID errors
				if tt.wantKeyIDErr {
					var keyIDErr *ErrKeyID
					if !errors.As(err, &keyIDErr) {
						t.Errorf("expected wrapped *ErrKeyID, got %T", err)
					}
				}
			}

			// Verify error message is non-empty
			msg := err.Error()
			if msg == "" {
				t.Error("error message is empty")
			}
		})
	}
}

// TestValidateKeyReferenceShorthandReturnsErrKeyID verifies that shorthand references
// (no colons) return ErrKeyID rather than ErrKeyReference.
func TestValidateKeyReferenceShorthandReturnsErrKeyID(t *testing.T) {
	err := ValidateKeyReference("key;bad")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var keyIDErr *ErrKeyID
	if !errors.As(err, &keyIDErr) {
		t.Fatalf("shorthand validation should return *ErrKeyID, got %T: %v", err, err)
	}
	if keyIDErr.Constraint != ConstraintInvalidChars {
		t.Errorf("constraint = %v, want ConstraintInvalidChars", keyIDErr.Constraint)
	}
}

func TestIsValidAlgorithm(t *testing.T) {
	tests := []struct {
		name  string
		algo  string
		valid bool
	}{
		// Asymmetric
		{"rsa", "rsa", true},
		{"ecdsa-p256", "ecdsa-p256", true},
		{"ed25519", "ed25519", true},
		{"ed448", "ed448", true},
		// Key exchange
		{"x25519", "x25519", true},
		{"x448", "x448", true},
		// Symmetric - AES
		{"aes256-gcm", "aes256-gcm", true},
		{"aes128", "aes128", true},
		// Symmetric - ChaCha20
		{"chacha20-poly1305", "chacha20-poly1305", true},
		{"chacha20", "chacha20", true},
		{"xchacha20-poly1305", "xchacha20-poly1305", true},
		{"xchacha20", "xchacha20", true},
		// Case insensitivity
		{"uppercase chacha", "CHACHA20-POLY1305", true},
		{"mixed case aes", "AES256-GCM", true},
		// Post-quantum
		{"ml-dsa-44", "ml-dsa-44", true},
		{"mldsa65", "mldsa65", true},
		{"ml-kem-768", "ml-kem-768", true},
		{"mlkem1024", "mlkem1024", true},
		// HMAC
		{"hmac-sha256", "hmac-sha256", true},
		{"hmac-sha512", "hmac-sha512", true},
		// FROST
		{"frost-ed25519", "frost-ed25519", true},
		{"frost-p256-sha256", "frost-p256-sha256", true},
		// Invalid
		{"empty string", "", false},
		{"garbage", "not-an-algo", false},
		{"partial match", "aes256-gc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidAlgorithm(tt.algo)
			if got != tt.valid {
				t.Errorf("isValidAlgorithm(%q) = %v, want %v", tt.algo, got, tt.valid)
			}
		})
	}
}

func TestIsValidKeyType(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		valid   bool
	}{
		{"signing", "signing", true},
		{"encryption", "encryption", true},
		{"hmac", "hmac", true},
		{"secret", "secret", true},
		{"tpm", "tpm", true},
		{"ca", "ca", true},
		{"uppercase signing", "SIGNING", true},
		{"invalid type", "invalid", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidKeyType(tt.keyType)
			if got != tt.valid {
				t.Errorf("isValidKeyType(%q) = %v, want %v", tt.keyType, got, tt.valid)
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

func BenchmarkValidateKeyReferenceFullFormat(b *testing.B) {
	ref := "software:encryption:chacha20-poly1305:stream-key"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateKeyReference(ref)
	}
}

func BenchmarkIsValidAlgorithm(b *testing.B) {
	algo := "chacha20-poly1305"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isValidAlgorithm(algo)
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

// TestSecurityAttackVectorsReturnTypedErrors ensures attack vectors produce typed errors
// that can be programmatically inspected.
func TestSecurityAttackVectorsReturnTypedErrors(t *testing.T) {
	t.Run("path traversal keyID returns ErrKeyID", func(t *testing.T) {
		err := ValidateKeyID("../../../etc/passwd")
		if err == nil {
			t.Fatal("expected error")
		}
		var keyIDErr *ErrKeyID
		if !errors.As(err, &keyIDErr) {
			t.Fatalf("expected *ErrKeyID, got %T", err)
		}
		if keyIDErr.Constraint != ConstraintPathTraversal {
			t.Errorf("constraint = %v, want ConstraintPathTraversal", keyIDErr.Constraint)
		}
	})

	t.Run("null byte backend returns ErrBackendName", func(t *testing.T) {
		err := ValidateBackendName("backend\x00")
		if err == nil {
			t.Fatal("expected error")
		}
		var backendErr *ErrBackendName
		if !errors.As(err, &backendErr) {
			t.Fatalf("expected *ErrBackendName, got %T", err)
		}
		if backendErr.Constraint != ConstraintNullByte {
			t.Errorf("constraint = %v, want ConstraintNullByte", backendErr.Constraint)
		}
	})

	t.Run("command injection keyID returns ErrKeyID", func(t *testing.T) {
		err := ValidateKeyID("key;rm -rf /")
		if err == nil {
			t.Fatal("expected error")
		}
		var keyIDErr *ErrKeyID
		if !errors.As(err, &keyIDErr) {
			t.Fatalf("expected *ErrKeyID, got %T", err)
		}
		if keyIDErr.Constraint != ConstraintInvalidChars {
			t.Errorf("constraint = %v, want ConstraintInvalidChars", keyIDErr.Constraint)
		}
	})

	t.Run("log injection returns ErrKeyID with ConstraintControlChars", func(t *testing.T) {
		err := ValidateKeyID("key\nINFO: fake log")
		if err == nil {
			t.Fatal("expected error")
		}
		var keyIDErr *ErrKeyID
		if !errors.As(err, &keyIDErr) {
			t.Fatalf("expected *ErrKeyID, got %T", err)
		}
		if keyIDErr.Constraint != ConstraintControlChars {
			t.Errorf("constraint = %v, want ConstraintControlChars", keyIDErr.Constraint)
		}
	})
}

// TestErrorTypeEmbedding verifies the error type hierarchy works correctly
// with errors.As across the embedding chain.
func TestErrorTypeEmbedding(t *testing.T) {
	t.Run("ErrKeyID is also ErrValidation", func(t *testing.T) {
		err := ValidateKeyID("")
		var valErr *ErrValidation
		if !errors.As(err, &valErr) {
			t.Fatalf("expected *ErrValidation via embedding, got %T", err)
		}
		if valErr.Constraint != ConstraintEmpty {
			t.Errorf("constraint = %v, want ConstraintEmpty", valErr.Constraint)
		}
	})

	t.Run("ErrBackendName is also ErrValidation", func(t *testing.T) {
		err := ValidateBackendName("")
		var valErr *ErrValidation
		if !errors.As(err, &valErr) {
			t.Fatalf("expected *ErrValidation via embedding, got %T", err)
		}
		if valErr.Constraint != ConstraintEmpty {
			t.Errorf("constraint = %v, want ConstraintEmpty", valErr.Constraint)
		}
	})

	t.Run("ErrKeyReference is also ErrValidation", func(t *testing.T) {
		err := ValidateKeyReference("")
		var valErr *ErrValidation
		if !errors.As(err, &valErr) {
			t.Fatalf("expected *ErrValidation via embedding, got %T", err)
		}
	})
}

// TestConstraintString verifies the Constraint.String() output.
func TestConstraintString(t *testing.T) {
	tests := []struct {
		constraint Constraint
		want       string
	}{
		{ConstraintEmpty, "cannot be empty"},
		{ConstraintNullByte, "contains null byte"},
		{ConstraintTooLong, "exceeds maximum length"},
		{ConstraintAbsolutePath, "cannot be an absolute path"},
		{ConstraintPathTraversal, "contains path traversal attempt"},
		{ConstraintControlChars, "contains control characters"},
		{ConstraintInvalidChars, "contains invalid characters"},
		{ConstraintInvalidFormat, "invalid format"},
		{ConstraintInvalidKeyType, "invalid key type"},
		{ConstraintInvalidAlgorithm, "invalid algorithm"},
		{Constraint(999), "unknown constraint"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.constraint.String()
			if got != tt.want {
				t.Errorf("Constraint(%d).String() = %q, want %q", tt.constraint, got, tt.want)
			}
		})
	}
}

// TestErrorMessages verifies that error messages are human-readable and informative.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name:     "empty key ID",
			err:      ValidateKeyID(""),
			contains: []string{"key ID", "cannot be empty"},
		},
		{
			name:     "too long key ID includes max",
			err:      ValidateKeyID(strings.Repeat("a", 256)),
			contains: []string{"key ID", "max 255"},
		},
		{
			name:     "invalid chars key ID includes allowed",
			err:      ValidateKeyID("key;name"),
			contains: []string{"key ID", "allowed"},
		},
		{
			name:     "empty backend name",
			err:      ValidateBackendName(""),
			contains: []string{"backend name", "cannot be empty"},
		},
		{
			name:     "invalid backend in reference includes component",
			err:      ValidateKeyReference("PKCS8:signing:ecdsa-p256:key"),
			contains: []string{"backend", "key reference"},
		},
		{
			name:     "invalid algo in reference includes algorithm",
			err:      ValidateKeyReference("pkcs8:signing:invalid-algo:key"),
			contains: []string{"algorithm", "key reference"},
		},
		{
			name:     "wrong colon count includes expected format",
			err:      ValidateKeyReference("backend:key"),
			contains: []string{"backend:type:algo:keyname"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected error, got nil")
			}
			msg := tt.err.Error()
			for _, substr := range tt.contains {
				if !strings.Contains(msg, substr) {
					t.Errorf("error message %q does not contain %q", msg, substr)
				}
			}
		})
	}
}

// TestErrKeyReferenceUnwrap verifies that Unwrap returns the wrapped cause.
func TestErrKeyReferenceUnwrap(t *testing.T) {
	t.Run("unwrap returns wrapped ErrBackendName", func(t *testing.T) {
		err := ValidateKeyReference("PKCS8:signing:ecdsa-p256:key")
		if err == nil {
			t.Fatal("expected error")
		}

		var refErr *ErrKeyReference
		if !errors.As(err, &refErr) {
			t.Fatalf("expected *ErrKeyReference, got %T", err)
		}

		// Unwrap should return the cause
		cause := refErr.Unwrap()
		if cause == nil {
			t.Fatal("expected non-nil cause from Unwrap()")
		}

		var backendErr *ErrBackendName
		if !errors.As(cause, &backendErr) {
			t.Fatalf("unwrapped cause should be *ErrBackendName, got %T", cause)
		}
	})

	t.Run("unwrap returns nil for non-component errors", func(t *testing.T) {
		err := ValidateKeyReference("")
		if err == nil {
			t.Fatal("expected error")
		}

		var refErr *ErrKeyReference
		if !errors.As(err, &refErr) {
			t.Fatalf("expected *ErrKeyReference, got %T", err)
		}

		if refErr.Unwrap() != nil {
			t.Error("expected nil cause for non-component error")
		}
	})

	t.Run("unwrap returns wrapped ErrKeyID for invalid keyname", func(t *testing.T) {
		err := ValidateKeyReference("pkcs8:signing:ecdsa-p256:key;bad")
		if err == nil {
			t.Fatal("expected error")
		}

		var refErr *ErrKeyReference
		if !errors.As(err, &refErr) {
			t.Fatalf("expected *ErrKeyReference, got %T", err)
		}

		cause := refErr.Unwrap()
		if cause == nil {
			t.Fatal("expected non-nil cause from Unwrap()")
		}

		var keyIDErr *ErrKeyID
		if !errors.As(cause, &keyIDErr) {
			t.Fatalf("unwrapped cause should be *ErrKeyID, got %T", cause)
		}
	})
}
