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

package rest

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
		{"valid simple", "my-key", false},
		{"valid with underscore", "my_key", false},
		{"valid with dot", "my.key", false},
		{"valid alphanumeric", "key123", false},
		{"valid mixed", "My-Key_123.test", false},
		{"empty", "", true},
		{"null byte", "key\x00id", true},
		{"absolute path unix", "/etc/passwd", true},
		{"path traversal", "../../../etc/passwd", true},
		{"path traversal mid", "foo/../../../etc/passwd", true},
		{"special chars", "key<>id", true},
		{"space", "key id", true},
		{"backslash", "key\\id", true},
		{"colon", "key:id", false}, // Colons are valid for extended key ID format (backend:type:algo:keyname)
		{"semicolon", "key;id", true},
		{"quote", "key\"id", true},
		{"single quote", "key'id", true},
		{"backtick", "key`id", true},
		{"pipe", "key|id", true},
		{"ampersand", "key&id", true},
		{"dollar", "key$id", true},
		{"hash", "key#id", true},
		{"at", "key@id", true},
		{"exclamation", "key!id", true},
		{"percent", "key%id", true},
		{"caret", "key^id", true},
		{"asterisk", "key*id", true},
		{"parentheses", "key(id)", true},
		{"brackets", "key[id]", true},
		{"braces", "key{id}", true},
		{"plus", "key+id", true},
		{"equals", "key=id", true},
		{"tilde", "key~id", true},
		{"too long", strings.Repeat("a", 256), true},
		{"max length", strings.Repeat("a", 255), false},
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
		name    string
		backend string
		wantErr bool
	}{
		{"valid simple", "memory", false},
		{"valid with hyphen", "aws-kms", false},
		{"valid with numbers", "backend123", false},
		{"empty", "", true},
		{"uppercase", "Memory", true},
		{"underscore", "my_backend", true},
		{"dot", "my.backend", true},
		{"space", "my backend", true},
		{"special chars", "backend<>", true},
		{"path traversal", "../backend", true},
		{"absolute path", "/etc/backend", true},
		{"too long", strings.Repeat("a", 65), true},
		{"max length", strings.Repeat("a", 64), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBackendName(tt.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBackendName(%q) error = %v, wantErr %v", tt.backend, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain text", "hello world", "hello world"},
		{"with newline", "hello\nworld", "helloworld"},
		{"with tab", "hello\tworld", "helloworld"},
		{"with carriage return", "hello\rworld", "helloworld"},
		{"with null byte", "hello\x00world", "helloworld"},
		{"with control char", "hello\x1Fworld", "helloworld"},
		{"with DEL char", "hello\x7Fworld", "helloworld"},
		{"long string", strings.Repeat("a", 1100), strings.Repeat("a", 1000) + "..."},
		{"exactly 1000", strings.Repeat("b", 1000), strings.Repeat("b", 1000)},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeString(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeString() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestValidateAndGetBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"empty backend", "", true},
		{"invalid backend chars", "backend<>", true},
		{"valid backend", "memory", true}, // Always returns error for direct call
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAndGetBackend(tt.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndGetBackend(%q) error = %v, wantErr %v", tt.backend, err, tt.wantErr)
			}
		})
	}
}

func TestValidateURLParam(t *testing.T) {
	tests := []struct {
		name      string
		param     string
		paramName string
		wantErr   bool
	}{
		{"valid keyID", "test-key", "keyID", false},
		{"valid id", "test-key", "id", false},
		{"valid backend", "memory", "backend", false},
		{"valid backendID", "memory", "backendID", false},
		{"valid generic", "some-value", "genericParam", false},
		{"empty keyID", "", "keyID", true},
		{"empty backend", "", "backend", true},
		{"null byte", "test\x00key", "keyID", true},
		{"control char", "test\x1Fkey", "keyID", true},
		{"percent encoding", "test%20key", "keyID", true},
		{"generic too long", strings.Repeat("x", 256), "genericParam", true},
		{"generic max length", strings.Repeat("y", 255), "genericParam", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLParam(tt.param, tt.paramName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURLParam(%q, %q) error = %v, wantErr %v", tt.param, tt.paramName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyID_PathTraversal(t *testing.T) {
	// More comprehensive path traversal tests
	attacks := []string{
		"..",
		"...",
		"../",
		"..\\",
		"../../",
		"..%2F",
		"..%5C",
		".%2e/",
		"%2e%2e/",
		"foo/../bar",
		"foo/./bar/../../../etc/passwd",
		"....//",
		"..../",
		"..%00/",
		"..%c0%af",
		"..%252f",
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			err := ValidateKeyID(attack)
			if err == nil {
				t.Errorf("ValidateKeyID(%q) should reject path traversal attempt", attack)
			}
		})
	}
}

func TestValidateKeyID_InjectionAttacks(t *testing.T) {
	// Test various injection attempts
	attacks := []string{
		"'; DROP TABLE keys;--",
		"<script>alert(1)</script>",
		"$(whoami)",
		"`whoami`",
		"${USER}",
		"{{.}}", // Template injection
		"\\n\\r",
		"key\nid",
		"key\rid",
		"key\r\nid",
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			err := ValidateKeyID(attack)
			if err == nil {
				t.Errorf("ValidateKeyID(%q) should reject injection attempt", attack)
			}
		})
	}
}
