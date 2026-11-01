package tpm2

import (
	"crypto"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Common test utilities (merged from test_common_test.go)
// ---------------------------------------------------------------------------

var (
	currentWorkingDirectoryCommon, _ = os.Getwd()
	TEST_DIR                         = fmt.Sprintf("%s/testdata", currentWorkingDirectoryCommon)
	CLEAN_TMP                        = false
)

func init() {
	// Ensure test directory exists
	_ = os.MkdirAll(TEST_DIR, 0755)
}

// ---------------------------------------------------------------------------
// Tests merged from types_helpers_test.go
// ---------------------------------------------------------------------------

func TestParseHash_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected crypto.Hash
	}{
		{"SHA-1 uppercase", "SHA-1", crypto.SHA1},
		{"SHA-1 lowercase", "sha-1", crypto.SHA1},
		{"SHA-1 mixed", "Sha-1", crypto.SHA1},
		{"SHA-256 uppercase", "SHA-256", crypto.SHA256},
		{"SHA-256 lowercase", "sha-256", crypto.SHA256},
		{"SHA-256 mixed", "Sha-256", crypto.SHA256},
		{"SHA-384 uppercase", "SHA-384", crypto.SHA384},
		{"SHA-384 lowercase", "sha-384", crypto.SHA384},
		{"SHA-512 uppercase", "SHA-512", crypto.SHA512},
		{"SHA-512 lowercase", "sha-512", crypto.SHA512},
		{"Invalid hash", "invalid", crypto.Hash(0)},
		{"Empty string", "", crypto.Hash(0)},
		{"MD5 unsupported", "MD5", crypto.Hash(0)},
		{"SHA3 not supported", "SHA3-256", crypto.Hash(0)},
		{"Partial match SHA", "SHA", crypto.Hash(0)},
		{"Partial match 256", "256", crypto.Hash(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseHash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Extended template parameter tests (merged from templates_test.go)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests merged from data_structures_test.go
// ---------------------------------------------------------------------------
