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

package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validTestConfig() *Config {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = &AccountConfig{
		DirectoryURL: "https://ca.example.com/directory",
		Email:        "admin@example.com",
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
	}
	return cfg
}

func validTestConfigWithCert() *Config {
	cfg := validTestConfig()
	cfg.Certificates["web-prod"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
	}
	return cfg
}

// TestDefaultConfig_MultiAccountFields verifies that DefaultConfig returns
// non-nil multi-account fields with expected default values for the new
// configuration model (storage, XKMS, logging, challenge, maps).
func TestDefaultConfig_MultiAccountFields(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	// Storage
	assert.Equal(t, "filesystem", cfg.Storage.Backend)
	require.NotNil(t, cfg.Storage.Options)
	assert.Contains(t, cfg.Storage.Options, "path")

	// XKMS
	assert.Equal(t, "software", cfg.XKMS.Backend)
	require.NotNil(t, cfg.XKMS.Options)
	assert.Contains(t, cfg.XKMS.Options, "path")

	// Logging
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)

	// Challenge
	assert.Equal(t, "80", cfg.Challenge.HTTP01.Port)
	assert.Equal(t, 300, cfg.Challenge.DNS01.TTL)

	// Accounts and Certificates maps
	require.NotNil(t, cfg.Accounts)
	assert.Empty(t, cfg.Accounts)
	require.NotNil(t, cfg.Certificates)
	assert.Empty(t, cfg.Certificates)
}

// TestDefaultConfig_NotNilFields verifies that all returned config sections
// have non-zero values where expected.
func TestDefaultConfig_NotNilFields(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	assert.NotEmpty(t, cfg.Storage.Backend)
	assert.NotEmpty(t, cfg.Storage.Options)
	assert.NotEmpty(t, cfg.XKMS.Backend)
	assert.NotEmpty(t, cfg.XKMS.Options)
	assert.NotEmpty(t, cfg.Logging.Level)
	assert.NotEmpty(t, cfg.Logging.Format)
	assert.NotEmpty(t, cfg.Logging.Output)
	assert.NotEmpty(t, cfg.Challenge.HTTP01.Port)
	assert.NotZero(t, cfg.Challenge.DNS01.TTL)
	assert.NotNil(t, cfg.Accounts)
	assert.NotNil(t, cfg.Certificates)
	assert.NotZero(t, cfg.Client.Timeout)
	assert.NotZero(t, cfg.Client.RetryAttempts)
	assert.NotZero(t, cfg.Renewal.CheckInterval)
}

// TestConfig_Validate_Success verifies that a valid config with one account
// and one certificate spec passes validation without error.
func TestConfig_Validate_Success(t *testing.T) {
	cfg := validTestConfigWithCert()
	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestConfig_Validate_NoAccounts verifies that an empty accounts map
// fails validation with an ErrValidation referencing accounts.
func TestConfig_Validate_NoAccounts(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Equal(t, "accounts", validationErr.Field)
	assert.Contains(t, validationErr.Reason, "at least one")
}

// TestConfig_Validate_MissingDirectoryURL verifies that an account without
// a DirectoryURL fails validation.
func TestConfig_Validate_MissingDirectoryURL(t *testing.T) {
	cfg := validTestConfig()
	cfg.Accounts["test-ca"].DirectoryURL = ""

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "directory")
	assert.Contains(t, validationErr.Reason, "directory URL")
}

// TestConfig_Validate_MissingEmail verifies that an account without
// an Email fails validation.
func TestConfig_Validate_MissingEmail(t *testing.T) {
	cfg := validTestConfig()
	cfg.Accounts["test-ca"].Email = ""

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "email")
	assert.Contains(t, validationErr.Reason, "email")
}

// TestConfig_Validate_MissingKey verifies that an account with a nil Key
// fails validation.
func TestConfig_Validate_MissingKey(t *testing.T) {
	cfg := validTestConfig()
	cfg.Accounts["test-ca"].Key = nil

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "key")
	assert.Contains(t, validationErr.Reason, "key configuration")
}

// TestConfig_Validate_MissingKeyAlgorithm verifies that an account key
// without an Algorithm fails validation.
func TestConfig_Validate_MissingKeyAlgorithm(t *testing.T) {
	cfg := validTestConfig()
	cfg.Accounts["test-ca"].Key.Algorithm = ""

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "algorithm")
	assert.Contains(t, validationErr.Reason, "algorithm")
}

// TestConfig_Validate_MissingKeyStore verifies that an account key
// without a Store fails validation.
func TestConfig_Validate_MissingKeyStore(t *testing.T) {
	cfg := validTestConfig()
	cfg.Accounts["test-ca"].Key.Store = ""

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "store")
	assert.Contains(t, validationErr.Reason, "key store")
}

// TestConfig_Validate_CertReferencesUnknownAccount verifies that a certificate
// spec referencing a non-existent account fails validation.
func TestConfig_Validate_CertReferencesUnknownAccount(t *testing.T) {
	cfg := validTestConfig()
	cfg.Certificates["web-prod"] = &CertificateSpec{
		Account: "nonexistent-account",
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
	}

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "account")
	assert.Contains(t, validationErr.Reason, "unknown account")
}

// TestConfig_Validate_CertMissingSubjectCN verifies that a certificate spec
// without a Subject.CN fails validation.
func TestConfig_Validate_CertMissingSubjectCN(t *testing.T) {
	cfg := validTestConfig()
	cfg.Certificates["web-prod"] = &CertificateSpec{
		Account: "test-ca",
		Subject: SubjectConfig{CN: ""},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
	}

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "subject.cn")
	assert.Contains(t, validationErr.Reason, "common name")
}

// TestConfig_Validate_CertMissingKey verifies that a certificate spec
// without a Key fails validation.
func TestConfig_Validate_CertMissingKey(t *testing.T) {
	cfg := validTestConfig()
	cfg.Certificates["web-prod"] = &CertificateSpec{
		Account:   "test-ca",
		Subject:   SubjectConfig{CN: "example.com"},
		Key:       nil,
		Challenge: "http-01",
	}

	err := cfg.Validate()
	require.Error(t, err)

	var validationErr *ErrValidation
	require.True(t, errors.As(err, &validationErr))
	assert.Contains(t, validationErr.Field, "key")
	assert.Contains(t, validationErr.Reason, "key configuration")
}

// TestConfig_Validate_NoCertificates verifies that a config with accounts
// but no certificates is valid since certificates are optional.
func TestConfig_Validate_NoCertificates(t *testing.T) {
	cfg := validTestConfig()
	assert.Empty(t, cfg.Certificates)

	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestInitLogger_StderrOutput verifies that InitLogger with stderr output
// returns a non-nil logger.
func TestInitLogger_StderrOutput(t *testing.T) {
	logger := InitLogger(LoggingConfig{
		Level:  "warn",
		Format: "json",
		Output: "stderr",
	})
	require.NotNil(t, logger)
}

// TestInitLogger_InvalidLevel verifies that InitLogger with an invalid
// level defaults to info and returns a non-nil logger.
func TestInitLogger_InvalidLevel(t *testing.T) {
	logger := InitLogger(LoggingConfig{
		Level:  "bogus-level",
		Format: "json",
		Output: "stdout",
	})
	require.NotNil(t, logger)
}

// TestParsePCRIndices_Comprehensive uses table-driven tests to cover
// valid inputs, boundary conditions, and edge cases for PCR index parsing.
func TestParsePCRIndices_Comprehensive(t *testing.T) {
	t.Run("standard indices", func(t *testing.T) {
		indices, err := ParsePCRIndices("0,1,2,3,7")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 1, 2, 3, 7}, indices)
	})

	t.Run("with spaces", func(t *testing.T) {
		indices, err := ParsePCRIndices(" 0 , 1 , 2 ")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 1, 2}, indices)
	})

	t.Run("boundary index 23", func(t *testing.T) {
		indices, err := ParsePCRIndices("0,23")
		require.NoError(t, err)
		assert.Equal(t, []int{0, 23}, indices)
	})

	t.Run("empty string", func(t *testing.T) {
		indices, err := ParsePCRIndices("")
		require.NoError(t, err)
		assert.Empty(t, indices)
	})
}

// TestParsePCRIndices_OutOfRange verifies that an index above 23
// returns ErrInvalidPCRIndex.
func TestParsePCRIndices_OutOfRange(t *testing.T) {
	_, err := ParsePCRIndices("25")
	require.Error(t, err)

	var pcrErr ErrInvalidPCRIndex
	require.True(t, errors.As(err, &pcrErr))
	assert.Equal(t, 25, pcrErr.Index)
}

// TestParsePCRIndices_NegativeIndex verifies that a negative index
// returns ErrInvalidPCRIndex.
func TestParsePCRIndices_NegativeIndex(t *testing.T) {
	_, err := ParsePCRIndices("-1")
	require.Error(t, err)

	var pcrErr ErrInvalidPCRIndex
	require.True(t, errors.As(err, &pcrErr))
	assert.Equal(t, -1, pcrErr.Index)
}

// TestParsePCRIndices_InvalidFormat verifies that a non-numeric string
// returns ErrInvalidPCRFormat.
func TestParsePCRIndices_InvalidFormat(t *testing.T) {
	_, err := ParsePCRIndices("abc")
	require.Error(t, err)

	var fmtErr ErrInvalidPCRFormat
	require.True(t, errors.As(err, &fmtErr))
	assert.Equal(t, "abc", fmtErr.Value)
}
