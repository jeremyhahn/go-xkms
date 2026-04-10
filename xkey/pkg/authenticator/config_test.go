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
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	require.NotNil(t, config)
	require.Equal(t, DefaultAAGUID, config.AAGUID)
	require.Equal(t, []int{COSEAlgES256}, config.SupportedAlgorithms)
	require.Equal(t, DefaultMaxCredentials, config.MaxCredentials)
	require.Equal(t, DefaultMaxResidentCredentials, config.MaxResidentCredentials)
	require.Equal(t, DefaultPINMinLength, config.PINMinLength)
	require.Equal(t, DefaultPINMaxRetries, config.PINMaxRetries)
	require.True(t, config.EnablePIN)
	require.True(t, config.EnableResidentKey)
	require.True(t, config.EnableCredentialManagement)
	require.True(t, config.EnableHMACSecret)
	require.Nil(t, config.Storage)
}

func TestConfig_SetDefaults(t *testing.T) {
	t.Run("sets all defaults for empty config", func(t *testing.T) {
		config := &Config{}
		config.SetDefaults()

		require.Equal(t, DefaultAAGUID, config.AAGUID)
		require.Equal(t, []int{COSEAlgES256}, config.SupportedAlgorithms)
		require.Equal(t, DefaultMaxCredentials, config.MaxCredentials)
		require.Equal(t, DefaultMaxResidentCredentials, config.MaxResidentCredentials)
		require.Equal(t, DefaultPINMinLength, config.PINMinLength)
		require.Equal(t, DefaultPINMaxRetries, config.PINMaxRetries)
	})

	t.Run("does not override existing values", func(t *testing.T) {
		customAAGUID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		config := &Config{
			AAGUID:                 customAAGUID,
			SupportedAlgorithms:    []int{COSEAlgES384},
			MaxCredentials:         200,
			MaxResidentCredentials: 50,
			PINMinLength:           6,
			PINMaxRetries:          10,
		}
		config.SetDefaults()

		require.Equal(t, customAAGUID, config.AAGUID)
		require.Equal(t, []int{COSEAlgES384}, config.SupportedAlgorithms)
		require.Equal(t, 200, config.MaxCredentials)
		require.Equal(t, 50, config.MaxResidentCredentials)
		require.Equal(t, 6, config.PINMinLength)
		require.Equal(t, 10, config.PINMaxRetries)
	})

	t.Run("sets PINMinLength to minimum 4 if less", func(t *testing.T) {
		config := &Config{
			PINMinLength: 2,
		}
		config.SetDefaults()
		require.Equal(t, DefaultPINMinLength, config.PINMinLength)
	})

	t.Run("forces EnablePIN when EnableCredentialManagement is true", func(t *testing.T) {
		config := &Config{
			EnablePIN:                  false,
			EnableCredentialManagement: true,
		}
		config.SetDefaults()
		require.True(t, config.EnablePIN,
			"CTAP2.1 credential management requires user verification; PIN must be forced on")
	})

	t.Run("does not force EnablePIN when EnableCredentialManagement is false", func(t *testing.T) {
		config := &Config{
			EnablePIN:                  false,
			EnableCredentialManagement: false,
		}
		config.SetDefaults()
		require.False(t, config.EnablePIN,
			"PIN should remain disabled when credential management is not enabled")
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("nil config returns ErrNilConfig", func(t *testing.T) {
		var config *Config
		err := config.Validate()
		require.ErrorIs(t, err, ErrNilConfig)
	})

	t.Run("empty algorithms returns ErrNoAlgorithms", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrNoAlgorithms)
	})

	t.Run("unsupported algorithm returns ErrUnsupportedAlgorithm", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{9999},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("zero max credentials returns ErrInvalidMaxCredentials", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         0,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidMaxCredentials)
	})

	t.Run("negative max credentials returns ErrInvalidMaxCredentials", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         -1,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidMaxCredentials)
	})

	t.Run("zero max resident credentials returns ErrInvalidMaxResidentCreds", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 0,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidMaxResidentCreds)
	})

	t.Run("resident credentials exceeding max returns ErrInvalidMaxResidentCreds", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 200,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidMaxResidentCreds)
	})

	t.Run("PIN min length less than 4 returns ErrInvalidPINMinLength", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           3,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidPINMinLength)
	})

	t.Run("zero PIN max retries returns ErrInvalidPINMaxRetries", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          0,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrInvalidPINMaxRetries)
	})

	t.Run("nil storage returns ErrNilStorage", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                nil,
		}
		err := config.Validate()
		require.ErrorIs(t, err, ErrNilStorage)
	})

	t.Run("valid config returns nil", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with multiple algorithms", func(t *testing.T) {
		config := &Config{
			SupportedAlgorithms:    []int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA},
			MaxCredentials:         100,
			MaxResidentCredentials: 25,
			PINMinLength:           4,
			PINMaxRetries:          8,
			Storage:                NewMemoryStorage(),
		}
		err := config.Validate()
		require.NoError(t, err)
	})
}

func TestConfig_SupportsAlgorithm(t *testing.T) {
	config := &Config{
		SupportedAlgorithms: []int{COSEAlgES256, COSEAlgEdDSA},
	}

	require.True(t, config.SupportsAlgorithm(COSEAlgES256))
	require.True(t, config.SupportsAlgorithm(COSEAlgEdDSA))
	require.False(t, config.SupportsAlgorithm(COSEAlgES384))
	require.False(t, config.SupportsAlgorithm(COSEAlgES512))
	require.False(t, config.SupportsAlgorithm(9999))
}

func TestIsSupportedAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm int
		supported bool
	}{
		{COSEAlgES256, true},
		{COSEAlgES384, true},
		{COSEAlgES512, true},
		{COSEAlgEdDSA, true},
		{COSEAlgRS256, false},
		{0, false},
		{9999, false},
		{-9999, false},
	}

	for _, tt := range tests {
		result := isSupportedAlgorithm(tt.algorithm)
		require.Equal(t, tt.supported, result, "algorithm %d", tt.algorithm)
	}
}

func TestStoredCredential_BackendID_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("with backend ID set", func(t *testing.T) {
		t.Parallel()

		cred := &StoredCredential{
			CredentialID: []byte("test-cred-id"),
			RPID:         "example.com",
			UserID:       []byte("user-1"),
			Algorithm:    COSEAlgES256,
			BackendID:    "tpm2",
		}

		data, err := json.Marshal(cred)
		require.NoError(t, err)

		// Verify JSON contains backend_id
		require.Contains(t, string(data), `"backend_id":"tpm2"`)

		var decoded StoredCredential
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		require.Equal(t, types.BackendType("tpm2"), decoded.BackendID)
	})

	t.Run("with empty backend ID omitted", func(t *testing.T) {
		t.Parallel()

		cred := &StoredCredential{
			CredentialID: []byte("test-cred-id"),
			RPID:         "example.com",
			UserID:       []byte("user-1"),
			Algorithm:    COSEAlgES256,
			BackendID:    "",
		}

		data, err := json.Marshal(cred)
		require.NoError(t, err)

		// Verify JSON omits backend_id when empty (omitempty tag)
		require.NotContains(t, string(data), `"backend_id"`)

		var decoded StoredCredential
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		require.Equal(t, types.BackendType(""), decoded.BackendID)
	})

	t.Run("backward compatible with old credentials", func(t *testing.T) {
		t.Parallel()

		// Simulate a credential stored before BackendID existed
		oldJSON := `{"CredentialID":"dGVzdA==","RPID":"example.com","Algorithm":-7}`

		var cred StoredCredential
		err := json.Unmarshal([]byte(oldJSON), &cred)
		require.NoError(t, err)
		require.Equal(t, types.BackendType(""), cred.BackendID, "old credentials should have empty BackendID")
	})
}
